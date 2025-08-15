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

void invlpg(void *x) {
   asm volatile("invlpg (%0)" ::"r" (x) : "memory");
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
    uint64_t *pdpt = (uint64_t *)get_zeroed_page(GFP_KERNEL);
    pml4[256] = virt_to_phys(pdpt)|3;
    uint64_t *pd = (uint64_t *)get_zeroed_page(GFP_KERNEL);
    pdpt[0] = virt_to_phys(pd)|3;
    uint64_t *pt = (uint64_t *)get_zeroed_page(GFP_KERNEL);
    pd[0] = virt_to_phys(pt)|3;
    pt[0] = 3|0xffffffffff000ULL;
  volatile uint64_t *addr = (uint64_t *)0xffff800000000000ULL;


asm volatile(
        "xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000069, %%r12; mov $1, %%r13; mov $10, %%r11;tdcall;"
        :::"r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdx", "rsi", "rdi","rbx", "memory");
  invlpg(addr);
  serialize();
  for (int x = 0;; ++x) {
    addr[0] = 0;
    asm volatile(
        "xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000069, %%r12; mov $2, %%r13; mov $10, %%r11;tdcall;"
        ".rept 48; addq $1, (%%rsi); .endr;"
        ::"S"(addr):"r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdi", "rdi","rbx", "memory");
  }

  asm volatile("sti":::"memory");


  return 0;

}



void cleanup_module(void)
{
  pr_info("unload.\n");
}



MODULE_LICENSE("GPL");

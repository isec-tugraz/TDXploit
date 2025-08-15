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
  serialize();
  for (int x = 0;; ++x) {
    asm volatile(
        "1: xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000042, %%r12; mov $2, %%r13; mov $10, %%r11;tdcall;"
        ".rept 82; nop; .endr; jmp 1b"
        :::"r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdi", "rdi","rbx", "memory");
  }

  asm volatile("sti":::"memory");

  return 0;

}



void cleanup_module(void)
{
  pr_info("unload.\n");
}



MODULE_LICENSE("GPL");

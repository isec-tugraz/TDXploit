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
#include "int.h"


#define ATTACKER KERN_INFO "attacker: "
#define IA32_TSC_DEADLINE 0x6e0


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
const struct file_operations data_file_fops = {
        .owner = THIS_MODULE,
        .read = data_read,
};


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
size_t accessed(void *addr) {
  size_t sum = 0; 
  size_t i = 0;
  mfence();
  size_t b = rdtsc_nofences();
  maccess(addr);
  //clflush_(addr);
  mfence();
  size_t e = rdtsc_nofences();
  //printk("TDX2: %lld\n", e-b);
  mfence();
  return e-b;
}
int init_module(void) 
{
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
  uint32_t *xx = vmalloc(1024ULL*4);
  uint32_t *yy = vmalloc(1024ULL*4);
  uint32_t *zz = vmalloc(1024ULL*4);
  asm volatile("cli":::"memory");
  uint64_t *page = (uint64_t *)get_zeroed_page(GFP_KERNEL);
  *page = 69;
  
  serialize();

  asm volatile(
	"xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000069, %%r12; mov %0, %%r13; mov $10, %%r11;tdcall;"
	::"S"(virt_to_phys(page)/4096):"r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdx", "rdi","rbx", "memory");
  
  serialize();
  
  maccess(page);
  for (int x = 0;x < 1024*1024; ++x) {
    serialize();
    uint64_t o = accessed(page);
    serialize();
    o = o > 1024 ? (1024-1) : o;
    ++yy[o];
  }
  maccess(page);
  for (int x = 0;x < 1024*1024; ++x) {
    asm volatile(
        "xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000070, %%r12; mov $1, %%r13; mov $10, %%r11;tdcall;"
        :::"rsi","r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdi", "rdi","rbx", "memory");
    serialize();
  
    uint64_t o = accessed(page);
    serialize();
    o = o > 1024 ? (1024-1) : o;
    ++zz[o];
  }
  maccess(page);
  for (int x = 0;x < 1024*1024; ++x) {
    clflush_(page);
    asm volatile(
        "xor %%rax, %%rax; xor %%r10, %%r10; mov $0xff00, %%rcx; mov $0x40000068, %%r12; mov $1, %%r13; mov $10, %%r11;tdcall;"
        :::"rsi","r8", "r9","r10", "r11", "r12", "r13", "r14", "r15", "rax","rcx", "rdi", "rdi","rbx", "memory");
    serialize();
    uint64_t o = accessed(page);
    serialize();
    o = o > 1024 ? (1024-1) : o;
    ++xx[o];
  }
  printDebug("hit = [");
  for (size_t i = 0; i < 1024; ++i) printDebug("%u, ", yy[i]);
  printDebug("]\n");
  printDebug("miss1 = [");
  for (size_t i = 0; i < 1024; ++i) printDebug("%u, ", xx[i]);
  printDebug("]\n");
  printDebug("miss2 = [");
  for (size_t i = 0; i < 1024; ++i) printDebug("%u, ", zz[i]);
  printDebug("]\n");
  
  asm volatile("sti":::"memory");
  vfree(yy);
  vfree(xx);
  vfree(zz);

  
  return 0;

} 

 

void cleanup_module(void) 
{ 
  pr_info("unload.\n"); 
  printDebug("unload.\n");
  debugfs_remove_recursive(subdir);
  vfree(debug_buffer);
} 

 

MODULE_LICENSE("GPL");

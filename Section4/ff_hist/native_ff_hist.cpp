#include <stdio.h>
#include <stdint.h>

uint32_t hit[1024];
uint32_t miss[1024];
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
void serialize(void) {
  asm volatile("serialize":::"memory");
}
void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }
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


char arr[4096*4];

int main() {
  arr[2*4096] = 7;
  serialize();
  for (size_t i = 0; i < 1024*1024; ++i){ 
    maccess(&arr[2*4096]);
    serialize();
    size_t time = accessed(&arr[2*4096]);
    serialize();
    time = time > 1024 ? (1024-1) : time;
    ++hit[time];
  }
  serialize();
  for (size_t i = 0; i < 1024*1024; ++i){ 
    clflush_(&arr[2*4096]);
    serialize();
    size_t time = accessed(&arr[2*4096]);
    serialize();
    time = time > 1024 ? (1024-1) : time;
    ++miss[time];
  }
  printf("hit = [");
  for (size_t i = 0; i < 1024; ++i) printf("%u, ", hit[i]);
  printf("]\n");
  printf("miss = [");
  for (size_t i = 0; i < 1024; ++i) printf("%u, ", miss[i]);
  printf("]\n");
}

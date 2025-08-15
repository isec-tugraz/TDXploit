#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <map>
#include <vector>
#include <cstring>

#define _XOPEN_SOURCE 700
#include <fcntl.h> /* open */
#include <stdint.h> /* uint64_t  */
#include <stdio.h> /* printf */
#include <stdlib.h> /* size_t */
#include <unistd.h> /* pread, sysconf */
#include <assert.h> /* pread, sysconf */

void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }
uint64_t rdtsc(void) { 
  uint64_t a, d; 
  asm volatile("rdtsc" : "=a"(a), "=d"(d) ::"memory"); 
  return (d << 32) | a; 
} 
void flush(void *mem) { 
  asm volatile("clflush (%0)"::"r"(mem):"memory"); 
} 
void mfence(void) {
  asm volatile("mfence":::"memory");
}
typedef struct {
    uint64_t pfn : 55;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

/* Parse the pagemap entry for the given virtual address.
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * @param[in]  vaddr      virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr)
{
    size_t nread;
    ssize_t ret;
    uint64_t data;
    uintptr_t vpn;

    vpn = vaddr / sysconf(_SC_PAGE_SIZE);
    nread = 0;
    while (nread < sizeof(data)) {
        ret = pread(pagemap_fd, ((uint8_t*)&data) + nread, sizeof(data) - nread,
                vpn * sizeof(data) + nread);
        nread += ret;
        if (ret <= 0) {
            return 1;
        }
    }
    entry->pfn = data & (((uint64_t)1 << 55) - 1);
    entry->soft_dirty = (data >> 55) & 1;
    entry->file_page = (data >> 61) & 1;
    entry->swapped = (data >> 62) & 1;
    entry->present = (data >> 63) & 1;
    return 0;
}

/* Convert the given virtual address to physical using /proc/PID/pagemap.
 *
 * @param[out] paddr physical address
 * @param[in]  pid   process to convert for
 * @param[in] vaddr virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr)
{
    char pagemap_file[BUFSIZ];
    int pagemap_fd;

    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)pid);
    pagemap_fd = open(pagemap_file, O_RDONLY);
    if (pagemap_fd < 0) {
        return 1;
    }
    PagemapEntry entry;
    if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
        return 1;
    }
    close(pagemap_fd);
    *paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
    return 0;
}

// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (140)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (1000000)

unsigned char key[] =
{
  0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

size_t sum;
size_t scount;

std::map<char*, std::map<size_t, size_t> > timings;

char* base;
char* probe;
char* end;


uint64_t getcommand() {
  uint64_t out = -1;
  asm volatile ("mov $0x40000069, %%rax; mov $1, %%rcx; cpuid;":"=a"(out)::"rbx", "rcx", "rdx", "memory");
  return out;
}
uint64_t post_plaintext(unsigned char plaintext[16]) {
  uint64_t out = -1;
  uint64_t p1;
  uint64_t p2;
  memcpy(&p1, plaintext, 8);
  memcpy(&p2, plaintext+8, 8);
  asm volatile ("mov $0x40000069, %%rax; cpuid;":"=a"(out), "+c"(p1)::"rbx", "rdx");
  asm volatile ("mov $0x40000069, %%rax; cpuid;":"=a"(out), "+c"(p2)::"rbx", "rdx");
  return out;
}
void post_key(unsigned char plaintext[16]) {
  uint64_t out = -1;
  uint64_t p1;
  uint64_t p2;
  memcpy(&p1, plaintext, 8);
  memcpy(&p2, plaintext+8, 8);
  asm volatile ("mov $0x40000040, %%rax; cpuid;":"=a"(out), "+c"(p1)::"rbx", "rdx");
  asm volatile ("mov $0x40000041, %%rax; cpuid;":"=a"(out), "+c"(p2)::"rbx", "rdx");
}

int main()
{
  int rng = open("/dev/urandom", O_RDONLY);
  int fd = open("./openssl/libcrypto.so", O_RDONLY);
  size_t size = lseek(fd, 0, SEEK_END);
  if (size == 0)
    exit(-1);
  size_t map_size = size;
  if (map_size & 0xFFF != 0)
  {
    map_size |= 0xFFF;
    map_size += 1;
  }
  base = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0)+0x1ccbc0;
  end = base + 1024;
  maccess(base);
  maccess(end);
  uintptr_t ad, ad2;
  assert(0 == virt_to_phys_user(&ad, getpid(), (uintptr_t)base));
  printf("%p\n", ad);
  assert(0 == virt_to_phys_user(&ad2, getpid(), ((uintptr_t)base)+0x1000));
  printf("%p\n", ad2);
  

  unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  unsigned char ciphertext[128];
  unsigned char restoredtext[128];

  AES_KEY key_struct;

  read(rng, key, 16);
  AES_set_encrypt_key(key, 128, &key_struct);
  size_t c = 1;

  while (1) {
    auto c = getcommand();
    printf("%lx\n", c);
    if (c == 1) {
      auto e = rdtsc()+ 10000000000ULL;
      while (e > rdtsc()) asm volatile ("":::"memory");
      continue;
    }
    if (c == 2) {
      auto e = rdtsc()+ 10000000000ULL;
      while (e > rdtsc()) {
        AES_encrypt(plaintext, ciphertext, &key_struct);
      }
      continue;
    }
    break;
  }
  post_key(key);

  uint64_t min_time = rdtsc();
  srand(min_time);
  sum = 0;


  for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
  {
    for (size_t i = 0; i < 16; ++i)
      plaintext[i] = rand() % 256;


    AES_encrypt(plaintext, ciphertext, &key_struct);
    if (post_plaintext(ciphertext)) {
      read(rng, key, 16);
      AES_set_encrypt_key(key, 128, &key_struct);
      post_key(key);
    }
  }

  for (auto ait : timings)
  {
    printf("%6p", (void*) (ait.first - base));
    for (auto kit : ait.second)
    {
      printf(",%4lu", kit.second);
    }
    printf("\n");
  }

  close(fd);
  munmap(base, map_size);
  fflush(stdout);
  return 0;
}


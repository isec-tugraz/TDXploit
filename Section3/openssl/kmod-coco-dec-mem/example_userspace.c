#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

static inline void clflush(volatile void *p) {
  asm volatile ("clflush (%0)" :: "r"(p));
}

int main() {
  int ret = 0;
  int fd = -1;
  void* buf;
  size_t buf_bytes = 1*4096;
  char* mod_path = "/dev/coco_dec_mem";

  printf("Opening kernel module dev file at %s\n", mod_path);
  fd = open(mod_path, O_RDWR|O_CLOEXEC);
  if(fd == -1 ) {
    printf("Failed to open %s\n", mod_path);
    return -1;
  }

  printf("Allocating unencrypted memory\n");
  //MAP_SHARED is important here! I thought this was only about IPC but without it raw
  //read/writes from the hypervisor to this address are not visisble
  buf = mmap(NULL, buf_bytes, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
  if(buf == MAP_FAILED) {
    printf("Failed to allocated unencrypted memory\n");
    goto error;
  }

  printf("Writing all 42 to memory\n");
  memset(buf, 42, buf_bytes);
  clflush(buf);
  

  printf("Straightforward vaddr to gpa parsing does not work yet. Check dmesg log for gpa");

  printf("Press enter to terminate\n");
  getchar();
  printf("Reading first byte of buf: 0x%x\n", *((volatile uint8_t*)buf));
  printf("Bye\n");
  

  goto cleanup;
error:
  ret = -1;
cleanup:
  if(fd != -1) close(fd);
  if(buf) munmap(buf, buf_bytes);
  return ret;
}

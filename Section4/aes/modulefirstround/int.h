#define COLLECT _IO(0x41, 1)
#define END _IO(0x41, 2)

#define DEVICE_NAME "attacker"

struct __attribute__((packed)) row_t {
    unsigned long long  addr;
};

struct Args {
  struct row_t *data;
  void **num;
  unsigned long long start;
};



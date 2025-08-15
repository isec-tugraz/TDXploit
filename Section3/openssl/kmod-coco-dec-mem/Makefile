all: coco_dec_mem.ko example_userspace
.PHONY: clean 

CFLAGS= -O3 -std=gnu11 -Wall -Wextra -Wpedantic -Werror

ifndef KERNEL_PATH
$(info Using currently running kernel. Overwrite KERNEL_PATH env var to change this)
KERNEL_RELEASE = $(shell uname -r)
KERNEL_PATH = /lib/modules/$(KERNEL_RELEASE)/build
endif

$(info Using KERNEL_PATH=$(KERNEL_PATH))

obj-m += coco_dec_mem.o
coco_dec_mem.ko: coco_dec_mem.c
	make -C $(KERNEL_PATH) M=$(PWD) modules

example_userspace: example_userspace.c
	gcc $(CFLAGS) -o example_userspace example_userspace.c

clean:
	rm -f coco_dec_mem.ko
	rm -f example_userspace
	rm -f modules.order
	rm -f *.o
	rm -f *.mod

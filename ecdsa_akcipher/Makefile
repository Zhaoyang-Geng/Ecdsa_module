CONFIG_MODULE_SIG=n

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build


MODULE_NAME := ecdsa_kernel_module


obj-m := $(MODULE_NAME).o

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

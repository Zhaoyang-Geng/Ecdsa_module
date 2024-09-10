KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

# 模块名
MODULE_NAME := md5_option

# 编译的对象文件
obj-m := $(MODULE_NAME).o

# 源文件
$(MODULE_NAME)-y += md5_module.o
$(MODULE_NAME)-y += firstmod.o

# 默认目标
all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

# 清理目标
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

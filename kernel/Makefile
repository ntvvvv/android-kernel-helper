KERNELDIR := /media/frank/data/goldfish-kernel/goldfish
PWD := $(shell pwd)
ARCH=x86_64
CROSS_COMPILE=/media/frank/data/android-aosp/prebuilts/gcc/linux-x86/x86/x86_64-linux-android-4.9/bin/x86_64-linux-android-
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
obj-m := main.o
modules:
	$(MAKE) -C $(KERNELDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD)  
clean:
	rm *.o *.ko *.mod.c *.order
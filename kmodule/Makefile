ifneq (${KERNELRELEASE},)
    obj-m := netcop.o
# Otherwise we were called directly from the command line.
# Invoke the kernel build system.
else
    KERNEL_SOURCE := /usr/src/linux
    PWD := $(shell pwd)
default:
	#${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules
	${MAKE} -C /lib/modules/$(shell uname -r)/build M=${PWD} modules
 
clean:
	#${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean
	rm -rf *.o *.order *.symvers *.ko *.mod.c .*.cmd .tmp_versions/
endif

# Kernel module Makefile
obj-m += lpr_parser.o
lpr_parser-objs := main.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers

# Install dependencies
install-deps:
	@echo "Installing dependencies (Ubuntu/Debian):"
	sudo apt-get update
	sudo apt-get install -y linux-headers-$(shell uname -r) build-essential
	@echo "Installing dependencies (CentOS/RHEL):"
	@echo "sudo yum install kernel-devel-$(shell uname -r) gcc make"
	@echo "or:"
	@echo "sudo dnf install kernel-devel-$(shell uname -r) gcc make"

# Load module
load:
	sudo insmod lpr_parser.ko

# Unload module
unload:
	sudo rmmod lpr_parser

# Show module info
info:
	modinfo lpr_parser.ko

# Show kernel messages
logs:
	dmesg | tail -20

.PHONY: all clean install-deps load unload info logs

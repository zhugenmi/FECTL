# Makefile for module

CC=gcc

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

CFLAGS += -I$(PWD)

obj-m := fectl_lsm.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

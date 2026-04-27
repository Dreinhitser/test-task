obj-m += vnet_ping.o
KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod vnet_ping.ko

unload:
	sudo rmmod vnet_ping
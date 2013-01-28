
obj-m += gaommio.o
#gaommio-objs += gao_mmio_interfaces.o gao_mmio_buffers.o gao_mmio_descriptors.o gao_mmio_queues.o gao_mmio_core.o 
gaommio-objs += gao_mmio_controller_port.o gao_mmio_port.o gao_mmio_resource.o gao_mmio.o


KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

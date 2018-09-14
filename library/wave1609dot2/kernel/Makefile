TARGET ?= virgil-wave1609dot2
KERNEL ?= /lib/modules/$(shell uname -r)/build

MBEDTLS = $(PWD)/mbedtls
MBEDTLS_CFLAGS = -I$(PWD)/include -I$(PWD)/../include -I$(PWD)/../include/virgil/wave1609dot2 \
	-I$(PWD)/../include/virgil/wave1609dot2/private -I$(MBEDTLS)/mbedtls/include \
	-include $(PWD)/lk.h -DMBEDTLS_CONFIG_FILE='"$(MBEDTLS)/config.h"'
export MBEDTLS MBEDTLS_CFLAGS

obj-m = $(TARGET).o
obj-y = mbedtls/

ccflags-y = $(MBEDTLS_CFLAGS)

$(TARGET)-y = main.o lk.o mbedtls/built-in.o \
	../src/vscw_assert.o ../src/vscw_error.o \
	../src/vscw_library.o ../src/vscw_memory.o \
	../src/vscw_wave1609dot2.o ../src/vscw_wave1609dot2_defs.o

all:
	$(MAKE) -C $(KERNEL) M=$(PWD)

clean:
	$(MAKE) -C $(KERNEL) M=$(PWD) clean

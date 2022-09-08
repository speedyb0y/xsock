
KBUILD:=/lib/modules/$(shell uname -r)/build/

CFLAGS_srv.o += -Wfatal-errors
CFLAGS_srv.o += -Werror
CFLAGS_srv.o += -Wall
CFLAGS_srv.o += -Wextra
CFLAGS_srv.o += -Wno-declaration-after-statement
CFLAGS_srv.o += -Wno-error=unused-parameter
CFLAGS_srv.o += -Wno-error=unused-function
CFLAGS_srv.o += -Wno-error=unused-label
CFLAGS_srv.o += -Wno-type-limits
CFLAGS_srv.o += -Wno-unused-parameter
CFLAGS_srv.o += -mpopcnt

CFLAGS_clt.o += -Wfatal-errors
CFLAGS_clt.o += -Werror
CFLAGS_clt.o += -Wall
CFLAGS_clt.o += -Wextra
CFLAGS_clt.o += -Wno-declaration-after-statement
CFLAGS_clt.o += -Wno-error=unused-parameter
CFLAGS_clt.o += -Wno-error=unused-function
CFLAGS_clt.o += -Wno-error=unused-label
CFLAGS_clt.o += -Wno-type-limits
CFLAGS_clt.o += -Wno-unused-parameter
CFLAGS_clt.o += -mpopcnt

obj-m += srv.o
obj-m += clt.o

default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean

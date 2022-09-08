
KBUILD:=/lib/modules/$(shell uname -r)/build/

CFLAGS_xsock-srv.o += -Wfatal-errors
CFLAGS_xsock-srv.o += -Werror
CFLAGS_xsock-srv.o += -Wall
CFLAGS_xsock-srv.o += -Wextra
CFLAGS_xsock-srv.o += -Wno-declaration-after-statement
CFLAGS_xsock-srv.o += -Wno-error=unused-parameter
CFLAGS_xsock-srv.o += -Wno-error=unused-function
CFLAGS_xsock-srv.o += -Wno-error=unused-label
CFLAGS_xsock-srv.o += -Wno-type-limits
CFLAGS_xsock-srv.o += -Wno-unused-parameter
CFLAGS_xsock-srv.o += -mpopcnt

CFLAGS_xsock-clt.o += -Wfatal-errors
CFLAGS_xsock-clt.o += -Werror
CFLAGS_xsock-clt.o += -Wall
CFLAGS_xsock-clt.o += -Wextra
CFLAGS_xsock-clt.o += -Wno-declaration-after-statement
CFLAGS_xsock-clt.o += -Wno-error=unused-parameter
CFLAGS_xsock-clt.o += -Wno-error=unused-function
CFLAGS_xsock-clt.o += -Wno-error=unused-label
CFLAGS_xsock-clt.o += -Wno-type-limits
CFLAGS_xsock-clt.o += -Wno-unused-parameter
CFLAGS_xsock-clt.o += -mpopcnt

obj-m += xsock-srv.o
obj-m += xsock-clt.o

default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean

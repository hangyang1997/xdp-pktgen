### XDP PKTGEN MAKE

CC ?= gcc
LLC ?= llc
CLANG ?= clang
M4 ?= m4

OBJS := xdev.o xudp.o xtcp.o keyword.o command.o xtask.o
KOBJS := xdev_kernel.o

Y := xpkt-command.y
L := xpkt-keyword.l

LIBBPF = ./libbpf/src

CFLAGS += -I$(LIBBPF) -g -O0 -Werror -Wall
BPF_CFLAGS += -I$(LIBBPF)

ifdef asan
LDFLAGS += -lasan
CFLAGS += -fsanitize=address
endif

LDFLAGS += -L$(LIBBPF) -l:libbpf.a -lelf -lz -lpthread -lreadline

.PHONY : xpktgen llvm-check $(CLANG) $(LLC) clean

xpktgen: llvm-check $(KOBJS) pre-progress xpkt

xpkt: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%o.%c:
	$(CC) $(CFLAGS) -c -o $@ $<

pre-progress: pre-1 pre-2
	$(CC) $(CFLAGS) -c -o command.o command.c
	$(CC) $(CFLAGS) -c -o keyword.o keyword.c

pre-2: $Y $L
	bison -dv -o command.c --header=command.h $Y
	flex -f -B -8 --outfile=keyword.c $L

pre-1: front.m4 
	$(M4) -P $< command.y > $Y
	$(M4) -P $< keyword.l > $L

$(KOBJS): %.o : %.c
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

clean:
	rm -f *.ll
	rm -f *.o
	rm -f xpkt
	rm -f command.h command.c command.output
	rm -f keyword.c $Y $L

### XDP PKTGEN MAKE

CC ?= gcc
LLC ?= llc
CLANG ?= clang

OBJS := xdev.o xpktgen.o
KOBJS := xdev_kernel.o

LIBBPF = ./libbpf/src

CFLAGS = -I$(LIBBPF) -I$(LIBBPF)/../include -g -O0 -Werror -Wall
BPF_CFLAGS += -I$(LIBBPF)
LDFLAGS += -L$(LIBBPF) -l:libbpf.a -lelf -lz

.PHONY : xpktgen llvm-check $(CLANG) $(LLC) clean

xpktgen: $(KOBJS) llvm-check xpkt

xpkt: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%o.%c:
	$(CC) $(CFLAGS) -c -o $@ $<

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

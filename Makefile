### XDP PKTGEN MAKE

CC ?= gcc

OBJS := xdev.o
CFLAGS = -I./libbpf/src -I./libbpf/include -g -O2 -Werror -Wall

.PHONY : xpktgen

xpktgen: $(OBJS)

%o.%c:
	$(CC) $(CFLAGS) -c -o $@ $<

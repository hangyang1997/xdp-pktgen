#include <net/if.h>
#include <argp.h>
#include <stdlib.h>
#include <unistd.h>
#include "xutil.h"
#include "xdev.h"
#include "xlog.h"

// test

int main(int argc, char **argv)
{
	struct xdev *dev;
	const char *ifname = "enp0s3";
	int index;
	struct xbuf bufs[1024];

	index = if_nametoindex(ifname);
	x_interface_attach(1, &index, "xdev_kernel.o");

	dev = x_dev_create(if_nametoindex(ifname), 0, 50, 50, 2048);
	if (!dev) {
		exit(-1);
	}

	int n_recv;
	while(1) {
		n_recv = x_dev_rx_burst(dev, bufs, 1024);
		printf("recv pkts cnt %d\n", n_recv);
		for (int i = 0; i < n_recv; ++i) {
			x_umem_free(dev, bufs[i].addr);
		}
		sleep(1);
	}

	return 0;
}

#include <net/if.h>
#include <argp.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include "xutil.h"
#include "xdev.h"
#include "xlog.h"
#include "xpkt.h"

int main(int argc, char **argv)
{
	struct xdev *dev;
	const char *ifname = "enp0s3";
	int index;
	struct xbuf bufs;
	struct timeval tv, ntv;
	__u64 send_cnt = 0;
	struct xudp uinfo;

	sscanf("08:00:27:db:19:cf", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&uinfo.smac[0],&uinfo.smac[1],&uinfo.smac[2],
		&uinfo.smac[3],&uinfo.smac[4],&uinfo.smac[5]);

	sscanf("08:00:27:99:1b:3f", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&uinfo.dmac[0],&uinfo.dmac[1],&uinfo.dmac[2],
		&uinfo.dmac[3],&uinfo.dmac[4],&uinfo.dmac[5]);

	uinfo.data_len = 9;
	uinfo.dport = 1000;
	uinfo.sport = 10001;
	uinfo.daddr = inet_addr("192.168.1.184");
	uinfo.saddr = inet_addr("192.168.1.200");

	index = if_nametoindex(ifname);
	x_interface_attach(1, &index, "xdev_kernel.o");

	dev = x_dev_create(if_nametoindex(ifname), 0, 2048, 2048, 2048);
	if (!dev) {
		exit(-1);
	}

	gettimeofday(&tv, NULL);
	while(1) {
		gettimeofday(&ntv, NULL);
		if (ntv.tv_sec > tv.tv_sec) {
			printf ("send pkt %llu\n", send_cnt);
			tv = ntv;
		}
		// sleep(1);

		if (x_udp_builder(dev, &uinfo, &bufs)) {
			puts("out of memory");
			x_dev_complete_tx(dev);
			continue;
		}

		int nret = x_dev_tx_burst(dev, &bufs, 1);
		send_cnt += nret;
		if (nret < 1) {
			x_umem_free(dev, bufs.addr);
		}
	}

	return 0;
}

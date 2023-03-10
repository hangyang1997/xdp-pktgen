#ifndef __XCFG_H
#define __XCFG_H

#include <linux/types.h>

#define DEV_INDEX_MAX 64
#define MAX_QUEUEID 64

#define DEV_MAX_QUEUE_SIZE 4096
#define DEV_MAX_FRAME_SIZE 8192

#define DEFAULT_XDEV_QUEUE_SIZE 2048
#define DEFAULT_XDEV_FRAME_SIZE 2048

#define PKT_MAX_DATA_LEN 1400
#define PKT_MIN_DATA_LEN 16
#define PKT_DEFAULT_DATA_LEN 64

#define MAX_PKT_SEND 64

#define DEFAULT_XDEV_XOBJ "xdev_kernel.o"

enum tx_pkt_type {
	X_UDP,
	X_TCP_SYN,
};

struct config {
	unsigned src_begin;
	unsigned src_end;
	unsigned dest;
	__u16 dport;
	char *ifname;
	__u8 queue_id[MAX_QUEUEID];
	__u8 queue_core_id[MAX_QUEUEID];
	int nqueue;
	__u8 rx_queue_id[MAX_QUEUEID];
	__u8 rx_queue_core_id[MAX_QUEUEID];
	int rx_nqueue;
	int ifindex;
	int time;
	__u16 data_len;
	__u8 smac[6];
	__u8 dmac[6];
	enum tx_pkt_type pkt_type;
};

extern struct config cfg;

void cmd_parse(int argc, char **argv);

#endif

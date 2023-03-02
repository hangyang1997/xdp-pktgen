#ifndef __XPKT_H
#define __XPKT_H

struct xudp {
	__u8 smac[6];
	__u8 dmac[6];
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 data_len;
};

int x_udp_builder (struct xdev *dev, struct xudp *uinfo, struct xbuf *buf);

#endif

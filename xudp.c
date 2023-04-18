#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <string.h>
#include <errno.h>
#include "xutil.h"
#include "xdev.h"
#include "xpkt.h"
#include "xconfig.h"


int x_udp_builder (struct xdev *dev, struct L4PKT *uinfo, struct xbuf *buf)
{
	struct ethhdr *eh;
	struct iphdr *ih;
	struct udphdr *uh;

	if (uinfo->data_len > PKT_MAX_DATA_LEN) {
		return -E2BIG;
	}

	buf->addr = x_umem_alloc(dev);
	if (buf->addr == INVALID_UMEM) {
		return -ENOMEM;
	}
	buf->len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + uinfo->data_len;

	eh = x_umem_address(dev, buf->addr);
	memcpy(eh->h_source, uinfo->smac, 6);
	memcpy(eh->h_dest, uinfo->dmac, 6);
	eh->h_proto = __cpu_to_be16(ETH_P_IP);

	ih = (struct iphdr*)(eh + 1);
	ih->saddr = uinfo->saddr;
	ih->daddr = uinfo->daddr;
	ih->version = 4;
	ih->id = 0;
	ih->frag_off = __cpu_to_be16(0x4000);
	ih->tot_len = __cpu_to_be16(sizeof(struct iphdr) + sizeof(struct udphdr) + uinfo->data_len);
	ih->ihl = sizeof(struct iphdr) >> 2;
	ih->check = 0;
	ih->ttl = 64;
	ih->protocol = IPPROTO_UDP;
	ih->check = __ip_cksum(ih, sizeof(struct iphdr));

	uh = (struct udphdr *)(ih + 1);
	uh->check = 0;
	uh->dest = __cpu_to_be16(uinfo->dport);
	uh->source = __cpu_to_be16(uinfo->sport);
	uh->len = __cpu_to_be16(sizeof(*uh) + uinfo->data_len);

	return 0;
}

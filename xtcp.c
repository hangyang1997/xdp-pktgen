#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include "xutil.h"
#include "xdev.h"
#include "xpkt.h"
#include "xconfig.h"

static inline __sum16 csum_fold(__wsum csum)
{
	__u32 sum = (__u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}


static inline __wsum
csum_tcpudp_nofold(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	asm("  addl %1, %0\n"
	    "  adcl %2, %0\n"
	    "  adcl %3, %0\n"
	    "  adcl $0, %0\n"
		: "=r" (sum)
	    : "g" (daddr), "g" (saddr), "g" ((len + proto) << 8), "0" (sum));
	return sum;
}

static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
		  __u8 proto, __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline __sum16 tcp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_TCP, base);
}

int x_tcp_syn_builder (struct xdev *dev, struct L4PKT *tinfo, struct xbuf *buf)
{
	struct ethhdr *eh;
	struct iphdr *ih;
	struct tcphdr *th;

	if (tinfo->data_len > PKT_MAX_DATA_LEN) {
		return -E2BIG;
	}

	buf->addr = x_umem_alloc(dev);
	if (buf->addr == INVALID_UMEM) {
		return -ENOMEM;
	}
	buf->len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);

	eh = x_umem_address(dev, buf->addr);
	memcpy(eh->h_source, tinfo->smac, 6);
	memcpy(eh->h_dest, tinfo->dmac, 6);
	eh->h_proto = __cpu_to_be16(ETH_P_IP);

	ih = (struct iphdr*)(eh + 1);
	ih->saddr = tinfo->saddr;
	ih->daddr = tinfo->daddr;
	ih->version = 4;
	ih->id = 0;
	ih->frag_off = __cpu_to_be16(0x4000);
	ih->tot_len = __cpu_to_be16(sizeof(struct iphdr) + sizeof(struct tcphdr));
	ih->ihl = sizeof(struct iphdr) >> 2;
	ih->check = 0;
	ih->ttl = 64;
	ih->protocol = IPPROTO_TCP;
	ih->check = __ip_cksum(ih, sizeof(struct iphdr));

	th = (struct tcphdr*)(ih + 1);
	memset(th, 0, sizeof(struct tcphdr));
	th->seq = 0;
	th->source = __cpu_to_be16(tinfo->sport);
	th->dest = __cpu_to_be16(tinfo->dport);
	th->window = 0xffff;
	th->ack = 0;
	th->syn = 1;
	th->check = 0;
	th->doff = sizeof(struct tcphdr) >> 2;
	th->check = tcp_v4_check(sizeof(struct tcphdr), tinfo->saddr, tinfo->daddr,
		csum_partial(th, sizeof(struct tcphdr), 0));

	return 0;
}






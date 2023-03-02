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

static inline uint32_t
__ip_cksum(const void *buf, size_t len)
{
	uint32_t sum = 0;
	/* workaround gcc strict-aliasing warning */
	uintptr_t ptr = (uintptr_t)buf;
	typedef uint16_t __attribute__((__may_alias__)) u16_p;
	const u16_p *u16_buf = (const u16_p *)ptr;

	while (len >= (sizeof(*u16_buf) * 4)) {
		sum += u16_buf[0];
		sum += u16_buf[1];
		sum += u16_buf[2];
		sum += u16_buf[3];
		len -= sizeof(*u16_buf) * 4;
		u16_buf += 4;
	}
	while (len >= sizeof(*u16_buf)) {
		sum += *u16_buf;
		len -= sizeof(*u16_buf);
		u16_buf += 1;
	}

	/* if length is in odd bytes */
	if (len == 1)
		sum += *((const uint8_t *)u16_buf);

	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);

	return (uint16_t)~sum;
}

static inline void __data_build (void *buf, unsigned len)
{
	char* data = buf;

	for (unsigned i = 0; i < len; ++i) {
		data[i] = '0' + (i & 42);
	}
}

int x_udp_builder (struct xdev *dev, struct xudp *uinfo, struct xbuf *buf)
{
	struct ethhdr *eh;
	struct iphdr *ih;
	struct udphdr *uh;

	if (uinfo->data_len > 1024) {
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
	ih->check = __ip_cksum(ih, ih->ihl);

	uh = (struct udphdr *)(ih + 1);
	uh->check = 0;
	uh->dest = __cpu_to_be16(uinfo->dport);
	uh->source = __cpu_to_be16(uinfo->sport);
	uh->len = __cpu_to_be16(sizeof(*uh) + uinfo->data_len);
	__data_build(uh + 1, uinfo->data_len);

	return 0;
}

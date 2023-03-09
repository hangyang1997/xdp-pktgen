#ifndef __XPKT_H
#define __XPKT_H

#define PKT_MAX_DATA_LEN 1400
#define PKT_MIN_DATA_LEN 16
#define PKT_DEFAULT_DATA_LEN 64

struct L4PKT {
	__u8 smac[6];
	__u8 dmac[6];
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 data_len;
};

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
	uint32_t *u32_data  = buf;
	unsigned data;

	data ='0';
	data |= data << 8;
	data |= data << 16;

	u32_data = buf;
	while (len >= 4) {
		*u32_data = data;
		u32_data++;
		len -= 4;
	}

	char *ucdata = (char*)u32_data;
	while (len-- > 0) {
		ucdata[len] = '0';
	}
}

int x_udp_builder (struct xdev *dev, struct L4PKT *uinfo, struct xbuf *buf);
int x_tcp_builder (struct xdev *dev, struct L4PKT *tinfo, struct xbuf *buf);

#endif

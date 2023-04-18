#ifndef __XPKT_H
#define __XPKT_H

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

static inline unsigned short from64to16(unsigned long x)
{
	/* Using extract instructions is a bit more efficient
	   than the original shift/bitmask version.  */

	union {
		unsigned long	ul;
		unsigned int	ui[2];
		unsigned short	us[4];
	} in_v, tmp_v, out_v;

	in_v.ul = x;
	tmp_v.ul = (unsigned long) in_v.ui[0] + (unsigned long) in_v.ui[1];

	/* Since the bits of tmp_v.sh[3] are going to always be zero,
	   we don't have to bother to add that in.  */
	out_v.ul = (unsigned long) tmp_v.us[0] + (unsigned long) tmp_v.us[1]
			+ (unsigned long) tmp_v.us[2];

	/* Similarly, out_v.us[2] is always zero for the final add.  */
	return out_v.us[0] + out_v.us[1];
}


static inline unsigned long do_csum(const unsigned char * buff, int len)
{
	int odd, count;
	unsigned long result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
		result = *buff << 8;
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			if (4 & (unsigned long) buff) {
				result += *(unsigned int *) buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */
			if (count) {
				unsigned long carry = 0;
				do {
					unsigned long w = *(unsigned long *) buff;
					count--;
					buff += 8;
					result += carry;
					result += w;
					carry = (w > result);
				} while (count);
				result += carry;
				result = (result & 0xffffffff) + (result >> 32);
			}
			if (len & 4) {
				result += *(unsigned int *) buff;
				buff += 4;
			}
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = from64to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

static inline __wsum csum_partial(const void *buff, int len, __wsum sum)
{
	unsigned long result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += (__u32)sum;
	/* 32+c bits -> 32 bits */
	result = (result & 0xffffffff) + (result >> 32);
	return (__wsum)result;
}

int x_udp_builder (struct xdev *dev, struct L4PKT *uinfo, struct xbuf *buf);
int x_tcp_syn_builder (struct xdev *dev, struct L4PKT *tinfo, struct xbuf *buf);

#endif

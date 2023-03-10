#ifndef __XDEV_H
#define __XDEV_H

#include <linux/types.h>
#include <stdint.h>

#define INVALID_UMEM UINT64_MAX

struct xdev;

struct xbuf {
	__u64 addr;
	unsigned len;
};

struct xdev_status {
	__u64 rx_drop;
	__u64 rx_invalid_descs;
	__u64 tx_invalid_descs;
	__u64 rx_ring_full;
};

struct xdev * x_dev_create (int ifindex, int qindex, unsigned tx_qs, unsigned rx_qs, unsigned frame_size);
void x_dev_destroy(struct xdev *dev);

__u64 x_umem_alloc(struct xdev *dev);
void x_umem_free(struct xdev *dev, __u64 addr);

void x_dev_complete_tx (struct xdev *dev);
void x_dev_fill_rx (struct xdev *dev);

int x_dev_tx_burst(struct xdev *dev, struct xbuf *pkts, unsigned npkt);
int x_dev_rx_burst(struct xdev *dev, struct xbuf *pkts, unsigned npkt);

int x_interface_attach (int ifindex, const char *xdp_obj_path);
void x_interface_detach(int ifindex);

void * x_umem_address(struct xdev *dev, __u64 addr);

int x_dev_status_get(struct xdev *dev, struct xdev_status *status);

#endif

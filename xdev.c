#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <linux/if_xdp.h>
#include <bpf.h>
#include <libbpf.h>
#include "xutil.h"
#include <linux/compiler.h>

#define XDEV_NB 64
#define INVALID_UMEM UINT64_MAX

struct dev_map {
	int map_fd;
} dev_maps[XDEV_NB];

struct xrings {
	void *ring;
	unsigned *productor;
	unsigned *consumer;
	unsigned cache;
	unsigned n;
};

struct xdev {
	int xsk;
	int ifindex;
	int qindex;
	int bind;

	void *umem;
	__u64 *umem_alloc_buffer;
	unsigned frame_size;
	unsigned n_umem_free;
	unsigned n_umem_size;

	struct xrings rx;
	struct xrings tx;
	struct xrings cr;
	struct xrings fr;
};

static inline __u64 umem_alloc(struct xdev *dev)
{
	if (dev->n_umem_free == 0) {
		return INVALID_UMEM;
	}

	return dev->umem_alloc_buffer[--dev->n_umem_free];
}

static inline void umem_free(struct xdev *dev, __u64 addr)
{
	dev->umem_alloc_buffer[dev->n_umem_free++] = addr;
}

static inline void x_dev_destroy(struct xdev *dev)
{
	if (dev->bind) {
		bpf_map_delete_elem(dev_maps[dev->ifindex].map_fd, &dev->qindex);
	}

	if (dev->xsk >= 0) {
		close(dev->xsk);
	}
	XFREE(dev->umem);
	XFREE(dev->umem_alloc_buffer);
	XFREE(dev);
}

static inline struct xdev * x_dev_create (int ifindex, int qindex, unsigned tx_qs, unsigned rx_qs, unsigned frame_size)
{
	struct xdp_umem_reg umem_reg;
	struct xdp_mmap_offsets offs;
	struct sockaddr_xdp sxdp;
	struct xdp_desc *xdesc;
	struct xdev *dev;
	unsigned sko_value;
	socklen_t sko_len;
	void *ring_map;

	if (frame_size == 0 || (rx_qs == 0 && tx_qs == 0)) {
		LOG("invalid param");
		return NULL;
	}

	if (dev_maps[ifindex].map_fd <= 0) {
		LOG("ifindex %d not attach xdp socket prog", ifindex);
		return NULL;
	}

	dev = XALLOC(sizeof(struct xdev));

	dev->xsk = socket (AF_XDP, SOCK_RAW, 0);
	if (dev->xsk < 0) {
		LOG("socket err %s", strerror(errno));
		goto err;
	}
	dev->ifindex = ifindex;
	dev->qindex = qindex;

	// set rx tx ring
	sko_value = rx_qs;
	if (setsockopt(dev->xsk, SOL_XDP, XDP_RX_RING, &sko_value, sizeof(sko_value))) {
		LOG("set rx ring size %u err, (%s)", rx_qs, strerror(errno));
		goto err;
	}
	sko_value = tx_qs;
	if (setsockopt(dev->xsk, SOL_XDP, XDP_TX_RING, &sko_value, sizeof(sko_value))) {
		LOG("set tx ring size %u err, (%s)", tx_qs, strerror(errno));
		goto err;
	}

	//init umem
	dev->n_umem_size = tx_qs + rx_qs;
	dev->frame_size = frame_size;
	if (posix_memalign(&dev->umem, getpagesize(), frame_size*dev->n_umem_size)) {
		LOG("posix_memalign err");
		goto err;
	}
	dev->umem_alloc_buffer = XALLOC(sizeof(__u64) * dev->n_umem_size);
	for (int i = 0; i < dev->n_umem_size; ++i) {
		dev->umem_alloc_buffer[i] = i * dev->frame_size;
	}
	dev->n_umem_free = dev->n_umem_size;

	umem_reg.addr = (uintptr_t)dev->umem;
	umem_reg.chunk_size = frame_size;
	umem_reg.len = frame_size*dev->n_umem_size;
	umem_reg.flags = 0;
	umem_reg.headroom = 0;
	if (setsockopt(dev->xsk, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg))) {
		LOG("umem register err, (%s)", strerror(errno));
		goto err;
	}

	// set cr and fr
	sko_value = tx_qs;
	if (setsockopt(dev->xsk, SOL_XDP, XDP_UMEM_COMPLETION_RING, &sko_value, sizeof(sko_value))) {
		LOG("set competion ring size err, size=%u, (%s)", tx_qs, strerror(errno));
		goto err;
	}
	sko_value = rx_qs;
	if (setsockopt(dev->xsk, SOL_XDP, XDP_UMEM_FILL_RING, &sko_value, sizeof(sko_value))) {
		LOG("set fill ring size err, size=%u, (%s)", rx_qs, strerror(errno));
		goto err;
	}

	// get ring offset
	sko_len = sizeof(offs);
	if (getsockopt(dev->xsk, SOL_XDP, XDP_MMAP_OFFSETS, &offs, &sko_len)) {
		LOG("Get ring offsets err, (%s)", strerror(errno));
		goto err;
	}

	dev->rx.n = rx_qs;
	dev->fr.n = rx_qs;
	dev->tx.n = tx_qs;
	dev->cr.n = tx_qs;

	// get rx ring addr
	ring_map = mmap(NULL, offs.rx.desc+rx_qs*sizeof(struct xdp_desc),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, dev->xsk, XDP_PGOFF_RX_RING);
	if (ring_map == MAP_FAILED) {
		LOG("mmap rx ring err, (%s)", strerror(errno));
		goto err;
	}
	dev->rx.ring = (char *)ring_map + offs.rx.desc;
	dev->rx.consumer = (unsigned*)((char*)ring_map + offs.rx.consumer);
	dev->rx.productor = (unsigned*)((char*)ring_map + offs.rx.producer);

	// get tx ring addr
	ring_map = mmap(NULL, offs.tx.desc+tx_qs*sizeof(struct xdp_desc), 
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, dev->xsk, XDP_PGOFF_TX_RING);
	if (ring_map == MAP_FAILED) {
		LOG("mmap tx ring err, (%s)", strerror(errno));
		goto err;
	}
	dev->tx.ring = (char *)ring_map + offs.tx.desc;
	dev->tx.consumer = (unsigned*)((char*)ring_map + offs.tx.consumer);
	dev->tx.productor = (unsigned*)((char*)ring_map + offs.tx.producer);

	// get cr ring addr
	ring_map = mmap(NULL, offs.cr.desc+tx_qs*sizeof(__u64), 
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, dev->xsk, XDP_UMEM_PGOFF_COMPLETION_RING);
	if (ring_map == MAP_FAILED) {
		LOG("mmap cr ring err, (%s)", strerror(errno));
		goto err;
	}
	dev->cr.ring = (char *)ring_map + offs.cr.desc;
	dev->cr.consumer = (unsigned*)((char*)ring_map + offs.cr.consumer);
	dev->cr.productor = (unsigned*)((char*)ring_map + offs.cr.producer);

	// get fr ring addr
	ring_map = mmap(NULL, offs.fr.desc+rx_qs*sizeof(__u64), 
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, dev->xsk, XDP_UMEM_PGOFF_FILL_RING);
	if (ring_map == MAP_FAILED) {
		LOG("mmap fr ring err, (%s)", strerror(errno));
		goto err;
	}
	dev->fr.ring = (char *)ring_map + offs.fr.desc;
	dev->fr.consumer = (unsigned*)((char*)ring_map + offs.fr.consumer);
	dev->fr.productor = (unsigned*)((char*)ring_map + offs.fr.producer);

	sxdp.sxdp_family = AF_XDP;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = qindex;
	sxdp.sxdp_flags = 0;
	sxdp.sxdp_shared_umem_fd = 0;
	if(bind(dev->xsk, (struct sockaddr*)&sxdp, sizeof(sxdp))) {
		LOG("bind ifindex %d queue id %d err, (%s)", ifindex, qindex, strerror(errno));
		goto err;
	}

	// init rx ring
	xdesc = (struct xdp_desc*)dev->rx.ring;
	for (int i = 0; i < dev->rx.n; ++i) {
		xdesc->addr = umem_alloc(dev);
		xdesc->len = dev->frame_size;
	}
	barrier();
	*dev->rx.productor = dev->rx.n;

	if (bpf_map_update_elem(dev_maps[ifindex].map_fd, &qindex, &dev->xsk, BPF_ANY)) {
		LOG("bpf_map_update_elem err");
		goto err;
	}

	return dev;

err:
	x_dev_destroy(dev);
	return NULL;
}

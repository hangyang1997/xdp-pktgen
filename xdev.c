#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_xdp.h>
#include <bpf.h>
#include <libbpf.h>
#include "xutil.h"
#include "xdev.h"

#define DEFAULT_XDEV_PROG_NAME "xdev_hook"
#define DEFAULT_XDEV_MAP_NAME "xdev_map"

#define u64_to_addr(rp, index) (((__u64*)(rp)->ring)[(index) & ((rp)->n-1)])
#define ring_to_xdesc(rp, index) ((struct xdp_desc *)(rp)->ring + ((index) & ((rp)->n-1)))

struct dev_map {
	int map_fd;
} dev_maps;
#define DEV_MAP_FD(ifindex) (dev_maps.map_fd)

struct xrings {
	void *ring;
	unsigned *productor;
	unsigned *consumer;
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

__u64 x_umem_alloc(struct xdev *dev)
{
	if (dev->n_umem_free == 0) {
		return INVALID_UMEM;
	}

	return dev->umem_alloc_buffer[--dev->n_umem_free];
}

void x_umem_free(struct xdev *dev, __u64 addr)
{
	dev->umem_alloc_buffer[dev->n_umem_free++] = addr;
}

void x_dev_destroy(struct xdev *dev)
{
	if (dev->bind) {
		bpf_map_delete_elem(DEV_MAP_FD(dev->ifindex), &dev->qindex);
	}

	if (dev->xsk >= 0) {
		close(dev->xsk);
	}
	XFREE(dev->umem);
	XFREE(dev->umem_alloc_buffer);
	XFREE(dev);
}

struct xdev * x_dev_create (int ifindex, int qindex, unsigned tx_qs, unsigned rx_qs, unsigned frame_size)
{
	struct xdp_umem_reg umem_reg;
	struct xdp_mmap_offsets offs;
	struct sockaddr_xdp sxdp;
	struct xdev *dev;
	unsigned sko_value;
	socklen_t sko_len;
	void *ring_map;

	if (frame_size == 0 || (rx_qs == 0 && tx_qs == 0)) {
		LOG("invalid param");
		return NULL;
	}

	if (DEV_MAP_FD(ifindex) < 0) {
		LOG("ifindex %d not attach xdp socket prog", ifindex);
		return NULL;
	}

	rx_qs = x_align32pow2(rx_qs);
	tx_qs = x_align32pow2(tx_qs);

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
	dev->n_umem_size = (tx_qs + rx_qs) * 2;
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
	dev->rx.ring = ring_map + offs.rx.desc;
	dev->rx.consumer = ring_map + offs.rx.consumer;
	dev->rx.productor = ring_map + offs.rx.producer;

	// get tx ring addr
	ring_map = mmap(NULL, offs.tx.desc+tx_qs*sizeof(struct xdp_desc), 
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, dev->xsk, XDP_PGOFF_TX_RING);
	if (ring_map == MAP_FAILED) {
		LOG("mmap tx ring err, (%s)", strerror(errno));
		goto err;
	}
	dev->tx.ring = ring_map + offs.tx.desc;
	dev->tx.consumer = ring_map + offs.tx.consumer;
	dev->tx.productor = ring_map + offs.tx.producer;

	// get cr ring addr
	ring_map = mmap(NULL, offs.cr.desc+tx_qs*sizeof(__u64),
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, dev->xsk, XDP_UMEM_PGOFF_COMPLETION_RING);
	if (ring_map == MAP_FAILED) {
		LOG("mmap cr ring err, (%s)", strerror(errno));
		goto err;
	}
	dev->cr.ring = ring_map + offs.cr.desc;
	dev->cr.consumer = ring_map + offs.cr.consumer;
	dev->cr.productor = ring_map + offs.cr.producer;

	// get fr ring addr
	ring_map = mmap(NULL, offs.fr.desc+rx_qs*sizeof(__u64), 
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, dev->xsk, XDP_UMEM_PGOFF_FILL_RING);
	if (ring_map == MAP_FAILED) {
		LOG("mmap fr ring err, (%s)", strerror(errno));
		goto err;
	}
	dev->fr.ring = ring_map + offs.fr.desc;
	dev->fr.consumer = ring_map + offs.fr.consumer;
	dev->fr.productor = ring_map + offs.fr.producer;

	sxdp.sxdp_family = AF_XDP;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = qindex;
	sxdp.sxdp_flags = 0;
	sxdp.sxdp_shared_umem_fd = 0;
	if(bind(dev->xsk, (struct sockaddr*)&sxdp, sizeof(sxdp))) {
		LOG("bind ifindex %d queue id %d err, (%s)", ifindex, qindex, strerror(errno));
		goto err;
	}

	// init fr ring
	for (int i = 0; i < dev->fr.n; ++i) {
		u64_to_addr(&dev->fr, i) = x_umem_alloc(dev);
	}
	barrier();
	*dev->fr.productor = dev->fr.n;

	if (bpf_map_update_elem(DEV_MAP_FD(ifindex), &qindex, &dev->xsk, BPF_ANY)) {
		LOG("bpf_map_update_elem err");
		goto err;
	}

	dev->bind = 1;

	return dev;

err:
	x_dev_destroy(dev);
	return NULL;
}

void x_dev_complete_tx (struct xdev *dev)
{
	struct xrings *cr = &dev->cr;
	unsigned cm, pd;

	cm = *cr->consumer;
	pd = *cr->productor;

	barrier();

	for (unsigned i = cm; i < pd; ++i) {
		x_umem_free(dev, u64_to_addr(cr, i));
	}

	barrier();
	*cr->consumer = pd;
}

int x_dev_tx_burst (struct xdev *dev, struct xbuf *pkts, unsigned npkt)
{
	struct xrings *tx = &dev->tx;
	unsigned cm, pd, n_tx;

	x_dev_complete_tx(dev);

	cm = *tx->consumer;
	pd = *tx->productor;

	barrier();

	if (pd - cm == tx->n) {
		// LOG("tx queue is full");
		sendto(dev->xsk, NULL, 0, MSG_DONTWAIT, NULL, 0);
		return 0;
	}

	n_tx = tx->n - (pd - cm);
	if (n_tx > npkt) {
		n_tx = npkt;
	}

	for (unsigned i = 0; i < n_tx; ++i) {
		ring_to_xdesc(tx, i+pd)->addr = pkts[i].addr;
		ring_to_xdesc(tx, i+pd)->len = pkts[i].len;
	}
	barrier();
	*tx->productor += n_tx;

	// Can be omitted in the new version
	sendto(dev->xsk, NULL, 0, MSG_DONTWAIT, NULL, 0);

	return n_tx;
}

void x_dev_fill_rx (struct xdev *dev)
{
	struct xrings *fr = &dev->fr;
	unsigned cm, pd, n_fill;
	__u64 addr;

	cm = *fr->consumer;
	pd = *fr->productor;

	barrier();

	if (pd - cm == fr->n) {
		return;
	}

	n_fill = fr->n - (pd - cm);

	unsigned i = 0;
	for (; i < n_fill; ++i) {
		addr = x_umem_alloc(dev);
		if (addr == INVALID_UMEM) {
			break;
		}
		u64_to_addr(fr, i+pd) = addr;
	}

	if (i > 0) {
		barrier();
		*fr->productor += i;
	}
}

int x_dev_rx_burst(struct xdev *dev, struct xbuf *pkts, unsigned npkt)
{
	struct xrings *rx = &dev->rx;
	unsigned cm, pd, n_rx;

	cm = *rx->consumer;
	pd = *rx->productor;

	barrier();

	if (pd == cm) {
		return 0;
	}

	n_rx = pd - cm;
	if (n_rx > npkt) {
		n_rx = npkt;
	}

	for(int i = 0; i < n_rx; ++i) {
		pkts[i].addr = ring_to_xdesc(rx, i+cm)->addr;
		pkts[i].len = ring_to_xdesc(rx, i+cm)->len;
	}

	barrier();
	*rx->consumer += n_rx;

	x_dev_fill_rx(dev);

	return n_rx;
}

int x_interface_attach (int n_if, int *ifindexs, const char *xdp_obj_path)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *xdp_prog = NULL;
	struct bpf_map *map;

	DEV_MAP_FD() = -1;

	obj = bpf_object__open(xdp_obj_path);
	if (!obj) {
		LOG("bpf open file %s err, (%s)", xdp_obj_path, strerror(errno));
		goto err;
	}
	xdp_prog = bpf_object__find_program_by_name(obj, DEFAULT_XDEV_PROG_NAME);
	if (!xdp_prog) {
		LOG("bpf obj find prog err, prog name %s", DEFAULT_XDEV_PROG_NAME);
		goto err;
	}
	map = bpf_object__find_map_by_name(obj, DEFAULT_XDEV_MAP_NAME);
	if (!map) {
		LOG("bpf obj map find err, need map %s", DEFAULT_XDEV_MAP_NAME);
		goto err;
	}
	if (bpf_map__type(map) != BPF_MAP_TYPE_XSKMAP) {
		LOG("bpf obj map type err , need BPF_MAP_TYPE_XSKMAP");
		goto err;
	}
	if (bpf_object__load(obj)) {
		LOG("bpf load %s err, (%s)", xdp_obj_path, strerror(errno));
		goto err;
	}

	DEV_MAP_FD() = bpf_map__fd(map);

	for (int i = 0; i < n_if; ++i) {
		bpf_xdp_attach(ifindexs[i], bpf_program__fd(xdp_prog), 0, NULL);
	}

	return 0;

err:
	if (obj) {
		bpf_object__close(obj);
	}
	return -1;
}

void x_interface_detach(int n_if, int *ifindexs)
{
	for (int i = 0; i < n_if; ++i) {
		bpf_xdp_detach(ifindexs[i], 0, NULL);
	}
}

void * x_umem_address(struct xdev *dev, __u64 addr)
{
	return dev->umem + addr;
}

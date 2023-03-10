#define _GNU_SOURCE
#define _POSIX_C_SOURCE

#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <pthread.h>
#include <errno.h>
#include "xutil.h"
#include "xdev.h"
#include "xlog.h"
#include "xpkt.h"
#include "xcfg.h"

struct xstatus {
	__u64 pkt_send;
	__u64 pkt_recv;
	__u64 pkt_tx_invalid_desc;
	__u64 pkt_rx_drop;
} status;

struct xdev_item {
	LIST_ENTRY(xdev_item) __l;
	struct xdev *dev;
	int queue_id;
	int ifindex;
};

struct xthread {
	LIST_ENTRY(xthread) __l;
	pthread_t thread;
	struct xdev_item *dev;
	__u8 queue_id;
	__u8 ifindex;
	__u8 core_id;
	__u8 dead;
	__u8 read;
	struct xstatus xs;
};

static volatile int launch_stopping;
static volatile int launch_start;
static LIST_HEAD(, xthread) xpkt_launch_queue;
static unsigned num_launcher;

static LIST_HEAD(, xdev_item) dev_list;

static struct xstatus total_status;
static struct timeval start_launch_tv, end_launch_tv;

static inline void xdp_status_print(struct xstatus *xs)
{
	fprintf(stdout, "Xpktgen ifname %s:\n", cfg.ifname);
	fprintf(stdout, "tx               : %llu\n", xs->pkt_send);
	fprintf(stdout, "rx               : %llu\n", xs->pkt_recv);
	fprintf(stdout, "rx drop          : %llu\n", xs->pkt_rx_drop);
	fprintf(stdout, "tx invalid descs : %llu\n", xs->pkt_tx_invalid_desc);
}

static inline void pkt_status_add(struct xstatus *s1, struct xstatus *s2)
{
	s1->pkt_recv += s2->pkt_recv;
	s1->pkt_rx_drop += s2->pkt_rx_drop;
	s1->pkt_send += s2->pkt_send;
	s1->pkt_tx_invalid_desc += s2->pkt_tx_invalid_desc;
}

static inline void 	xdp_time_print(__u64 sec)
{
	unsigned h, m, s;

	h = sec / 3600;
	m = sec % 3600;
	s = m % 60;
	m = m / 60;

	fprintf(stdout, "Time consuming %uh:%um:%us :\n", h, m, s);
}

static void * l4_xpkt_launch(struct xthread *xth);

static inline void * launch_routine(void* arg)
{
	return l4_xpkt_launch((struct xthread *)arg);
}

static inline void xpkt_launch_start (void)
{
	struct xthread *xth;

	LIST_FOREACH(xth, &xpkt_launch_queue, __l) {
		if (pthread_create(&xth->thread, NULL, launch_routine, xth)) {
			FAIL("pthread create err %s\n", strerror(errno));
		}
		xth->dead = 0;
	}

	launch_start = 1;
	sleep(0);

	gettimeofday(&start_launch_tv, NULL);
}

static inline int xpkt_launch_stop (void)
{
	struct xthread *xth;
	unsigned launcher = num_launcher;
	unsigned loop_count;
#define MAX_LOOP 100

	if (!launch_stopping || !launch_start) {
		return 1;
	}

	loop_count = 0;

	memset(&total_status, 0, sizeof(total_status));

	while (launcher) {
		loop_count++;
		LIST_FOREACH(xth, &xpkt_launch_queue, __l) {
			if (xth->dead) {
				continue;
			}
			if (pthread_tryjoin_np(xth->thread, NULL) == 0) {
				pkt_status_add(&total_status, &xth->xs);
				xth->dead = 1;
				launcher--;
			}
		}
		if (loop_count > MAX_LOOP) {
			LOG("The process has not exited after looping %u times, and it is forced to exit", MAX_LOOP);
			break;
		}
		sleep(0);
	}
#undef MAX_LOOP

	launch_start = 0;

	gettimeofday(&end_launch_tv, NULL);
	xdp_time_print(end_launch_tv.tv_sec - start_launch_tv.tv_sec);
	xdp_status_print(&total_status);

	return 0;
}

static inline struct xthread * xpkt_launch_add (int core_id, struct xdev_item *dev, int read)
{
	struct xthread *xth;

	xth = XALLOC(sizeof(struct xthread));
	xth->core_id = core_id;
	xth->dev = dev;
	xth->read = read;

	LIST_INSERT_HEAD(&xpkt_launch_queue, xth, __l);
	num_launcher++;

	return xth;
}

static inline void xpkt_launch_clean (void)
{
	struct xthread *xth;

	while ((xth = LIST_FIRST(&xpkt_launch_queue)) != NULL) {
		LIST_REMOVE(xth, __l);
		XFREE(xth);
	}
	num_launcher = 0;
}

static inline struct xdev_item *dev_create(int ifindex, int queue_id)
{
	struct xdev_item *dev;

	LIST_FOREACH(dev, &dev_list, __l) {
		if (dev->ifindex == ifindex && dev->queue_id == queue_id) {
			return dev;
		}
	}

	if (x_interface_attach (ifindex, DEFAULT_XDEV_XOBJ)) {
		FAIL("interface attach err ifname=%s", cfg.ifname);
	}

	dev = XALLOC(sizeof(struct xdev_item));
	dev->ifindex = ifindex;
	dev->queue_id = queue_id;

	dev->dev = x_dev_create(ifindex, queue_id,
		DEFAULT_XDEV_QUEUE_SIZE, DEFAULT_XDEV_QUEUE_SIZE, DEFAULT_XDEV_FRAME_SIZE);
	if (!dev->dev) {
		FAIL("dev create err ifindex %d - queue id %d", ifindex, queue_id);
	}

	return dev;
}

static inline void dev_destroy(int ifindex, int queue_id)
{
	struct xdev_item *dev;

	LIST_FOREACH(dev, &dev_list, __l) {
		if (dev->ifindex == ifindex && dev->queue_id == queue_id) {
			LIST_REMOVE(dev, __l);
			x_dev_destroy(dev->dev);
			x_interface_detach(dev->ifindex);
			XFREE(dev);
		}
	}
}

static inline void dev_destroy_all(void)
{
	struct xdev_item *dev;

	while ((dev = LIST_FIRST(&dev_list)) != NULL) {
		LIST_REMOVE(dev, __l);
		x_dev_destroy(dev->dev);
		x_interface_detach(dev->ifindex);
		XFREE(dev);
	}
}

static void * l4_xpkt_launch(struct xthread *xth)
{
	struct xstatus *xs;
	struct xdev_item *dev;
	struct xdev_status dev_status;
	cpu_set_t cps;
	struct L4PKT l4info;
	struct xbuf buf[MAX_PKT_SEND];
	unsigned loops;
	__u32 src;
	__u32 ip_mask;
	__u8 ntx;
	int (*l4_pkt_builder)(struct xdev *dev, struct L4PKT *tinfo, struct xbuf *buf);

	if (cfg.pkt_type == X_TCP_SYN) {
		l4_pkt_builder = x_tcp_syn_builder;
	} else {
		l4_pkt_builder = x_udp_builder;
	}

	dev = xth->dev;
	l4info.daddr = cfg.dest;
	l4info.dport = cfg.dport;
	memcpy(l4info.smac, cfg.smac, 6);
	memcpy(l4info.dmac, cfg.dmac, 6);
	l4info.data_len = cfg.data_len ? : PKT_DEFAULT_DATA_LEN;
	loops = 1;
	ip_mask = cfg.src_begin - cfg.src_end;
	src = cfg.src_begin;
	ntx = MAX_PKT_SEND;
	xs = &xth->xs;
	memset(xs, 0, sizeof(*xs));

	CPU_ZERO(&cps);
	CPU_SET(xth->core_id, &cps);
	if (pthread_setaffinity_np(xth->thread, sizeof(cps), &cps)) {
		LOG("Set cpu affinity error cpu id %hhu", xth->core_id);
	}

	while(!launch_start)
		sleep(0);

	while (1) {
begin:
		if (unlikely(launch_stopping)) {
			break;
		}

		for (int i = 0 ; i < ntx; ++i) {
			l4info.sport = loops & UINT16_MAX;
			l4info.saddr = src;

			l4_pkt_builder(dev->dev, &l4info, &buf[i]);
			if (buf[i].addr == INVALID_UMEM) {
				sleep(0);
				x_dev_complete_tx(dev->dev);
				goto begin;
			}
			if (0 == loops % UINT16_MAX && ip_mask) {
				src = (loops / UINT16_MAX) % ip_mask + cfg.src_begin;
			}
			loops++;
		}

		ntx = x_dev_tx_burst(dev->dev, buf, MAX_PKT_SEND);
	}

	x_dev_status_get(dev->dev, &dev_status);
	xs->pkt_send = loops;
	xs->pkt_rx_drop = dev_status.rx_drop;
	xs->pkt_tx_invalid_desc = dev_status.tx_invalid_descs;

	return NULL;
}

static void sig_handler (int sig)
{
	if (sig == SIGINT
		|| sig == SIGTERM
		|| sig == SIGALRM)
	{
		launch_stopping = 1;
	}
}

int main(int argc, char **argv)
{
	sigset_t sigs, emptysigs;
	struct xdev_item *dev;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGALRM, sig_handler);
	signal(SIGKILL, sig_handler);
	signal(SIGQUIT, sig_handler);

	// sigprocmask(SIG_SETMASK, NULL, &sigs);
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGKILL);
	sigaddset(&sigs, SIGQUIT);
	sigaddset(&sigs, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigs, NULL);

	cmd_parse(argc, argv);

	for (int i = 0; i < cfg.nqueue; ++i) {
		dev = dev_create(cfg.ifindex, cfg.queue_id[i]);
		xpkt_launch_add(cfg.queue_core_id[i], dev, 0);
	}

	xpkt_launch_start();
	if (cfg.time > 0) {
		alarm(cfg.time);
	}

	sigemptyset(&emptysigs);
	while (sigsuspend(&emptysigs) == -1 && xpkt_launch_stop());

	xpkt_launch_clean();
	dev_destroy_all();

	return 0;
}

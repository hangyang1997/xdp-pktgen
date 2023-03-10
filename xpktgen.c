#define _GNU_SOURCE
#define _POSIX_C_SOURCE

#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
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

struct xthread {
	pthread_t thread;
	struct xdev *dev;
	__u8 queue_id;
	__u8 ifindex;
	__u8 core_id;
	__u8 dead;
};

static volatile int xpkt_stopping;
static volatile int xpkt_start;

static inline void pkt_status_add(struct xstatus *s1, struct xstatus *s2)
{
	s1->pkt_recv += s2->pkt_recv;
	s1->pkt_rx_drop += s2->pkt_rx_drop;
	s1->pkt_send += s2->pkt_send;
	s1->pkt_tx_invalid_desc += s2->pkt_tx_invalid_desc;
}

static inline void xdp_status_print(struct xstatus *xs)
{
	fprintf(stdout, "Xpktgen ifname %s:\n", cfg.ifname);
	fprintf(stdout, "tx               : %llu\n", xs->pkt_send);
	fprintf(stdout, "rx               : %llu\n", xs->pkt_recv);
	fprintf(stdout, "rx drop          : %llu\n", xs->pkt_rx_drop);
	fprintf(stdout, "tx invalid descs : %llu\n", xs->pkt_tx_invalid_desc);
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

static void * l4_xpkt_launch(void* arg)
{
	struct xthread *xth;
	struct xstatus *xs;
	struct xdev *dev;
	struct xdev_status dev_status;
	cpu_set_t cps;
	struct L4PKT l4info;
	struct xbuf buf[64];
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

	xth = (struct xthread *)arg;
	dev = xth->dev;
	l4info.daddr = cfg.dest;
	l4info.dport = cfg.dport;
	memcpy(l4info.smac, cfg.smac, 6);
	memcpy(l4info.dmac, cfg.dmac, 6);
	l4info.data_len = cfg.data_len ? : PKT_DEFAULT_DATA_LEN;
	loops = 1;
	ip_mask = cfg.src_begin - cfg.src_end;
	src = cfg.src_begin;
	ntx = 64;

	CPU_ZERO(&cps);
	CPU_SET(xth->core_id, &cps);
	if (pthread_setaffinity_np(xth->thread, sizeof(cps), &cps)) {
		LOG("Set cpu affinity error cpu id %hhu", xth->core_id);
	}

	while(!xpkt_start)
		sleep(0);

	xs = XALLOC(sizeof(struct xstatus));

	while (1) {
begin:
		if (unlikely(xpkt_stopping)) {
			break;
		}

		for (int i = 0 ; i < ntx; ++i) {
			l4info.sport = loops & UINT16_MAX;
			l4info.saddr = src;

			l4_pkt_builder(dev, &l4info, &buf[i]);
			if (buf[i].addr == INVALID_UMEM) {
				sleep(0);
				x_dev_complete_tx(dev);
				goto begin;
			}
			if (0 == loops % UINT16_MAX) {
				src = (loops / UINT16_MAX) % ip_mask + cfg.src_begin;
			}
			loops++;
		}

		ntx = x_dev_tx_burst(dev, buf, 64);
	}

	x_dev_status_get(dev, &dev_status);
	xs->pkt_send = loops;
	xs->pkt_rx_drop = dev_status.rx_drop;
	xs->pkt_tx_invalid_desc = dev_status.tx_invalid_descs;

	x_dev_destroy(dev);
	x_interface_detach(xth->ifindex);

	return xs;
}

static void sig_handler (int sig)
{
	if (sig == SIGINT ||
		sig == SIGTERM
		|| sig == SIGALRM)
	{
		xpkt_stopping = 1;
	}
}

int main(int argc, char **argv)
{
	sigset_t sigs, emptysigs;
	struct xthread xth[MAX_QUEUEID];
	struct xthread *pxth;
	struct xstatus total_status, *th_status;
	struct timeval tv_start, tv_end;
	unsigned thread_cnt;
	int stopped;
	int nloops_when_stop;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGALRM, sig_handler);

	// sigprocmask(SIG_SETMASK, NULL, &sigs);
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigs, NULL);

	cmd_parse(argc, argv);

	if (x_interface_attach (cfg.ifindex, DEFAULT_XDEV_XOBJ)) {
		FAIL("interface attach err ifname=%s", cfg.ifname);
	}

	memset(xth, 0, sizeof(xth));
	for (int i = 0; i < cfg.nqueue; ++i) {
		pxth = &xth[i];
		pxth->dev = x_dev_create(cfg.ifindex, cfg.queue_id[i],
			DEFAULT_XDEV_QUEUE_SIZE, DEFAULT_XDEV_QUEUE_SIZE, DEFAULT_XDEV_FRAME_SIZE);
		if (!pxth->dev) {
			FAIL("dev create err ifname %s - queue id %d", cfg.ifname, cfg.queue_id[i]);
		}
		pxth->queue_id = cfg.queue_id[i];
		pxth->core_id = cfg.queue_core_id[i];
		pxth->ifindex = cfg.ifindex;
		if (pthread_create(&pxth->thread, NULL, l4_xpkt_launch, pxth)) {
			FAIL("pthread create err %s\n", strerror(errno));
		}
	}

	memset(&total_status, 0, sizeof(total_status));
	memset(&th_status, 0, sizeof(th_status));
	stopped = 0;
	nloops_when_stop = 0;
	thread_cnt = cfg.nqueue;
	th_status = NULL;

	gettimeofday(&tv_start, NULL);
	xpkt_start = 1;
	sleep(0);
	if (cfg.time > 0) {
		alarm(cfg.time);
	}

	sigemptyset(&emptysigs);
	while (!stopped && (xpkt_stopping || sigsuspend(&emptysigs) == -1)) {
		if (xpkt_stopping) {
			++nloops_when_stop;
		}
		for (int i = 0; i < cfg.nqueue; ++i) {
			if (xth[i].dead) {
				continue;
			}
			if (pthread_tryjoin_np(xth[i].thread, (void**)&th_status) == 0) {
				if (th_status) {
					pkt_status_add(&total_status, th_status);
				} else {
					LOG("thread return null status");
				}
				xth[i].dead = 1;
				thread_cnt--;
			}
			if (thread_cnt == 0) {
				stopped = 1;
				break;
			}
		}
		if (nloops_when_stop > 100) {
			LOG("loop count 100 when stop");
			stopped = 1;
		}
		sleep(0);
	}

	gettimeofday(&tv_end, NULL);
	xdp_time_print(tv_end.tv_sec - tv_start.tv_sec);
	xdp_status_print(&total_status);

	return 0;
}

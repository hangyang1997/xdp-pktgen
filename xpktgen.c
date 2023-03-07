#define _GNU_SOURCE
#define _POSIX_C_SOURCE

#include <net/if.h>
#include <argp.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include "xutil.h"
#include "xdev.h"
#include "xlog.h"
#include "xpkt.h"

#define DEFAULT_XDEV_QUEUE_SIZE 2048
#define DEFAULT_XDEV_FRAME_SIZE 2048
#define MAX_QUEUEID 64
#define DEFAULT_XDEV_XOBJ "xdev_kernel.o"

struct xstatus {
	volatile __u64 pkt_send;
	volatile __u64 pkt_recv;
	volatile __u64 pkt_tx_drop;
	volatile __u64 pkt_rx_drop;
} status;

struct xthread {
	pthread_t thread;
	struct xdev *dev;
	__u8 queue_id;
	__u8 core_id;
	__u8 dead;
};

struct config {
	unsigned src_begin;
	unsigned src_end;
	unsigned dest;
	__u16 dport;
	char *ifname;
	__u8 queue_id[MAX_QUEUEID];
	__u8 queue_core_id[MAX_QUEUEID];
	int nqueue;
	int ifindex;
	__u8 smac[6];
	__u8 dmac[6];
} cfg;


static const char *doc = "Base XDP packet gen";

static volatile int xpkt_stopping;

enum {
	OPT_SRC = 's',
	OPT_DST = 'd',
	OPT_QUEUE = 'q',
	OPT_SHORTKEY = 128,
	OPT_DPORT,
	OPT_IFNAME,
	OPT_SMAC,
	OPT_DMAC,
};

enum {
	OPT_SRC_BIT,
	OPT_DST_BIT,
	OPT_QUEUE_BIT,
	OPT_SHORTKEY_BIT,
	OPT_DPORT_BIT,
	OPT_IFNAME_BIT,
	OPT_SMAC_BIT,
	OPT_DMAC_BIT,
};

#define OPT_BIT(opt) (1 << opt ## _BIT)
#define OPT_BIT_SET(opt) arg_cache |= OPT_BIT(opt)
#define ARG_CORRECT() ((arg_required & arg_cache) == arg_required)

static __u64 arg_required = OPT_BIT(OPT_SRC)
	| OPT_BIT(OPT_DST)
	| OPT_BIT(OPT_QUEUE)
	| OPT_BIT(OPT_DPORT)
	| OPT_BIT(OPT_SMAC)
	| OPT_BIT(OPT_DMAC)
	| OPT_BIT(OPT_IFNAME);

static __u64 arg_cache;

static struct argp_option options[] = {
	{"src",  's', "IP-Range",      0,  "IP range [required] x.x.x.x-x.x.x.x" },
	{"dst",  'd', "IP", 0, "Dest address [required] x.x.x.x"},
	{"queue-id", 'q', "NUMBER:NUMBER", 0,
		"Correspondence between NIC queue and CPU Core, exp: 0:1,1:2 [required] N:N,N:N..."},
	{"dport", OPT_DPORT, "PORT", 0, "Destination port [required]"},
	{"interface", OPT_IFNAME, "IFNAME", 0, "[required]"},
	{"smac", OPT_SMAC, "MAC", 0, "Source Mac [required] x:x:x:x:x:x"},
	{"dmac", OPT_DMAC, "MAC", 0, "Dest Mac [required] x:x:x:x:x:x"},
	{ 0 }
};

static inline int parse_ip_range (uint32_t *begin, uint32_t *end, char *ip_string)
{
	char *tok;

	tok = strstr(ip_string, "-");
	if (tok) {
		*tok = '\0';
		tok++;
	} else {
		tok = ip_string;
	}
	*begin = inet_addr(ip_string);
	*end = inet_addr(tok);

	if (*begin == 0 || *end == 0) {
		return -1;
	}

	return 0;
}

static inline int parse_ip(uint32_t *ip, char *string)
{
	*ip = inet_addr(string);

	return *ip == 0;
}

static inline int parse_mac(__u8 *mac, const char *string)
{
	return 6 != sscanf (string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
}

static inline int queue_id_exist (int queue)
{
	for (int i = 0; i < cfg.nqueue; ++i) {
		if (cfg.queue_core_id[i] == queue) {
			return 1;
		}
	}
	return 0;
}

static inline void parse_queue_id (char *string)
{
	__u8 queue, core;
	__u16 max_core;
	char *endptr;

	max_core = get_nprocs_conf();
	endptr = string;

	while (*string !=0) {
		queue = strtoul(string, &endptr, 10);
		if (!endptr || *endptr != ':' || queue > MAX_QUEUEID) {
			FAIL("Error queueu id");
		}
		if (queue_id_exist(queue)) {
			FAIL("queueu id exist");
		}
		string = endptr+1;
		core = strtoul(string, &endptr, 10);
		if (!endptr || (*endptr != ',' && *endptr != 0) || core > max_core) {
			FAIL("Errror core id %hhu", core);
		}
		if (*endptr == ',') {
			endptr++;
		}
		string = endptr;
		cfg.queue_core_id[cfg.nqueue] = core;
		cfg.queue_id[cfg.nqueue] = queue;
		cfg.nqueue++;
		if (cfg.nqueue >= MAX_QUEUEID) {
			break;
		}
	}
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case OPT_SRC:
			if (parse_ip_range(&cfg.src_begin, &cfg.src_end, arg)) {
				FAIL("error ip range %s", arg);
			}
			if (cfg.src_begin > cfg.src_end) {
				SWAP32(cfg.src_begin, cfg.src_end);
			}
			OPT_BIT_SET(OPT_SRC);
			break;
		case OPT_DST:
			if (parse_ip(&cfg.dest, arg)) {
				FAIL("error ip %s", arg);
			}
			OPT_BIT_SET(OPT_DST);
			break;
		case OPT_DPORT:
			cfg.dport = atoi(arg);
			OPT_BIT_SET(OPT_DPORT);
			break;
		case OPT_QUEUE:
			parse_queue_id(arg);
			OPT_BIT_SET(OPT_QUEUE);
			break;
		case OPT_IFNAME:
			cfg.ifname = strdup(arg);
			cfg.ifindex = if_nametoindex(cfg.ifname);
			if (cfg.ifindex <= 0) {
				FAIL("err ifname=%s", cfg.ifname);
			}
			OPT_BIT_SET(OPT_IFNAME);
			break;
		case OPT_SMAC:
			OPT_BIT_SET(OPT_SMAC);
			if (parse_mac(cfg.smac, arg)) {
				FAIL("error smac address %s", arg);
			}
			break;
		case OPT_DMAC:
			OPT_BIT_SET(OPT_DMAC);
			if (parse_mac(cfg.dmac, arg)) {
				FAIL("error dmac address %s", arg);
			}
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void cmd_parse(int argc, char **argv)
{
	struct argp argp = { options, parse_opt, NULL, doc};

	if (argp_parse(&argp, argc, argv, 0, 0, NULL)) {
		FAIL("arg err");
	}

	if (!ARG_CORRECT()) {
		FAIL("fault args");
	}
}

static inline void xdp_status_print(struct xdev *dev)
{
	struct xdev_status status;

	x_dev_status_get(dev, &status);

	fprintf(stdout, "tx invalid descs %llu\n", status.tx_invalid_descs);
}

static void * xpkt_launch(void* arg)
{
	struct xthread *xth;
	struct xdev *dev;
	cpu_set_t cps;
	struct xudp udp;
	struct xbuf buf;
	unsigned loops;
	__u32 src;
	__u32 ip_mask;

	xth = (struct xthread *)arg;
	dev = xth->dev;
	udp.daddr = cfg.dest;
	udp.dport = cfg.dport;
	memcpy(udp.smac, cfg.smac, 6);
	memcpy(udp.dmac, cfg.dmac, 6);
	udp.data_len = 10;
	loops = 1;
	ip_mask = cfg.src_begin - cfg.src_end;
	src = cfg.src_begin;

	CPU_ZERO(&cps);
	CPU_SET(xth->core_id, &cps);
	if (pthread_setaffinity_np(xth->thread, sizeof(cps), &cps)) {
		LOG("Set cpu affinity error cpu id %hhu", xth->core_id);
	}

	while (1) {
		if (unlikely(xpkt_stopping)) {
			break;
		}

		udp.sport = htons(loops & UINT16_MAX);
		udp.saddr = src;

		x_udp_builder(dev, &udp, &buf);
		if (buf.addr == INVALID_UMEM) {
			sleep(0);
			x_dev_complete_tx(dev);
			continue;
		}

		if (1 != x_dev_tx_burst(dev, &buf, 1)) {
			x_umem_free(dev, buf.addr);
			continue;
		}

		if (0 == loops % UINT16_MAX) {
			src = (loops / UINT16_MAX) % ip_mask + cfg.src_begin;
		}

		loops++;
	}

	return NULL;
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

	if (x_interface_attach (1, &cfg.ifindex, DEFAULT_XDEV_XOBJ)) {
		FAIL("interface attach err ifname=%s", cfg.ifname);
	}

	for (int i = 0; i < cfg.nqueue; ++i) {
		pxth = &xth[i];
		pxth->dev = x_dev_create(cfg.ifindex, cfg.queue_id[i],
			DEFAULT_XDEV_QUEUE_SIZE, DEFAULT_XDEV_QUEUE_SIZE, DEFAULT_XDEV_FRAME_SIZE);
		if (!pxth->dev) {
			FAIL("dev create err ifname %s - queue id %d", cfg.ifname, cfg.queue_id[i]);
		}
		pxth->queue_id = cfg.queue_id[i];
		pxth->core_id = cfg.queue_core_id[i];
		if (pthread_create(&pxth->thread, NULL, xpkt_launch, pxth)) {
			FAIL("pthread create err %s\n", strerror(errno));
		}
	}

	stopped = 0;
	nloops_when_stop = 0;
	thread_cnt = cfg.nqueue;
	sigemptyset(&emptysigs);
	while (!stopped && (xpkt_stopping || sigsuspend(&emptysigs) == -1)) {
		if (xpkt_stopping) {
			++nloops_when_stop;
		}
		for (int i = 0; i < cfg.nqueue; ++i) {
			if (xth[i].dead) {
				continue;
			}
			if (pthread_tryjoin_np(xth[i].thread, NULL) == 0) {
				xth[i].dead = 1;
				thread_cnt--;
			}
			if (thread_cnt == 0) {
				stopped = 1;
				break;
			}
		}
		if (nloops_when_stop > 10) {
			FAIL("loop count 10 when stop");
			stopped = 1;
		}
		sleep(0);
	}

	return 0;
}

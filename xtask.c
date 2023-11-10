#define _GNU_SOURCE
#define _POSIX_C_SOURCE

#include <sys/time.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <termios.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "xlog.h"
#include "xdev.h"
#include "xutil.h"
#include "xtask.h"
#include "xpkt.h"
#include "xconfig.h"

#define CLOSE_ECHO() \
	struct termios old_termios, new_termios; \
	tcgetattr(STDIN_FILENO, &old_termios);   \
	new_termios = old_termios;               \
	new_termios.c_lflag &= ~(ECHO);          \
	tcsetattr(STDIN_FILENO, TCSANOW, &new_termios)

#define OPEN_ECHO() \
	tcsetattr(STDIN_FILENO, TCSANOW, &old_termios)

static LIST_HEAD(, xtask) task_list;

struct task_thread_ctx {
	LIST_ENTRY(task_thread_ctx) __l;
	struct xtask *task;
	struct xdev *dev;
	pthread_t thread;
	struct timeval tv;
	volatile __u64	pkts_counter;
};
static LIST_HEAD(, task_thread_ctx) task_launch_queue;
static volatile int launch_stop;
static pthread_t print_thread;

static void launching_sig_handler (int sig)
{
	if (sig == SIGINT
		|| sig == SIGTERM
		|| sig == SIGALRM)
	{
		launch_stop = 1;
		return;
	}

	LOG("program exit with signal %d", sig);
	exit(0);
}

struct xtask * xtask_lookup(const char *ifname, int queue_id)
{
	struct xtask *task;

	LIST_FOREACH(task, &task_list, __l) {
		if (task->queue_id == queue_id && !strcmp(task->ifname, ifname)) {
			return task;
		}
	}

	return NULL;
}

struct xtask * xtask_get (const char *ifname, int queue_id)
{
	struct xtask *task;
	int ifindex;

	task = xtask_lookup(ifname, queue_id);
	if (task) {
		return task;
	}

	ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		LOG("error ifname %s", ifname);
		return NULL;
	}


	task = XALLOC(sizeof(struct xtask));
	task->sport_begin = htons(1);
	task->sport_end = 65535;
	task->ifname = XSTRDUP(ifname);
	task->queue_id = queue_id;
	task->ifindex = ifindex;

	LIST_INSERT_HEAD(&task_list, task, __l);

	return task;
}

void xtask_remove (struct xtask *task)
{
	if (!task) {
		return;
	}
	LIST_REMOVE(task, __l);
	XFREE(task->ifname);
	XFREE(task);
}

void xtask_cleanup(void)
{
	struct xtask *task;

	while((task=LIST_FIRST(&task_list))) {
		xtask_remove(task);
	}
}

static void make_launch_queue (void)
{
	struct task_thread_ctx *ctx;
	struct xtask *task;
	struct xdev *dev;

	LIST_FOREACH (task, &task_list, __l) {
		if (!TASK_IS_READY(task)) {
			LOG("task %s-%d is not ready - ignoring", task->ifname, task->queue_id);
			continue;
		}
		if (x_interface_attach (task->ifindex, DEFAULT_XDEV_XOBJ)) {
			LOG("set xdp obj for ifname=%s error - ignore", task->ifname);
			continue;
		}

		dev = x_dev_create(task->ifindex, task->queue_id,
			DEFAULT_XDEV_QUEUE_SIZE, DEFAULT_XDEV_QUEUE_SIZE, DEFAULT_XDEV_FRAME_SIZE);
		if (dev == NULL) {
			LOG("create dev ifname=%s queue id =%d - ignore", task->ifname, task->queue_id);
			continue;
		}
		ctx = XALLOC(sizeof(struct task_thread_ctx));
		ctx->dev = dev;
		ctx->task = task;
		LIST_INSERT_HEAD(&task_launch_queue, ctx, __l);
	}
}

static inline void launch_ctx_clean(struct task_thread_ctx *ctx)
{
	x_dev_destroy(ctx->dev);
	x_interface_detach(ctx->task->ifindex);
	XFREE(ctx);
}

static int launch_stop_and_recycle(void)
{
	struct task_thread_ctx *ctx;

	while ((ctx = LIST_FIRST(&task_launch_queue))) {
		if (pthread_tryjoin_np(ctx->thread, NULL) == 0) {
			LIST_REMOVE(ctx, __l);
			launch_ctx_clean(ctx);
		}
	}

	return !LIST_EMPTY(&task_launch_queue);
}

static void * l4_xpkt_launch(struct task_thread_ctx *ctx)
{
	struct xtask *task = ctx->task;
	struct xdev *dev = ctx->dev;
	cpu_set_t cps;
	struct L4PKT l4info;
	struct xbuf buf[MAX_PKT_SEND];
	unsigned loops;
	__u32 src;
	__u32 ip_mask;
	__u8 ntx;
	int (*l4_pkt_builder)(struct xdev *dev, struct L4PKT *tinfo, struct xbuf *buf);

	if (task->pkt_type == PTT_TCP_SYN) {
		l4_pkt_builder = x_tcp_syn_builder;
	} else {
		l4_pkt_builder = x_udp_builder;
	}

	l4info.daddr = task->dest;
	l4info.dport = ntohs(task->dport);
	memcpy(l4info.smac, task->smac, 6);
	memcpy(l4info.dmac, task->dmac, 6);
	l4info.data_len = task->data_len ? : PKT_DEFAULT_DATA_LEN;
	loops = 1;
	ip_mask = task->src_begin - task->src_end;
	src = task->src_begin;
	ntx = MAX_PKT_SEND;

	CPU_ZERO(&cps);
	CPU_SET(task->core_id, &cps);
	if (pthread_setaffinity_np(ctx->thread, sizeof(cps), &cps)) {
		LOG("Set cpu affinity error cpu id %hhu", task->core_id);
	}

	while (!launch_stop) {
begin:
		for (int i = 0 ; i < ntx; ++i) {
			l4info.sport = loops & UINT16_MAX;
			l4info.saddr = src;

			l4_pkt_builder(dev, &l4info, &buf[i]);
			if (buf[i].addr == INVALID_UMEM) {
				sleep(0);
				x_dev_complete_tx(dev);
				goto begin;
			}
			if (0 == loops % UINT16_MAX && ip_mask) {
				src = (loops / UINT16_MAX) % ip_mask + task->src_begin;
			}
			loops++;
		}

		ntx = x_dev_tx_burst(dev, buf, MAX_PKT_SEND);

		ctx->pkts_counter += ntx;
	}

	// x_dev_status_get(dev->dev, &dev_status);
	// xs->pkt_send = loops;
	// xs->pkt_rx_drop = dev_status.rx_drop;
	// xs->pkt_tx_invalid_desc = dev_status.tx_invalid_descs;

	return NULL;
}

#define launch_signal_set(handler) \
	signal(SIGINT,  handler); \
	signal(SIGTERM, handler); \
	signal(SIGALRM, handler); \
	signal(SIGKILL, handler); \
	signal(SIGQUIT, handler); \
	signal(SIGQUIT, handler)

static void * print_launching_status_thread (__attribute__((unused)) void *arg)
{
	struct task_thread_ctx *ctx;
	struct xtask *task;
	struct timeval tv;

	while (!launch_stop) {
		sleep(1);
		LIST_FOREACH(ctx, &task_launch_queue, __l) {
			task = ctx->task;
			gettimeofday(&tv, NULL);
			fprintf(stdout, "TASK[%s-%d]	%s %10llu pkts", task->ifname, task->queue_id,
				task->read?"recv":"send", ctx->pkts_counter);
			fprintf(stdout, "	using %5lu seconds\n", tv.tv_sec - ctx->tv.tv_sec);
		}
	}

	return NULL;
}

static void create_print_status_thread(void)
{
	// pthread_attr_t attr;

	// while (pthread_kill(print_thread, 0) == 0) {
	// 	pthread_cancel(pti)
	// }

	// pthread_attr_init(&attr);
	// pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&print_thread, NULL, print_launching_status_thread, NULL)) {
		FAIL("create print thread error %s", strerror(errno));
	}
}

static void recycle_print_status_thread(void)
{
	int cycle_cnt = 0;

	while (pthread_tryjoin_np(print_thread, NULL)) {
		if (cycle_cnt++ > 16) {
			// LOG ("print thread recycle failed, try 16 counts");
			// print thread in sleep status, we can cancel it
			pthread_cancel(print_thread);
			break;
		}
		sleep(0);
	}
}

static void start_launch (int time)
{
	struct task_thread_ctx *ctx;
	sigset_t empty_sigs, sigs, old_sigs;

	launch_signal_set (launching_sig_handler);

	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGKILL);
	sigaddset(&sigs, SIGQUIT);
	sigaddset(&sigs, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigs, &old_sigs);

	CLOSE_ECHO();

	launch_stop = 0;
	LIST_FOREACH(ctx, &task_launch_queue, __l) {
		if (pthread_create(&ctx->thread, NULL, (void*)l4_xpkt_launch, ctx)) {
			FAIL("pthread create err %s\n", strerror(errno));
		}
		gettimeofday(&ctx->tv, NULL);
	}

	sleep(0);

	if (time) {
		alarm(time+1);
	}

	create_print_status_thread();

	sigemptyset(&empty_sigs);
	while ((launch_stop || sigsuspend(&empty_sigs) == -1) && launch_stop_and_recycle())
		sleep(0);

	recycle_print_status_thread();

	OPEN_ECHO();

	if (time) {
		alarm(0);
	}

	launch_signal_set(SIG_DFL);
	sigprocmask(SIG_SETMASK, &old_sigs, NULL);
}

void xtask_start (int time)
{
	if (LIST_EMPTY(&task_list)) {
		return;
	}

	make_launch_queue();

	if (LIST_EMPTY(&task_launch_queue)) {
		return;
	}

	start_launch (time);
}

// list API
#define P1(X, ...) fprintf(stdout, "\033[34m"X"\033[0m", ##__VA_ARGS__)
#define P2(X, ...) fprintf(stdout, "    \033[33m"X"\033[0m", ##__VA_ARGS__)
#define P3(X, ...) fprintf(stdout, "        "X, ##__VA_ARGS__)
#define LN fprintf(stdout, "\n")

static const char *pkt_type_string(struct xtask *task)
{
	switch(task->pkt_type) {
		case PTT_UDP:
			return "udp";
		case PTT_TCP_SYN:
			return "tcp-syn";
		default:
			return "unknown";
	}

	return "";
}

void xtask_list (struct xtask *task)
{
	__u16 x1, x2;

	P1("TASK[%s-%d]", task->ifname, task->queue_id);
	P1("\tcore%d", task->core_id);
	P1("\t%s", TASK_IS_READY(task) ? "ready":"");
	LN;
	P2("smac         "MAC_FMT, MAC(task->smac));
	LN;
	P2("dmac         "MAC_FMT, MAC(task->dmac));
	LN;
	P2("source       "IP_FMT"-"IP_FMT, IP(task->src_begin), IP(task->src_end));
	LN;
	x1 = ntohs(task->sport_begin);
	x2 = ntohs(task->sport_end);
if (x1 > x2) {
	P2("sport        %hu-%hu", x2, x1);
} else {
	P2("sport        %hu-%hu", x1, x2);
}
	LN;
	P2("destination  "IP_FMT, IP(task->dest));
	LN;
	P2("dport        %hu", htons(task->dport));
	LN;
	P2("pkt_type     %s", pkt_type_string(task));
	LN;
}

void xtask_list_outline(void)
{
	struct xtask *task;

	LIST_FOREACH(task, &task_list, __l) {
		P1("TASK[%s-%d]", task->ifname, task->queue_id);
		P1("\tcore%d", task->core_id);
		LN;
	}
}

#undef P1
#undef P2
#undef P3
#undef LN

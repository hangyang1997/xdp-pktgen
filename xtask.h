#ifndef __XTASK_H
#define __XTASK_H

#include <sys/queue.h>
#include <linux/types.h>
#include <stddef.h>

extern struct xtask *current_task;

typedef enum {
	PTT_UDP,
	PTT_TCP_SYN,
} pkt_type_t;

enum {
	TASK_F_SRC,
	TASK_F_DST,
	TASK_F_DPORT,
	TASK_F_SPORT,
	TASK_F_SMAC,
	TASK_F_DMAC,
	TASK_F_TIME,
	TASK_F_DATA_LEN,
	TASK_F_PKT_TYPE,
	TASK_F_CORE,
};

#define TASK_F_REQUIRE (TASK_F_SRC|TASK_F_DST|TASK_F_DPORT|TASK_F_SMAC|TASK_F_DMAC)
#define TASK_SET(task, flag) (task)->set_flag |= flag
#define TASK_IS_READY(task) (((task)->set_flag & TASK_F_REQUIRE) == TASK_F_REQUIRE)

struct xtask {
	LIST_ENTRY(xtask) __l;

	__u64 set_flag;

	__u32 src_begin;
	__u32 src_end;
	__u32 dest;
	__u32 time;

	__u16 sport_begin;
	__u16 sport_end;
	__u16 dport;
	__u16 data_len;
	__u8 core_id;
	__u8 read;
	__u8 smac[6];
	__u8 dmac[6];
	pkt_type_t pkt_type;

// key
	int queue_id;
	int ifindex;
	char *ifname;
};

extern struct xtask * xtask_get (const char *ifname, int queue_id);

extern void xtask_remove (struct xtask *task);

extern struct xtask * xtask_lookup (const char *ifname, int queue_id);

extern void xtask_cleanup(void);
extern void xtask_list (struct xtask *task);
extern void xtask_list_outline(void);

extern void xtask_start (int time);

extern void xtask_save(const char *filename);

#endif

#include <net/if.h>
#include <argp.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include "xutil.h"
#include "xdev.h"
#include "xlog.h"
#include "xpkt.h"

struct config {
	unsigned src_begin;
	unsigned src_end;
	unsigned dest;
	uint16_t dport;
	uint64_t lcore_mask;
	char *ifname;
	int queue_id;
} cfg;

static const char *doc = "Base XDP packet gen";

enum {
	OPT_SRC = 's',
	OPT_DST = 'd',
	OPT_QUEUE = 'q',
	OPT_SHORTKEY = 128,
	OPT_DPORT,
	OPT_IFNAME,
};

enum {
	OPT_SRC_BIT,
	OPT_DST_BIT,
	OPT_QUEUE_BIT,
	OPT_SHORTKEY_BIT,
	OPT_DPORT_BIT,
	OPT_IFNAME_BIT,
};

#define OPT_BIT(opt) (1 << opt ## _BIT)
#define OPT_BIT_SET(opt) arg_cache |= OPT_BIT(opt)
#define ARG_CORRECT() ((arg_required & arg_cache) == arg_required)

static __u64 arg_required = OPT_BIT(OPT_SRC)
	| OPT_BIT(OPT_DST)
	| OPT_BIT(OPT_QUEUE)
	| OPT_BIT(OPT_DPORT)
	| OPT_BIT(OPT_IFNAME);

static __u64 arg_cache;

static struct argp_option options[] = {
	{"src",  's', "IP-Range",      0,  "IP range x.x.x.x-x.x.x.x" },
	{"dst",  'd', "IP", 0, "Dest address x.x.x.x"},
	{"queue-id", 'q', "NUMBER", 0, NULL},
	{"dport", OPT_DPORT, "PORT", 0, "Destination port"},
	{"interface", OPT_IFNAME, "IFNAME", 0, NULL},
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

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch (key) {
		case OPT_SRC:
			if (parse_ip_range(&cfg.src_begin, &cfg.src_end, arg)) {
				FAIL("error ip range %s", arg);
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
			cfg.queue_id = atoi(arg);
			break;
		case OPT_IFNAME:
			cfg.ifname = strdup(arg);
			OPT_BIT_SET(OPT_IFNAME);
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

int main(int argc, char **argv)
{

	cmd_parse(argc, argv);

	return 0;
}

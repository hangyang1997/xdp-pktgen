#ifndef __XCFG_H
#define __XCFG_H

#include <linux/types.h>

#define DEV_INDEX_MAX 64
#define MAX_QUEUEID 64

#define DEV_MAX_QUEUE_SIZE 4096
#define DEV_MAX_FRAME_SIZE 8192

#define DEFAULT_XDEV_QUEUE_SIZE 2048
#define DEFAULT_XDEV_FRAME_SIZE 2048

#define PKT_MAX_DATA_LEN 1400
#define PKT_MIN_DATA_LEN 16
#define PKT_DEFAULT_DATA_LEN 64

#define MAX_PKT_SEND 64

#define DEFAULT_XDEV_XOBJ "xdev_kernel.o"

#define DEFAULT_XTASK_CONFIG_SAVE_FILE "tmp.xt"

#endif

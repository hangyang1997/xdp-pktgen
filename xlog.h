#ifndef __XDEV_LOG_H
#define __XDEV_LOG_H

#include <stdio.h>

#define LOG(fmt, ...) do {				 \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	fprintf(stderr, "\n");				 \
} while(0)

#endif

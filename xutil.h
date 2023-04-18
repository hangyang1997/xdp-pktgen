#ifndef __XDEV_UTIL_H
#define __XDEV_UTIL_H

#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include "xlog.h"

#define CONST_PTR_TO_PTR(cptr) ({ 	\
	union {							\
		const void *__cptr; 		\
		void *__ptr;				\
	} v;							\
	v.__cptr = cptr;				\
	(void*)v.__ptr;					\
})

#define XMALLOC(size) ({								\
	void *buffer;										\
	buffer = malloc(size);								\
	if (buffer == NULL) {								\
		LOG("out of memory size=%u", (unsigned)(size)); \
		exit(-1);										\
	}													\
	(void*)buffer;										\
})

#define XALLOC(size) ({									\
	void *buffer;										\
	buffer = calloc(1, size);							\
	if (buffer == NULL) {								\
		LOG("out of memory size=%u", (unsigned)(size)); \
		exit(-1);										\
	}													\
	(void*)buffer;										\
})

#define XSTRDUP(text) ({								\
	void *buffer;										\
	buffer = strdup(text);								\
	if (buffer == NULL) {								\
		LOG("out of memory");							\
		exit(-1);										\
	}													\
	(char*)buffer;										\
})


#define XFREE(ptr) do { \
	if (ptr) {			\
		free(ptr);		\
	}					\
} while(0)

#define XFREE_PTR(ptr) do { \
	if (ptr) {				\
		free(ptr);			\
		ptr = NULL;			\
	}						\
} while (0)

#define XFREE_CONST(cptr) do {			\
	void *ptr = CONST_PTR_TO_PTR(cptr);	\
	XFREE(ptr);							\
} while(0)

#define XFREE_CONST_PTR(cptr) do {		\
	void *ptr = CONST_PTR_TO_PTR(cptr); \
	XFREE(ptr);						\
	cptr = NULL;					\
} while(0)

#define FAIL(msg...) do {	\
	LOG(msg);				\
	exit(-1);				\
} while(0)

static inline __u32
x_align32pow2(__u32 x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	return x + 1;
}

#define barrier()	asm volatile("" ::: "memory")

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#ifndef likelymakm
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#define IP_FMT "%hhu.%hhu.%hhu.%hhu"
#define IP(X) ((__u8*)&(X))[0], ((__u8*)&(X))[1], ((__u8*)&(X))[2], ((__u8*)&(X))[3]

#define MAC_FMT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define MAC(X) ((__u8*)X)[0], ((__u8*)X)[1], ((__u8*)X)[2], ((__u8*)X)[3], ((__u8*)X)[4], ((__u8*)X)[5]

#define __SWAP_N(X, Y) do {		\
	X = (X) ^ (Y);				\
	Y = (X) ^ (Y);				\
	X = (X) ^ (Y);				\
} while(0)

#define SWAP8(X, Y) __SWAP_N(X, Y)
#define SWAP16(X, Y) __SWAP_N(X, Y)
#define SWAP32(X, Y) __SWAP_N(X, Y)
#define SWAP_PTR(X, Y) __SWAP_N((uintptr_t)(X), (uintptr_t)(Y))

#endif

#ifndef __XDEV_UTIL_H
#define __XDEV_UTIL_H

#include <malloc.h>
#include <stdlib.h>
#include "xlog.h"

#define CONST_PTR_TO_PTR(cptr) ({ \
	union { \
		const void *__cptr; \
		void *__ptr; \
	} v; \
	v.__cptr = cptr; \
	(void*)v.__ptr; \
})

#define XMALLOC(size) ({ \
	void *buffer; \
	buffer = malloc(size); \
	if (buffer == NULL) { \
		LOG("out of memory size=%u", (unsigned)(size)); \
		exit(-1); \
	} \
	(void*)buffer; \
})

#define XALLOC(size) ({ \
	void *buffer; \
	buffer = calloc(1, size); \
	if (buffer == NULL) { \
		LOG("out of memory size=%u", (unsigned)(size)); \
		exit(-1); \
	} \
	(void*)buffer; \
})

#define XFREE(ptr) do { \
	if (ptr) { \
		free(ptr); \
	} \
} while(0)

#define XFREE_PTR(ptr) do { \
	if (ptr) { \
		free(ptr); \
		ptr = NULL; \
	} \
} while (0)

#define XFREE_CONST(cptr) do { \
	void *ptr = CONST_PTR_TO_PTR(cptr); \
	XFREE(ptr); \
} while(0)

#define XFREE_CONST_PTR(cptr) do { \
	void *ptr = CONST_PTR_TO_PTR(cptr); \
	XFREE_PTR(ptr); \
} while(0)

#endif

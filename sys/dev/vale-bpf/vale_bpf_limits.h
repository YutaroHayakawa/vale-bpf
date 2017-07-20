#ifndef _VALE_BPF_LIMITS_H_
#define _VALE_BPF_LIMITS_H_

#if defined(linux)
#include <linux/types.h>

#define UINT32_MAX ((uint32_t)-1)
#define UINT64_MAX ((uint64_t)-1)

#define INT32_MIN (-2147483647 - 1)
#define INT32_MAX (2147483647)

#elif defined(__FreeBSD__)
#include <sys/types.h>
#else
#error Unsupported platform
#endif
#endif

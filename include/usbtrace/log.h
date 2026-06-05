/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __USBTRACE_LOG_H
#define __USBTRACE_LOG_H

#include <stdio.h>

extern int usbtrace_verbose;

#define ut_err(fmt, ...)  fprintf(stderr, "[usbtrace] ERROR: " fmt "\n", ##__VA_ARGS__)
#define ut_warn(fmt, ...) fprintf(stderr, "[usbtrace] WARN: " fmt "\n", ##__VA_ARGS__)
#define ut_info(fmt, ...) fprintf(stderr, "[usbtrace] " fmt "\n", ##__VA_ARGS__)
#define ut_dbg(fmt, ...)                                                       \
	do {                                                                  \
		if (usbtrace_verbose)                                         \
			fprintf(stderr, "[usbtrace] DEBUG: " fmt "\n",        \
				##__VA_ARGS__);                               \
	} while (0)

#endif /* __USBTRACE_LOG_H */

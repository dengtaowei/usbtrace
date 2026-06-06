// SPDX-License-Identifier: GPL-2.0
/*
 * Shared user-space helpers for usbtrace modules. See include/usbtrace/cli.h.
 *
 * This file is auto-discovered by the build (find src -name '*.c') and linked
 * into the binary; it is not a module and registers nothing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "usbtrace/cli.h"
#include "usbtrace/log.h"

int usbtrace_filter_getopt(int optchar, const char *arg,
			   struct usbtrace_filter *f)
{
	switch (optchar) {
	case USBTRACE_OPT_VID:
		f->vid = (unsigned int)strtoul(arg, NULL, 0);
		return 1;
	case USBTRACE_OPT_PID:
		f->pid = (unsigned int)strtoul(arg, NULL, 0);
		return 1;
	default:
		return 0;
	}
}

int usbtrace_filter_parse(int argc, char **argv, struct usbtrace_filter *f)
{
	static const struct option lo[] = {
		USBTRACE_FILTER_LONGOPTS,
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};
	int c;

	optind = 1; /* argv[0] is the module name; scan from there */
	while ((c = getopt_long(argc, argv, "h", lo, NULL)) != -1) {
		if (usbtrace_filter_getopt(c, optarg, f))
			continue;
		switch (c) {
		case 'h':
			return 1; /* request help */
		default:
			return -1;
		}
	}
	return 0;
}

const char *usbtrace_speed_str(unsigned char speed)
{
	switch (speed) {
	case 1: return "low";
	case 2: return "full";
	case 3: return "high";
	case 4: return "wireless";
	case 5: return "super";
	case 6: return "super+";
	default: return "?";
	}
}

int usbtrace_libbpf_print(enum libbpf_print_level lvl, const char *fmt,
			  va_list args)
{
	if (lvl == LIBBPF_DEBUG && !usbtrace_verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

const char *usbtrace_json_escape(const char *src, char *dst, size_t dstsz)
{
	size_t o = 0;

	if (dstsz == 0)
		return dst;

	for (; *src && o + 2 < dstsz; src++) {
		unsigned char c = (unsigned char)*src;

		switch (c) {
		case '"':
		case '\\':
			dst[o++] = '\\';
			dst[o++] = c;
			break;
		case '\n':
			dst[o++] = '\\';
			dst[o++] = 'n';
			break;
		case '\t':
			dst[o++] = '\\';
			dst[o++] = 't';
			break;
		case '\r':
			dst[o++] = '\\';
			dst[o++] = 'r';
			break;
		default:
			if (c < 0x20) {
				/* \uXXXX needs 6 bytes plus the NUL. */
				if (o + 6 >= dstsz)
					goto done;
				o += snprintf(dst + o, dstsz - o, "\\u%04x", c);
			} else {
				dst[o++] = c;
			}
			break;
		}
	}
done:
	dst[o] = '\0';
	return dst;
}

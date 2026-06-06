/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared user-space helpers for usbtrace modules: common --vid/--pid filtering,
 * output-mode flag (--json), libbpf log routing, and small formatters. Keeping
 * these in one place avoids each module re-implementing identical boilerplate.
 *
 * BPF-side filtering lives in <usbtrace/filter.bpf.h>.
 */
#ifndef __USBTRACE_CLI_H
#define __USBTRACE_CLI_H

#include <stdarg.h>
#include <stddef.h>

#include <bpf/libbpf.h>

/* Output mode. Set by the global --json option (defined in main.c). When non-
 * zero, modules emit one JSON object per line instead of aligned text. */
extern int usbtrace_json;

/* Common per-device filter shared by tracing modules (0 = match any). */
struct usbtrace_filter {
	unsigned int vid;
	unsigned int pid;
};

/* Option codes + getopt_long() entries for the shared --vid/--pid options.
 * A module folds USBTRACE_FILTER_LONGOPTS into its own option array and routes
 * each parsed option through usbtrace_filter_getopt(). */
#define USBTRACE_OPT_VID 0x1001
#define USBTRACE_OPT_PID 0x1002

#define USBTRACE_FILTER_LONGOPTS                                               \
	{ "vid", required_argument, 0, USBTRACE_OPT_VID },                     \
	{ "pid", required_argument, 0, USBTRACE_OPT_PID }

/* If optchar is one of the shared filter options, parse arg into f and return
 * 1 (consumed); otherwise return 0 so the caller handles its own options. */
int usbtrace_filter_getopt(int optchar, const char *arg,
			   struct usbtrace_filter *f);

/* Vanilla parser for modules whose only options are --vid/--pid/--help (most of
 * them). Returns 0 ok, <0 on error, >0 to request help. Modules with extra
 * options use USBTRACE_FILTER_LONGOPTS + usbtrace_filter_getopt() directly. */
int usbtrace_filter_parse(int argc, char **argv, struct usbtrace_filter *f);

/* Human-readable USB speed (enum usb_device_speed value). */
const char *usbtrace_speed_str(unsigned char speed);

/* Shared libbpf log callback; suppresses DEBUG unless usbtrace_verbose. */
int usbtrace_libbpf_print(enum libbpf_print_level lvl, const char *fmt,
			  va_list args);

/* Escape src into dst as a JSON string body (no surrounding quotes). dst is
 * always NUL-terminated; returns dst for convenient inline use in printf. */
const char *usbtrace_json_escape(const char *src, char *dst, size_t dstsz);

#endif /* __USBTRACE_CLI_H */

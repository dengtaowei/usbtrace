/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared event consumer for class-traffic modules (uvc/uac/hid/storage).
 *
 * The load/attach/poll lifecycle is the generic usbtrace_run() harness; this
 * header adds only the class-specific bits layered on top: argument parsing,
 * event printing (text + JSON), a health tally and the exit summary. So a class
 * module's .c is just open skeleton → usbtrace_run() with these callbacks.
 */
#ifndef __USBTRACE_CLASS_STREAM_H
#define __USBTRACE_CLASS_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>	/* __u8/__u16/... used by usbtrace/class.h */

#include "usbtrace/class.h"
#include "usbtrace/cli.h"

/* Running stream-health tally, printed at exit. */
struct class_stats {
	unsigned long urbs;	   /* class URBs seen */
	unsigned long isoc_err;	   /* URBs with error_count > 0 */
	unsigned long status_err;  /* URBs with status != 0 */
	unsigned long long bytes;  /* total actual_length */
};

/* ring_buffer__new() ctx: pass &this. Set .all from --all before polling. */
struct class_stream_ctx {
	bool all;		   /* print every URB (default: anomalies only) */
	struct class_stats stats;
};

/* enum usbtrace_class -> short name ("video"/"audio"/"hid"/"storage"). */
const char *usbtrace_class_str(unsigned char klass);

/* Shared --vid/--pid/--all/-h parser. Returns 0 ok, <0 error, >0 help. */
int class_stream_parse_args(int argc, char **argv, struct usbtrace_filter *filt,
			    bool *all);

/* ring_buffer__new() callback. ctx must be a struct class_stream_ctx *. */
int class_stream_on_event(void *ctx, void *data, size_t len);

/* Print the end-of-session summary (honors --json). */
void class_stream_summary(const char *modname, const struct class_stats *st);

#endif /* __USBTRACE_CLASS_STREAM_H */

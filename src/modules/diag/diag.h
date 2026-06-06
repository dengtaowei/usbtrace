/* SPDX-License-Identifier: GPL-2.0 */
/*
 * diag module: normalized cross-module event view.
 *
 * The diag rule engine consumes events from several tracing modules
 * (urb/enum/lifecycle/power) at once. Each module has its own record layout,
 * so diag flattens them into a single kind-agnostic struct diag_event that the
 * engine and the YAML rules reference by field name. This decouples the rule
 * DSL from the raw per-module struct layouts.
 */
#ifndef __USBTRACE_MOD_DIAG_H
#define __USBTRACE_MOD_DIAG_H

#include <stdint.h>
#include <linux/types.h>	/* __u32/__u64 used by usbtrace/common.h */

#include "usbtrace/common.h"

/* Normalized, user-space-only view of any module event. */
struct diag_event {
	uint32_t kind;	  /* enum usbtrace_event_kind */
	uint64_t ts_ns;	  /* bpf_ktime_get_ns() at emit (CLOCK_MONOTONIC) */

	/* device identity (the correlation key) */
	uint16_t vid;
	uint16_t pid;
	uint16_t busnum;
	uint16_t devnum;
	uint8_t speed;
	uint8_t portnum;

	/* urb/class-specific */
	int32_t status;
	uint32_t latency_ns;
	uint32_t actual;
	uint32_t length;
	int32_t error_count;	/* class isoc packet errors (urb->error_count) */
	uint8_t xfer_type;
	uint8_t dir_in;
	uint8_t ep;
	uint8_t is_submit;

	/* class-specific */
	uint8_t cls;		/* enum usbtrace_class (when kind == CLASS) */

	/* enum-specific */
	uint8_t old_state;
	uint8_t new_state;

	/* power/lifecycle action */
	uint8_t action;

	char comm[USBTRACE_COMM_LEN];
	char devpath[16];
};

/*
 * Device correlation key. Only (bus,dev) is stable across modules and across an
 * enumeration: vid/pid read 0000:0000 in early enumeration (before the device
 * descriptor is fetched), and urb events carry no devpath, so (bus,dev) is the
 * common denominator. vid/pid are learned and stored on the window for display.
 */
struct diag_devkey {
	uint16_t busnum;
	uint16_t devnum;
};

static inline struct diag_devkey diag_event_key(const struct diag_event *e)
{
	struct diag_devkey k = { e->busnum, e->devnum };

	return k;
}

#endif /* __USBTRACE_MOD_DIAG_H */

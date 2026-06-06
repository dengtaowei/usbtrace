/* SPDX-License-Identifier: GPL-2.0 */
/*
 * usbtrace_run() — the one shared "load → attach → poll" harness for every
 * single-skeleton module (urb/enum/lifecycle/power/uvc/uac/hid/storage).
 *
 * Each tracing module differs only in (1) its skeleton type, (2) the .rodata
 * config it sets, and (3) how it formats events. Everything else — loading,
 * attaching, building the ring buffer, the poll loop, Ctrl-C / error handling,
 * and teardown of the ring buffer — is identical, so it lives here. A module's
 * run() becomes: open skeleton → set cfg → usbtrace_run() → destroy skeleton.
 *
 * This is what makes the modules behave consistently and keeps a new module to
 * a few lines. It uses libbpf's generic skeleton ABI (bpf_object__*_skeleton),
 * which every generated skeleton struct exposes via its first two fields
 * (`skeleton`, `obj`) plus `maps.events`.
 *
 * Ownership: the module owns open()/destroy() of its skeleton; usbtrace_run()
 * never frees it (so the module can read maps/stats afterwards and teardown is
 * symmetric with open).
 */
#ifndef __USBTRACE_RUN_H
#define __USBTRACE_RUN_H

#include <stdbool.h>

#include <bpf/libbpf.h>

struct usbtrace_run {
	/* From the opened skeleton: `skel->skeleton` and `skel->maps.events`. */
	struct bpf_object_skeleton *skeleton;
	struct bpf_map *events;

	/* Ring-buffer consumer (ctx is passed through to it). */
	ring_buffer_sample_fn on_event;
	void *ctx;

	/* Optional. Called once after a successful attach, before polling —
	 * the right place to print a "tracing ..." line and a text header. */
	void (*on_start)(void);

	/* Optional. Called once after the poll loop ends — e.g. a summary. */
	void (*on_stop)(void);
};

/*
 * Load + attach the skeleton, then poll `events` until *running is false.
 * Returns a process exit code (0 = ok). Does not open or destroy the skeleton.
 */
int usbtrace_run(const struct usbtrace_run *r, volatile bool *running);

#endif /* __USBTRACE_RUN_H */

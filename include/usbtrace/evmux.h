/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The event-consumer abstraction: one or more module `events` maps merged into
 * a single poll loop.
 *
 * This is the ONLY place user space knows which BPF event transport is in use.
 * The backend is fixed at build time (config.mk `USBTRACE_EVENTS`):
 *
 *   ringbuf -> one ring_buffer, extra sources via ring_buffer__add()
 *   perf    -> one perf_buffer per source; flat epoll over per-CPU perf fds,
 *              drain via perf_buffer__consume() (never nest epoll-on-epoll)
 *
 * Both back-ends deliver records through the same `ring_buffer_sample_fn`
 * signature, so consumers (and the whole module layer) are transport-agnostic:
 *
 *   usbtrace_run()  - single source, used by every tracing module
 *   diag            - several sources merged into one correlation loop
 */
#ifndef __USBTRACE_EVMUX_H
#define __USBTRACE_EVMUX_H

#include <bpf/libbpf.h>

struct usbtrace_evmux;

/* Create a consumer delivering every record to cb(ctx, data, size). */
struct usbtrace_evmux *usbtrace_evmux_new(ring_buffer_sample_fn cb, void *ctx);

/* Add one loaded module's `events` map. Returns 0 on success, -errno on error. */
int usbtrace_evmux_add(struct usbtrace_evmux *m, struct bpf_map *events);

/* Poll all sources. Returns records consumed, or -errno (incl. -EINTR). */
int usbtrace_evmux_poll(struct usbtrace_evmux *m, int timeout_ms);

void usbtrace_evmux_free(struct usbtrace_evmux *m);

#endif /* __USBTRACE_EVMUX_H */

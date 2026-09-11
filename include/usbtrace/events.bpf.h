/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared events map + emit helper for every tracing module.
 *
 * Selected at *build* time via config.mk (USBTRACE_EVENTS=ringbuf|perf):
 *   ringbuf (default) -> BPF_MAP_TYPE_RINGBUF + bpf_ringbuf_*
 *   perf              -> BPF_MAP_TYPE_PERF_EVENT_ARRAY + bpf_perf_event_output
 *                        (-DUSBTRACE_USE_PERF)
 *
 * Include AFTER vmlinux.h and bpf_helpers.h. Declares global `events`.
 */
#ifndef __USBTRACE_EVENTS_BPF_H
#define __USBTRACE_EVENTS_BPF_H

#include "usbtrace/compat.bpf.h"

#ifdef USBTRACE_USE_PERF
/*
 * max_entries is an upper bound on CPUs; libbpf still pins one buffer per
 * online CPU at open. Keep this explicit so older tooling does not see 0.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 128);
} events SEC(".maps");
#else
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");
#endif

/*
 * Emit a stack-filled event record. `ctx` is the program context (pt_regs *
 * for kprobe, bpf_raw_tracepoint_args * for raw_tp, …); required for perf,
 * unused for ringbuf.
 *
 * Keep the event object in a tight block at the call site when nesting emits
 * (see uvc_emit_frame) so BPF stack pressure stays under 512 bytes.
 */
#ifdef USBTRACE_USE_PERF
#define USBTRACE_EVENT_OUTPUT(ctx, eptr)                                       \
	bpf_perf_event_output((ctx), &events, BPF_F_CURRENT_CPU, (eptr),       \
			      sizeof(*(eptr)))
#else
#define USBTRACE_EVENT_OUTPUT(ctx, eptr)                                       \
	({                                                                    \
		typeof(*(eptr)) *__ut_e =                                     \
			bpf_ringbuf_reserve(&events, sizeof(*(eptr)), 0);      \
		if (__ut_e) {                                                 \
			*__ut_e = *(eptr);                                    \
			bpf_ringbuf_submit(__ut_e, 0);                         \
		}                                                             \
		0;                                                            \
	})
#endif

#endif /* __USBTRACE_EVENTS_BPF_H */

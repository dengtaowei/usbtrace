/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Hook feature-probing + per-program graceful degradation.
 *
 * "One CO-RE binary across kernels" means a probe target a module wants may not
 * exist on the running kernel (function renamed/removed, driver built differently,
 * a tracepoint absent). Rather than fail the whole module, we check each BPF
 * program's attach target BEFORE load and disable just the ones that cannot
 * attach (libbpf then skips them at load + attach). A module keeps running on
 * whatever hooks ARE present; it only fails when none are.
 *
 * The check is generic: it reads the program's SEC() name
 * (e.g. "kprobe/usb_submit_urb", "tracepoint/vb2/vb2_buf_done") and consults the
 * kernel's own lists (ftrace available_filter_functions / kallsyms for functions,
 * tracefs events/ for tracepoints). Availability is tri-state: when it cannot be
 * determined (lists unreadable / unknown SEC form) we FAIL OPEN and leave the
 * program enabled, so we never wrongly disable a hook that would have worked.
 */
#ifndef __USBTRACE_PROBE_H
#define __USBTRACE_PROBE_H

#include <bpf/libbpf.h>

/* Is a kprobe-able kernel function present? 1 = yes, 0 = no, -1 = unknown. */
int usbtrace_kfunc_available(const char *name);

/* Is a tracepoint present? 1 = yes, 0 = no, -1 = unknown. */
int usbtrace_tracepoint_available(const char *subsys, const char *event);

/* Is a tracepoint with this event name present in any subsystem? */
int usbtrace_tracepoint_event_available(const char *event);

/*
 * Walk every program of an opened (not yet loaded) bpf_object and disable
 * autoload for any whose attach target is provably absent (warns for each).
 * Programs whose availability is unknown stay enabled (fail-open).
 *
 * Returns the number of programs still enabled. 0 means the module has no usable
 * hook on this kernel and the caller should treat that as a failure to attach.
 */
int usbtrace_autoload_filter(struct bpf_object *obj);

#endif /* __USBTRACE_PROBE_H */

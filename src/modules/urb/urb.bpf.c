// SPDX-License-Identifier: GPL-2.0
/*
 * urb module BPF program.
 *
 * Traces USB Request Block (URB) lifecycle at the two universal choke points
 * every host-controller driver funnels through:
 *
 *   usb_submit_urb(struct urb *urb, gfp_t mem_flags)       -> request queued
 *   usb_hcd_giveback_urb(hcd, urb, status)                 -> request completed
 *
 * submit timestamps are stashed in a hash keyed by the urb pointer and paired
 * with the completion to compute submit->complete latency. CO-RE
 * (BPF_CORE_READ) keeps it portable across kernels and across
 * x86/arm/arm64/... with a single source.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/filter.bpf.h"
#include "urb.h"

char LICENSE[] SEC("license") = "GPL";

/* Filled in from user space before load (see urb.c). The `= {}` initializer is
 * required for correct BTF emission of const volatile globals on clang <= 10. */
const volatile struct urb_config cfg = {};

/* USB pipe bit layout (mirrors <linux/usb.h> usb_pipe* macros). */
#define USB_DIR_IN 0x80

static __always_inline __u8 pipe_endpoint(__u32 pipe)
{
	return (pipe >> 15) & 0xf;
}
static __always_inline __u8 pipe_is_in(__u32 pipe)
{
	return (pipe & USB_DIR_IN) ? 1 : 0;
}
static __always_inline __u8 pipe_type(__u32 pipe)
{
	return (pipe >> 30) & 0x3;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);   /* urb pointer */
	__type(value, __u64); /* submit ts_ns */
} start_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int urb_passes_filter(struct urb *urb, __u16 *vid_out,
					     __u16 *pid_out)
{
	struct usb_device *dev = BPF_CORE_READ(urb, dev);

	return usbtrace_dev_match(dev, cfg.filter_vid, cfg.filter_pid, vid_out,
				 pid_out);
}

static __always_inline void fill_common(struct urb_event *e, struct urb *urb,
					__u16 vid, __u16 pid)
{
	struct usb_device *dev = BPF_CORE_READ(urb, dev);
	__u32 pipe = BPF_CORE_READ(urb, pipe);

	e->vid = vid;
	e->product = pid;
	e->busnum = BPF_CORE_READ(dev, bus, busnum);
	e->devnum = BPF_CORE_READ(dev, devnum);
	e->ep = pipe_endpoint(pipe);
	e->dir_in = pipe_is_in(pipe);
	e->xfer_type = pipe_type(pipe);
	e->length = BPF_CORE_READ(urb, transfer_buffer_length);
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("kprobe/usb_submit_urb")
int BPF_KPROBE(on_submit, struct urb *urb)
{
	__u16 vid = 0, pid = 0;
	__u64 key = (__u64)urb;
	__u64 ts = bpf_ktime_get_ns();

	if (!urb)
		return 0;
	if (!urb_passes_filter(urb, &vid, &pid))
		return 0;

	bpf_map_update_elem(&start_ts, &key, &ts, BPF_ANY);

	if (!cfg.emit_submit)
		return 0;

	struct urb_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->hdr.kind = USBTRACE_EVT_URB;
	e->hdr.size = sizeof(*e);
	e->hdr.ts_ns = ts;
	e->is_submit = 1;
	fill_common(e, urb, vid, pid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Hook usb_hcd_giveback_urb(hcd, urb, status) rather than the inner
 * __usb_hcd_giveback_urb(urb): the authoritative completion status is the
 * 'status' argument here. At __usb_hcd_giveback_urb entry urb->status is still
 * -EINPROGRESS (it is assigned from urb->unlinked only just before calling the
 * completion handler), which is why reading urb->status reported -115 (-EINPROGRESS)
 * for every event.
 */
SEC("kprobe/usb_hcd_giveback_urb")
int BPF_KPROBE(on_giveback, struct usb_hcd *hcd, struct urb *urb, int status)
{
	__u16 vid = 0, pid = 0;
	__u64 key = (__u64)urb;
	__u64 now = bpf_ktime_get_ns();
	__u64 *tsp;

	if (!urb)
		return 0;

	tsp = bpf_map_lookup_elem(&start_ts, &key);
	/* If we never saw the submit (filtered or pre-existing), and a filter is
	 * active, re-check; otherwise skip to keep output focused. */
	if (!tsp) {
		if (cfg.filter_vid || cfg.filter_pid) {
			if (!urb_passes_filter(urb, &vid, &pid))
				return 0;
		} else {
			return 0;
		}
	} else if (!urb_passes_filter(urb, &vid, &pid)) {
		bpf_map_delete_elem(&start_ts, &key);
		return 0;
	}

	struct urb_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e) {
		if (tsp)
			bpf_map_delete_elem(&start_ts, &key);
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->hdr.kind = USBTRACE_EVT_URB;
	e->hdr.size = sizeof(*e);
	e->hdr.ts_ns = now;
	e->is_submit = 0;
	e->latency_ns = tsp ? (now - *tsp) : 0;
	e->status = status;
	e->actual = BPF_CORE_READ(urb, actual_length);
	fill_common(e, urb, vid, pid);
	bpf_ringbuf_submit(e, 0);

	if (tsp)
		bpf_map_delete_elem(&start_ts, &key);
	return 0;
}

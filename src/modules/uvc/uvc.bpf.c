// SPDX-License-Identifier: GPL-2.0
/*
 * uvc module BPF program (USB Video Class).
 *
 * Foundation hook: uvc_video_complete(struct urb *urb) — the uvcvideo streaming
 * URB completion callback every isoc/bulk video URB funnels through. Its arg is
 * a CORE type, so the shared emit helper reads only urb/usb_device (no uvcvideo
 * module BTF needed). See include/usbtrace/class_urb.bpf.h and docs/class.md.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/class_urb.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile struct usbtrace_class_config cfg = {};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/uvc_video_complete")
int BPF_KPROBE(on_video_complete, struct urb *urb)
{
	return usbtrace_class_urb_emit(&events, urb, cfg.filter_vid,
				       cfg.filter_pid, USBTRACE_CLASS_VIDEO);
}

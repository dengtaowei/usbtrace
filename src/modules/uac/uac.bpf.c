// SPDX-License-Identifier: GPL-2.0
/*
 * uac module BPF program (USB Audio Class).
 *
 * Hook: snd_complete_urb(struct urb *urb) — the snd-usb-audio URB completion
 * callback for both playback and capture isoc streams. Core-type arg, so the
 * shared emit helper reads only urb/usb_device (no snd-usb-audio module BTF).
 * error_count surfaces isoc packet errors (underrun/overrun manifests as
 * short/late packets); dir_in distinguishes capture (IN) from playback (OUT).
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

SEC("kprobe/snd_complete_urb")
int BPF_KPROBE(on_complete, struct urb *urb)
{
	return usbtrace_class_urb_emit(&events, urb, cfg.filter_vid,
				       cfg.filter_pid, USBTRACE_CLASS_AUDIO);
}

// SPDX-License-Identifier: GPL-2.0
/*
 * storage module BPF program (USB Mass Storage, Bulk-Only Transport).
 *
 * Hook: usb_stor_blocking_completion(struct urb *urb) — the usb-storage bulk
 * URB completion used by the CBW/data/CSW transport. Core-type arg, so the
 * shared emit helper reads only urb/usb_device (no usb-storage module BTF).
 * status surfaces stalls/timeouts (-EPIPE/-ETIMEDOUT) that precede SCSI error
 * recovery / bus resets; dir_in separates data-in from data-out/CBW phases.
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

SEC("kprobe/usb_stor_blocking_completion")
int BPF_KPROBE(on_complete, struct urb *urb)
{
	return usbtrace_class_urb_emit(&events, urb, cfg.filter_vid,
				       cfg.filter_pid, USBTRACE_CLASS_STORAGE);
}

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

#include "usbtrace/pt_regs.bpf.h"
#include "usbtrace/class_urb.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const volatile struct usbtrace_class_config cfg = {};

SEC("kprobe/usb_stor_blocking_completion")
int on_complete(struct pt_regs *ctx)
{
	struct urb *urb = USBTRACE_KPTR((void *)USBTRACE_PT_PARM1(ctx));

	return usbtrace_class_urb_emit(ctx, urb, cfg.filter_vid,
				       cfg.filter_pid, USBTRACE_CLASS_STORAGE);
}

// SPDX-License-Identifier: GPL-2.0
/*
 * hid module BPF program (USB HID).
 *
 * Hooks the usbhid interrupt URB completion callbacks:
 *   hid_irq_in(struct urb *urb)   - input reports (device -> host)
 *   hid_irq_out(struct urb *urb)  - output reports / SET_REPORT (host -> device)
 * Both take a CORE type, so the shared emit helper reads only urb/usb_device.
 * dir_in distinguishes the two; status surfaces transfer errors and the IN/OUT
 * mix can reveal unexpected host->device report traffic.
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

SEC("kprobe/hid_irq_in")
int BPF_KPROBE(on_irq_in, struct urb *urb)
{
	return usbtrace_class_urb_emit(&events, urb, cfg.filter_vid,
				       cfg.filter_pid, USBTRACE_CLASS_HID);
}

SEC("kprobe/hid_irq_out")
int BPF_KPROBE(on_irq_out, struct urb *urb)
{
	return usbtrace_class_urb_emit(&events, urb, cfg.filter_vid,
				       cfg.filter_pid, USBTRACE_CLASS_HID);
}

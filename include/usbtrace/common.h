/* SPDX-License-Identifier: GPL-2.0 */
/*
 * usbtrace common definitions shared between BPF (kernel) and user space.
 *
 * IMPORTANT: This header is included from .bpf.c programs. Keep it free of
 * any libc / kernel-only headers. Use only fixed-width integer types.
 */
#ifndef __USBTRACE_COMMON_H
#define __USBTRACE_COMMON_H

#define USBTRACE_COMM_LEN 16

/* USB transfer types (matches PIPE_* encoding in <linux/usb.h>). */
enum usbtrace_xfer_type {
	USBTRACE_XFER_ISOC = 0,
	USBTRACE_XFER_INT = 1,
	USBTRACE_XFER_CONTROL = 2,
	USBTRACE_XFER_BULK = 3,
};

/* Event kind: lets a single ring buffer carry multiple record layouts as the
 * project grows (urb, enumeration, power, uac, uvc ...). */
enum usbtrace_event_kind {
	USBTRACE_EVT_URB = 1,
	USBTRACE_EVT_ENUM = 2,
	USBTRACE_EVT_POWER = 3,
	/* reserved for future modules: UAC/UVC/HID/storage ... */
};

/* Common envelope at the head of every event pushed to the ring buffer.
 * Modules embed this as their first member so the dispatcher can route by
 * .kind without knowing the concrete type. */
struct usbtrace_event_hdr {
	__u32 kind;	/* enum usbtrace_event_kind */
	__u32 size;	/* total bytes of the concrete event */
	__u64 ts_ns;	/* bpf_ktime_get_ns() at emit time */
};

#endif /* __USBTRACE_COMMON_H */

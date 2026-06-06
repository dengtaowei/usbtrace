/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared types for "class-traffic" modules (uvc/uac/hid/storage and future
 * ones). These modules all observe the same thing: a class driver's URB
 * completion callback. Rather than each inventing its own record, they share
 * ONE normalized record (struct class_urb_event, hdr.kind == USBTRACE_EVT_CLASS)
 * discriminated by `class` (enum usbtrace_class).
 *
 * Why one shared shape: it makes diag cooperation trivial — diag has a single
 * normalize case and a single rule vocabulary (kind: class, class: video|...)
 * for every class module, present and future. Adding a class module does not
 * grow diag's event model.
 *
 * BPF-safe: fixed-width ints only; included from both .bpf.c and user space.
 */
#ifndef __USBTRACE_CLASS_H
#define __USBTRACE_CLASS_H

#include "usbtrace/common.h"

/* Which class driver produced the event. Append only; values are on-the-wire. */
enum usbtrace_class {
	USBTRACE_CLASS_VIDEO = 0,	/* uvcvideo */
	USBTRACE_CLASS_AUDIO = 1,	/* snd-usb-audio */
	USBTRACE_CLASS_HID = 2,		/* usbhid */
	USBTRACE_CLASS_STORAGE = 3,	/* usb-storage */
	USBTRACE_CLASS_MAX
};

/*
 * One class-traffic record: a streaming/transfer URB completed in a class
 * driver. Every field is read straight off `struct urb` / `urb->dev`, which are
 * CORE kernel types in vmlinux BTF — so this works without any class driver's
 * module BTF. error_count is the isoc packet-error count (the primary
 * corruption/drop signal for video/audio); for INT/BULK it is typically 0 and
 * `status` is the signal instead.
 */
struct class_urb_event {
	struct usbtrace_event_hdr hdr;	/* kind = USBTRACE_EVT_CLASS */

	__s32 status;		  /* urb->status (0 = ok) */
	__s32 error_count;	  /* urb->error_count (isoc packets with errors) */
	__u32 number_of_packets;  /* isoc packets in this URB (0 for INT/BULK) */
	__u32 actual_length;	  /* bytes transferred */
	__s32 start_frame;	  /* isoc start (micro)frame */
	__u32 pid;		  /* tgid in context (often irq/kworker) */

	__u16 vid;
	__u16 product;
	__u16 busnum;
	__u16 devnum;

	__u8 klass;		  /* enum usbtrace_class */
	__u8 ep;		  /* endpoint number */
	__u8 dir_in;		  /* 1 = IN (device->host) */
	__u8 xfer_type;		  /* enum usbtrace_xfer_type */

	char comm[USBTRACE_COMM_LEN];
};

/* Config pushed into every class BPF program via .rodata before load. Uniform
 * across class modules so diag can set the filter generically. */
struct usbtrace_class_config {
	__u16 filter_vid; /* 0 = any */
	__u16 filter_pid; /* 0 = any */
};

#endif /* __USBTRACE_CLASS_H */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared BPF-side helper for class-traffic modules (uvc/uac/hid/storage).
 *
 * Every class module hooks its driver's URB completion callback, whose argument
 * is a CORE type (`struct urb *`), and emits a normalized struct class_urb_event
 * (see class.h). This helper does the reserve/fill/submit so a module's .bpf.c
 * is just "kprobe -> usbtrace_class_urb_emit(&events, urb, ..., CLASS_X)".
 *
 * Include AFTER "vmlinux.h" in a .bpf.c.
 *
 * EXTENSION RULE: only read core USB types here (urb, urb->dev). Class drivers'
 * private structs live in module BTF, not vmlinux BTF; staying on core types is
 * what makes this CO-RE helper portable across kernels/arches.
 */
#ifndef __USBTRACE_CLASS_URB_BPF_H
#define __USBTRACE_CLASS_URB_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "usbtrace/class.h"
#include "usbtrace/filter.bpf.h"

#define USBTRACE_USB_DIR_IN 0x80

/*
 * Reserve/fill/submit one class_urb_event for `urb` into the `events` ringbuf.
 * Returns 0 always (BPF programs return 0). Applies the (fvid,fpid) filter.
 */
static __always_inline int
usbtrace_class_urb_emit(void *events, struct urb *urb, __u16 fvid, __u16 fpid,
			__u8 klass)
{
	__u16 vid = 0, pid = 0;
	struct usb_device *dev;
	__u32 pipe;

	if (!urb)
		return 0;
	dev = BPF_CORE_READ(urb, dev);
	if (!usbtrace_dev_match(dev, fvid, fpid, &vid, &pid))
		return 0;

	struct class_urb_event *e = bpf_ringbuf_reserve(events, sizeof(*e), 0);

	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->hdr.kind = USBTRACE_EVT_CLASS;
	e->hdr.size = sizeof(*e);
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->klass = klass;

	pipe = BPF_CORE_READ(urb, pipe);
	e->ep = (pipe >> 15) & 0xf;
	e->dir_in = (pipe & USBTRACE_USB_DIR_IN) ? 1 : 0;
	e->xfer_type = (pipe >> 30) & 0x3;

	e->status = BPF_CORE_READ(urb, status);
	e->error_count = BPF_CORE_READ(urb, error_count);
	e->number_of_packets = BPF_CORE_READ(urb, number_of_packets);
	e->actual_length = BPF_CORE_READ(urb, actual_length);
	e->start_frame = BPF_CORE_READ(urb, start_frame);

	e->vid = vid;
	e->product = pid;
	e->busnum = BPF_CORE_READ(dev, bus, busnum);
	e->devnum = BPF_CORE_READ(dev, devnum);
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

#endif /* __USBTRACE_CLASS_URB_BPF_H */

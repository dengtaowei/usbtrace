// SPDX-License-Identifier: GPL-2.0
/*
 * lifecycle module BPF program.
 *
 * Traces USB device connect/disconnect at the two USB-core choke points:
 *
 *   usb_new_device(struct usb_device *udev)      -> connect (enumeration done)
 *   usb_disconnect(struct usb_device **pdev)     -> disconnect (teardown start)
 *
 * Note usb_disconnect() takes a *pointer to* the usb_device pointer, so we
 * deref one level before reading device fields. CO-RE (BPF_CORE_READ) keeps it
 * portable across kernels and arches.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/filter.bpf.h"
#include "lifecycle.h"

char LICENSE[] SEC("license") = "GPL";

/* Filled in from user space before load (see lifecycle.c). */
const volatile struct lifecycle_config cfg;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int emit(struct usb_device *dev, __u8 action)
{
	__u16 vid = 0, pid = 0;

	if (!dev)
		return 0;
	if (!usbtrace_dev_match(dev, cfg.filter_vid, cfg.filter_pid, &vid, &pid))
		return 0;

	struct lifecycle_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->hdr.kind = USBTRACE_EVT_LIFECYCLE;
	e->hdr.size = sizeof(*e);
	e->hdr.ts_ns = bpf_ktime_get_ns();

	e->action = action;
	e->vid = vid;
	e->product = pid;
	e->busnum = BPF_CORE_READ(dev, bus, busnum);
	e->devnum = BPF_CORE_READ(dev, devnum);
	e->speed = BPF_CORE_READ(dev, speed);
	e->portnum = BPF_CORE_READ(dev, portnum);
	BPF_CORE_READ_STR_INTO(&e->devpath, dev, devpath);
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/usb_new_device")
int BPF_KPROBE(on_new_device, struct usb_device *udev)
{
	return emit(udev, LIFECYCLE_CONNECT);
}

SEC("kprobe/usb_disconnect")
int BPF_KPROBE(on_disconnect, struct usb_device **pdev)
{
	struct usb_device *udev = NULL;

	if (!pdev)
		return 0;
	bpf_probe_read_kernel(&udev, sizeof(udev), pdev);
	return emit(udev, LIFECYCLE_DISCONNECT);
}

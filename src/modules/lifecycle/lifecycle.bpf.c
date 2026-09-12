// SPDX-License-Identifier: GPL-2.0
/*
 * lifecycle module BPF program.
 *
 * Traces USB device connect/disconnect at the two USB-core choke points:
 *
 *   usb_new_device(struct usb_device *udev)      -> connect
 *   usb_disconnect(struct usb_device **pdev)     -> disconnect
 *   usb_reset_device(struct usb_device *udev)    -> reset (reset_resume flag)
 *
 * usb_new_device reads descriptors only inside usb_enumerate_device(), so a
 * plain entry kprobe would often see idVendor/idProduct still 0. Stash the
 * udev pointer on entry and emit from the kretprobe after a successful return.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/filter.bpf.h"
#include "usbtrace/events.bpf.h"
#include "usbtrace/pt_regs.bpf.h"
#include "lifecycle.h"

char LICENSE[] SEC("license") = "GPL";

const volatile struct lifecycle_config cfg = {};

/* tid -> usb_device * for usb_new_device entry/exit pairing */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} new_dev_pending SEC(".maps");

static __always_inline int emit(struct pt_regs *ctx, struct usb_device *dev,
				__u8 action)
{
	__u16 vid = 0, pid = 0;
	struct lifecycle_event e = {};

	dev = USBTRACE_KPTR(dev);
	if (!dev)
		return 0;
	if (!usbtrace_dev_match(dev, cfg.filter_vid, cfg.filter_pid, &vid, &pid))
		return 0;

	e.hdr.kind = USBTRACE_EVT_LIFECYCLE;
	e.hdr.size = sizeof(e);
	e.hdr.ts_ns = bpf_ktime_get_ns();

	e.action = action;
	e.reset_resume = 0;
	if (action == LIFECYCLE_RESET)
		e.reset_resume =
			(__u8)BPF_CORE_READ_BITFIELD_PROBED(dev, reset_resume);
	e.vid = vid;
	e.product = pid;
	e.busnum = BPF_CORE_READ(dev, bus, busnum);
	e.devnum = BPF_CORE_READ(dev, devnum);
	e.speed = BPF_CORE_READ(dev, speed);
	e.portnum = BPF_CORE_READ(dev, portnum);
	BPF_CORE_READ_STR_INTO(&e.devpath, dev, devpath);
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	USBTRACE_EVENT_OUTPUT(ctx, &e);
	return 0;
}

SEC("kprobe/usb_new_device")
int on_new_device(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 udev = USBTRACE_PTR_KEY((void *)USBTRACE_PT_PARM1(ctx));

	if (!udev)
		return 0;
	bpf_map_update_elem(&new_dev_pending, &id, &udev, BPF_ANY);
	return 0;
}

SEC("kretprobe/usb_new_device")
int on_new_device_exit(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 *pud;
	struct usb_device *udev;
	int ret = usbtrace_kret_int(USBTRACE_PT_RET(ctx));

	pud = bpf_map_lookup_elem(&new_dev_pending, &id);
	if (!pud)
		return 0;
	udev = USBTRACE_KPTR((void *)(unsigned long)(*pud));
	bpf_map_delete_elem(&new_dev_pending, &id);
	if (ret < 0 || !udev)
		return 0;
	return emit(ctx, udev, LIFECYCLE_CONNECT);
}

SEC("kprobe/usb_disconnect")
int on_disconnect(struct pt_regs *ctx)
{
	struct usb_device **pdev =
		USBTRACE_KPTR((void *)USBTRACE_PT_PARM1(ctx));
	struct usb_device *udev;

	if (!pdev)
		return 0;
	udev = usbtrace_read_kptr(pdev);
	return emit(ctx, udev, LIFECYCLE_DISCONNECT);
}

SEC("kprobe/usb_reset_device")
int on_reset(struct pt_regs *ctx)
{
	return emit(ctx, (struct usb_device *)USBTRACE_PT_PARM1(ctx),
		    LIFECYCLE_RESET);
}

// SPDX-License-Identifier: GPL-2.0
/*
 * power module BPF program.
 *
 * Traces USB runtime power management by hooking the autosuspend/autoresume
 * entry points in usbcore:
 *
 *   usb_autosuspend_device(struct usb_device *udev)  -> request runtime suspend
 *   usb_autoresume_device(struct usb_device *udev)   -> request runtime resume
 *   usb_port_suspend(struct usb_device *udev, ...)   -> actual port suspend
 *   usb_port_resume(struct usb_device *udev, ...)    -> actual port resume
 *
 * usb_port_* fire for both runtime autosuspend and system sleep (S3). Pair
 * with `urb --ctrl` to see the SET_FEATURE / CLEAR_FEATURE packets that
 * usb_port_suspend/resume issue. CO-RE (BPF_CORE_READ) keeps it portable
 * across kernels and arches.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/filter.bpf.h"
#include "usbtrace/events.bpf.h"
#include "usbtrace/pt_regs.bpf.h"
#include "power.h"

char LICENSE[] SEC("license") = "GPL";

/* Filled in from user space before load (see power.c). The `= {}` initializer is
 * required for correct BTF emission of const volatile globals on clang <= 10. */
const volatile struct power_config cfg = {};

static __always_inline int emit(void *ctx, struct usb_device *dev, __u8 action)
{
	__u16 vid = 0, pid = 0;
	struct power_rec e = {};

	dev = USBTRACE_KPTR(dev);
	if (!dev)
		return 0;
	if (!usbtrace_dev_match(dev, cfg.filter_vid, cfg.filter_pid, &vid, &pid))
		return 0;

	e.hdr.kind = USBTRACE_EVT_POWER;
	e.hdr.size = sizeof(e);
	e.hdr.ts_ns = bpf_ktime_get_ns();

	e.action = action;
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

SEC("kprobe/usb_autosuspend_device")
int on_autosuspend(struct pt_regs *ctx)
{
	return emit(ctx, (struct usb_device *)USBTRACE_PT_PARM1(ctx),
		    POWER_AUTOSUSPEND);
}

SEC("kprobe/usb_autoresume_device")
int on_autoresume(struct pt_regs *ctx)
{
	return emit(ctx, (struct usb_device *)USBTRACE_PT_PARM1(ctx),
		    POWER_AUTORESUME);
}

SEC("kprobe/usb_port_suspend")
int on_port_suspend(struct pt_regs *ctx)
{
	return emit(ctx, (struct usb_device *)USBTRACE_PT_PARM1(ctx),
		    POWER_PORT_SUSPEND);
}

SEC("kprobe/usb_port_resume")
int on_port_resume(struct pt_regs *ctx)
{
	return emit(ctx, (struct usb_device *)USBTRACE_PT_PARM1(ctx),
		    POWER_PORT_RESUME);
}

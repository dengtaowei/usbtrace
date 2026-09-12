// SPDX-License-Identifier: GPL-2.0
/*
 * hub module BPF program.
 *
 * Port-level hub actions:
 *
 *   hub_port_reset(hub, port1, udev, delay, warm)
 *   hub_port_disable(hub, port1, set_state)
 *   usb_hub_set_port_power(hdev, hub, port1, set)
 *   port_over_current_notify(port_dev)
 *
 * Prefer the child usb_device on that port so (vid,pid,bus,dev) matches other
 * device-scoped records. If the port is empty, fall back to the hub device
 * and still emit portnum. Each hook is autoload-filtered independently.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/filter.bpf.h"
#include "usbtrace/events.bpf.h"
#include "usbtrace/pt_regs.bpf.h"
#include "hub.h"

char LICENSE[] SEC("license") = "GPL";

const volatile struct hub_config cfg = {};

static __always_inline struct usb_device *hub_child(struct usb_hub *hub,
						    int port1)
{
	struct usb_port **ports;
	struct usb_port *port;

	if (!hub || port1 < 1 || port1 > 16)
		return NULL;
	ports = BPF_CORE_READ(hub, ports);
	port = usbtrace_kptr_idx(ports, port1 - 1);
	if (!port)
		return NULL;
	return USBTRACE_KPTR(BPF_CORE_READ(port, child));
}

static __always_inline int emit_dev(struct pt_regs *ctx, struct usb_device *dev,
				    int port1, __u8 action, __u8 warm,
				    __u32 oc_count)
{
	__u16 vid = 0, pid = 0;
	struct hub_event e = {};

	dev = USBTRACE_KPTR(dev);
	if (!dev)
		return 0;
	if (!usbtrace_dev_match(dev, cfg.filter_vid, cfg.filter_pid, &vid, &pid))
		return 0;

	e.hdr.kind = USBTRACE_EVT_HUB;
	e.hdr.size = sizeof(e);
	e.hdr.ts_ns = bpf_ktime_get_ns();

	e.action = action;
	e.vid = vid;
	e.product = pid;
	e.busnum = BPF_CORE_READ(dev, bus, busnum);
	e.devnum = BPF_CORE_READ(dev, devnum);
	e.speed = BPF_CORE_READ(dev, speed);
	e.portnum = port1 > 0 ? (__u8)port1 : BPF_CORE_READ(dev, portnum);
	e.warm = warm;
	e.oc_count = oc_count;
	BPF_CORE_READ_STR_INTO(&e.devpath, dev, devpath);
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	USBTRACE_EVENT_OUTPUT(ctx, &e);
	return 0;
}

static __always_inline int emit_hub_port(struct pt_regs *ctx,
					 struct usb_hub *hub, int port1,
					 struct usb_device *udev, __u8 action,
					 __u8 warm, __u32 oc_count)
{
	struct usb_device *dev;

	hub = USBTRACE_KPTR(hub);
	udev = USBTRACE_KPTR(udev);
	dev = udev ? udev : hub_child(hub, port1);
	if (!dev && hub)
		dev = BPF_CORE_READ(hub, hdev);
	return emit_dev(ctx, dev, port1, action, warm, oc_count);
}

SEC("kprobe/hub_port_reset")
int on_port_reset(struct pt_regs *ctx)
{
	struct usb_hub *hub = (struct usb_hub *)USBTRACE_PT_PARM1(ctx);
	int port1 = (int)USBTRACE_PT_PARM2(ctx);
	struct usb_device *udev = (struct usb_device *)USBTRACE_PT_PARM3(ctx);

	return emit_hub_port(ctx, hub, port1, udev, HUB_RESET, 0, 0);
}

SEC("kprobe/hub_port_disable")
int on_port_disable(struct pt_regs *ctx)
{
	struct usb_hub *hub = (struct usb_hub *)USBTRACE_PT_PARM1(ctx);
	int port1 = (int)USBTRACE_PT_PARM2(ctx);

	return emit_hub_port(ctx, hub, port1, NULL, HUB_DISABLE, 0, 0);
}

SEC("kprobe/usb_hub_set_port_power")
int on_set_port_power(struct pt_regs *ctx)
{
	struct usb_device *hdev = (struct usb_device *)USBTRACE_PT_PARM1(ctx);
	struct usb_hub *hub = (struct usb_hub *)USBTRACE_PT_PARM2(ctx);
	int port1 = (int)USBTRACE_PT_PARM3(ctx);
	int set = (int)USBTRACE_PT_PARM4(ctx);
	__u8 action = set ? HUB_POWER_ON : HUB_POWER_OFF;
	struct usb_device *child;

	hub = USBTRACE_KPTR(hub);
	hdev = USBTRACE_KPTR(hdev);
	child = hub_child(hub, port1);
	if (!child)
		child = hdev;
	return emit_dev(ctx, child, port1, action, 0, 0);
}

SEC("kprobe/port_over_current_notify")
int on_overcurrent(struct pt_regs *ctx)
{
	struct usb_port *port =
		USBTRACE_KPTR((void *)USBTRACE_PT_PARM1(ctx));
	struct usb_device *child;
	int port1;
	__u32 oc;

	if (!port)
		return 0;
	port1 = (int)BPF_CORE_READ(port, portnum);
	oc = BPF_CORE_READ(port, over_current_count);
	child = USBTRACE_KPTR(BPF_CORE_READ(port, child));
	if (!child)
		return 0;
	return emit_dev(ctx, child, port1, HUB_OVERCURRENT, 0, oc);
}

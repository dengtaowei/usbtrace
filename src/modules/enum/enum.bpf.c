// SPDX-License-Identifier: GPL-2.0
/*
 * enum module BPF program.
 *
 * Traces the USB enumeration timeline by hooking the single function every
 * enumeration path funnels through to advance a device's state machine:
 *
 *   usb_set_device_state(struct usb_device *udev, enum usb_device_state state)
 *
 * Each transition (NOTATTACHED -> ATTACHED -> POWERED -> DEFAULT -> ADDRESS ->
 * CONFIGURED, plus SUSPENDED) is emitted with old->new state so a stalled or
 * failed bring-up is visible as "stuck at DEFAULT" / "never reached ADDRESS".
 * CO-RE (BPF_CORE_READ) keeps it portable across kernels and arches.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/filter.bpf.h"
#include "usbtrace/events.bpf.h"
#include "usbtrace/pt_regs.bpf.h"
#include "enum.h"

char LICENSE[] SEC("license") = "GPL";

/* Filled in from user space before load (see enum.c). The `= {}` initializer is
 * required for correct BTF emission of const volatile globals on clang <= 10. */
const volatile struct enum_config cfg = {};

SEC("kprobe/usb_set_device_state")
int on_set_state(struct pt_regs *ctx)
{
	struct usb_device *udev = (struct usb_device *)USBTRACE_PT_PARM1(ctx);
	enum usb_device_state new_state =
		(enum usb_device_state)USBTRACE_PT_PARM2(ctx);
	__u16 vid = 0, pid = 0;
	struct enum_event e = {};

	udev = USBTRACE_KPTR(udev);
	if (!udev)
		return 0;
	if (!usbtrace_dev_match(udev, cfg.filter_vid, cfg.filter_pid, &vid, &pid))
		return 0;

	e.hdr.kind = USBTRACE_EVT_ENUM;
	e.hdr.size = sizeof(e);
	e.hdr.ts_ns = bpf_ktime_get_ns();

	e.vid = vid;
	e.product = pid;
	e.busnum = BPF_CORE_READ(udev, bus, busnum);
	e.devnum = BPF_CORE_READ(udev, devnum);
	e.old_state = BPF_CORE_READ(udev, state);
	e.new_state = (__u8)new_state;
	e.speed = BPF_CORE_READ(udev, speed);
	e.portnum = BPF_CORE_READ(udev, portnum);
	BPF_CORE_READ_STR_INTO(&e.devpath, udev, devpath);
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	USBTRACE_EVENT_OUTPUT(ctx, &e);
	return 0;
}

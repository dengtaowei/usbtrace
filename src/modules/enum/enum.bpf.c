// SPDX-License-Identifier: GPL-2.0
/*
 * enum module BPF program.
 *
 * Enumeration timeline:
 *
 *   usb_set_device_state(udev, state)           -> device-state machine
 *   usb_get_device_descriptor / hub_set_address
 *     / usb_set_configuration                   -> ep0 milestones (kretprobe,
 *                                                 so the return status is set)
 *
 * State transitions use step=STATE. Control milestones carry the kretprobe
 * status. Missing symbols are autoload-filtered per program.
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

const volatile struct enum_config cfg = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} desc_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} addr_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u64);
} config_pending SEC(".maps");

static __always_inline int emit_enum(struct pt_regs *ctx, struct usb_device *udev,
				     __u8 old_state, __u8 new_state, __u8 step,
				     __s32 status)
{
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
	e.old_state = old_state;
	e.new_state = new_state;
	e.speed = BPF_CORE_READ(udev, speed);
	e.portnum = BPF_CORE_READ(udev, portnum);
	e.step = step;
	e.status = status;
	BPF_CORE_READ_STR_INTO(&e.devpath, udev, devpath);
	e.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	USBTRACE_EVENT_OUTPUT(ctx, &e);
	return 0;
}

static __always_inline int stash(void *map, struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 udev = USBTRACE_PTR_KEY((void *)USBTRACE_PT_PARM1(ctx));

	if (!udev)
		return 0;
	bpf_map_update_elem(map, &id, &udev, BPF_ANY);
	return 0;
}

static __always_inline int pop_emit(void *map, struct pt_regs *ctx, __u8 step)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u64 *pud;
	struct usb_device *udev;
	__u8 state;
	int ret;

	if (step == ENUM_STEP_GET_DESC)
		ret = usbtrace_kret_ptr_or_int(USBTRACE_PT_RET(ctx));
	else
		ret = usbtrace_kret_int(USBTRACE_PT_RET(ctx));

	pud = bpf_map_lookup_elem(map, &id);
	if (!pud)
		return 0;
	udev = USBTRACE_KPTR((void *)(unsigned long)(*pud));
	bpf_map_delete_elem(map, &id);
	if (!udev)
		return 0;
	state = BPF_CORE_READ(udev, state);
	return emit_enum(ctx, udev, state, state, step, ret);
}

SEC("kprobe/usb_set_device_state")
int on_set_state(struct pt_regs *ctx)
{
	struct usb_device *udev = (struct usb_device *)USBTRACE_PT_PARM1(ctx);
	enum usb_device_state new_state =
		(enum usb_device_state)USBTRACE_PT_PARM2(ctx);
	__u8 old_state;

	udev = USBTRACE_KPTR(udev);
	if (!udev)
		return 0;
	old_state = BPF_CORE_READ(udev, state);
	return emit_enum(ctx, udev, old_state, (__u8)new_state, ENUM_STEP_STATE,
			 0);
}

SEC("kprobe/usb_get_device_descriptor")
int on_get_desc(struct pt_regs *ctx)
{
	return stash(&desc_pending, ctx);
}

SEC("kretprobe/usb_get_device_descriptor")
int on_get_desc_exit(struct pt_regs *ctx)
{
	return pop_emit(&desc_pending, ctx, ENUM_STEP_GET_DESC);
}

SEC("kprobe/hub_set_address")
int on_set_addr(struct pt_regs *ctx)
{
	return stash(&addr_pending, ctx);
}

SEC("kretprobe/hub_set_address")
int on_set_addr_exit(struct pt_regs *ctx)
{
	return pop_emit(&addr_pending, ctx, ENUM_STEP_SET_ADDR);
}

SEC("kprobe/usb_set_configuration")
int on_set_config(struct pt_regs *ctx)
{
	return stash(&config_pending, ctx);
}

SEC("kretprobe/usb_set_configuration")
int on_set_config_exit(struct pt_regs *ctx)
{
	return pop_emit(&config_pending, ctx, ENUM_STEP_SET_CONFIG);
}

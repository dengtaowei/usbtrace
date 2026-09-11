/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared types for the "power" module (autosuspend / autoresume). Included by
 * both power.bpf.c (kernel) and power.c (user space); keep it dependency-free
 * (fixed-width ints only).
 */
#ifndef __USBTRACE_MOD_POWER_H
#define __USBTRACE_MOD_POWER_H

#include "usbtrace/common.h"

enum power_action {
	POWER_AUTOSUSPEND = 0,
	POWER_AUTORESUME = 1,
	POWER_PORT_SUSPEND = 2,	/* usb_port_suspend: runtime + system sleep */
	POWER_PORT_RESUME = 3,	/* usb_port_resume: selective / system resume */
};

/* One record per autosuspend/autoresume call.
 * Named power_rec (not power_event) to avoid clashing with kernel
 * enum power_event in older vmlinux.h (e.g. Linux 5.4). */
struct power_rec {
	struct usbtrace_event_hdr hdr;

	__u32 pid;	  /* tgid in context (kworker or caller) */

	__u16 vid;
	__u16 product;
	__u16 busnum;
	__u16 devnum;

	__u8 action;	  /* enum power_action */
	__u8 speed;	  /* enum usb_device_speed */
	__u8 portnum;
	__u8 _pad;

	char devpath[16];
	char comm[USBTRACE_COMM_LEN];
};

/* Config pushed into the BPF program via .rodata before load. */
struct power_config {
	__u16 filter_vid; /* 0 = any */
	__u16 filter_pid; /* 0 = any */
};

#endif /* __USBTRACE_MOD_POWER_H */

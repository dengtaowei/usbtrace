/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared types for the "enum" module (enumeration timeline). Included by both
 * enum.bpf.c (kernel) and enum.c (user space), so keep it dependency-free
 * (fixed-width ints only).
 */
#ifndef __USBTRACE_MOD_ENUM_H
#define __USBTRACE_MOD_ENUM_H

#include "usbtrace/common.h"

/* One record per usb_set_device_state() transition. */
struct enum_event {
	struct usbtrace_event_hdr hdr;

	__u32 pid;	  /* tgid in context (usually a kworker/hub thread) */

	__u16 vid;
	__u16 product;
	__u16 busnum;
	__u16 devnum;

	__u8 old_state;	  /* enum usb_device_state at probe entry */
	__u8 new_state;	  /* enum usb_device_state requested */
	__u8 speed;	  /* enum usb_device_speed */
	__u8 portnum;	  /* hub port the device sits on */

	char devpath[16]; /* USB topology path, e.g. "1.3" */
	char comm[USBTRACE_COMM_LEN];
};

/* Config pushed into the BPF program via .rodata before load. */
struct enum_config {
	__u16 filter_vid; /* 0 = any */
	__u16 filter_pid; /* 0 = any */
};

#endif /* __USBTRACE_MOD_ENUM_H */

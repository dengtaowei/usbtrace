/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared types for the "lifecycle" module (connect / disconnect / reset). Included by
 * both lifecycle.bpf.c (kernel) and lifecycle.c (user space); keep it
 * dependency-free (fixed-width ints only).
 */
#ifndef __USBTRACE_MOD_LIFECYCLE_H
#define __USBTRACE_MOD_LIFECYCLE_H

#include "usbtrace/common.h"

enum lifecycle_action {
	LIFECYCLE_CONNECT = 0,	  /* usb_new_device: device fully enumerated */
	LIFECYCLE_DISCONNECT = 1, /* usb_disconnect: device going away */
	LIFECYCLE_RESET = 2,	  /* usb_reset_device: port reset + re-verify */
};

/* One record per connect / disconnect / reset. */
struct lifecycle_event {
	struct usbtrace_event_hdr hdr;

	__u32 pid;	  /* tgid in context */

	__u16 vid;
	__u16 product;
	__u16 busnum;
	__u16 devnum;

	__u8 action;	  /* enum lifecycle_action */
	__u8 speed;	  /* enum usb_device_speed */
	__u8 portnum;
	__u8 reset_resume; /* 1 if udev->reset_resume was set (resume path) */

	char devpath[16];
	char comm[USBTRACE_COMM_LEN];
};

/* Config pushed into the BPF program via .rodata before load. */
struct lifecycle_config {
	__u16 filter_vid; /* 0 = any */
	__u16 filter_pid; /* 0 = any */
};

#endif /* __USBTRACE_MOD_LIFECYCLE_H */

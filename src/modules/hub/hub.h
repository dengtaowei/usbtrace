/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared types for the "hub" module (port reset / disable / power / OC).
 * Included by hub.bpf.c and hub.c; keep it BPF-safe (fixed-width ints only).
 */
#ifndef __USBTRACE_MOD_HUB_H
#define __USBTRACE_MOD_HUB_H

#include "usbtrace/common.h"

enum hub_action {
	HUB_RESET = 0,		/* hub_port_reset */
	HUB_DISABLE = 1,	/* hub_port_disable */
	HUB_POWER_OFF = 2,	/* usb_hub_set_port_power(..., false) */
	HUB_POWER_ON = 3,	/* usb_hub_set_port_power(..., true) */
	HUB_OVERCURRENT = 4,	/* port_over_current_notify */
};

/* One record per hub-port decision. */
struct hub_event {
	struct usbtrace_event_hdr hdr;

	__u32 pid;
	__u32 oc_count;	  /* over_current_count when action is OVERCURRENT */

	__u16 vid;
	__u16 product;
	__u16 busnum;
	__u16 devnum;

	__u8 action;	  /* enum hub_action */
	__u8 speed;
	__u8 portnum;
	__u8 warm;	  /* 1 = USB3 warm (BH) reset */

	char devpath[16];
	char comm[USBTRACE_COMM_LEN];
};

struct hub_config {
	__u16 filter_vid;
	__u16 filter_pid;
};

#endif /* __USBTRACE_MOD_HUB_H */

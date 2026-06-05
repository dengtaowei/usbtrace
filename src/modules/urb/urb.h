/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared types for the "urb" module. Included by both urb.bpf.c (kernel) and
 * urb.c (user space), so keep it dependency-free (fixed-width ints only).
 */
#ifndef __USBTRACE_MOD_URB_H
#define __USBTRACE_MOD_URB_H

#include "usbtrace/common.h"

/* One record per URB completion (and optionally per submission). */
struct urb_event {
	struct usbtrace_event_hdr hdr;

	__u64 latency_ns; /* submit -> complete; 0 for submit records */
	__u32 pid;	  /* tgid of submitter (best-effort) */
	__u32 length;	  /* transfer_buffer_length */
	__u32 actual;	  /* actual_length (complete only) */
	__s32 status;	  /* urb->status (complete only) */

	__u16 vid;
	__u16 product;
	__u16 busnum;
	__u16 devnum;

	__u8 ep;	  /* endpoint number */
	__u8 dir_in;	  /* 1 = IN (device->host), 0 = OUT */
	__u8 xfer_type;	  /* enum usbtrace_xfer_type */
	__u8 is_submit;	  /* 1 = submit, 0 = complete */

	char comm[USBTRACE_COMM_LEN];
};

/* Config pushed into the BPF program via .rodata before load. */
struct urb_config {
	__u16 filter_vid; /* 0 = any */
	__u16 filter_pid; /* 0 = any */
	__u8 emit_submit; /* also emit submission records */
	__u8 _pad[3];
};

#endif /* __USBTRACE_MOD_URB_H */

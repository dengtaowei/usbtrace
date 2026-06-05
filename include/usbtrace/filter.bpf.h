/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared BPF-side per-device filter for usbtrace modules.
 *
 * Include AFTER "vmlinux.h" in a .bpf.c. Provides a single CO-RE read of
 * idVendor/idProduct plus the (vid,pid) match used by every device-scoped
 * module, so the filter lives in one place.
 */
#ifndef __USBTRACE_FILTER_BPF_H
#define __USBTRACE_FILTER_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

/* Apply the (fvid,fpid) filter to a usb_device; 0 means "match any".
 * Returns 1 on match (filling vid_out/pid_out), 0 otherwise. */
static __always_inline int usbtrace_dev_match(struct usb_device *dev,
					      __u16 fvid, __u16 fpid,
					      __u16 *vid_out, __u16 *pid_out)
{
	__u16 vid = BPF_CORE_READ(dev, descriptor.idVendor);
	__u16 pid = BPF_CORE_READ(dev, descriptor.idProduct);

	if (fvid && vid != fvid)
		return 0;
	if (fpid && pid != fpid)
		return 0;
	*vid_out = vid;
	*pid_out = pid;
	return 1;
}

#endif /* __USBTRACE_FILTER_BPF_H */

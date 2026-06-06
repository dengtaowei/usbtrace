/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uvcvideo CO-RE stubs for driver-layer kprobes (module BTF tier).
 */
#ifndef __USBTRACE_UVC_BPF_H
#define __USBTRACE_UVC_BPF_H

#include "usbtrace/vb2.bpf.h"

#define UVC_QUEUE_DROP_CORRUPTED	(1 << 1)
#define UVC_FMT_FLAG_COMPRESSED		0x00000001

struct uvc_device {
	struct usb_device *udev;
} __attribute__((preserve_access_index));

struct uvc_video_queue {
	struct vb2_queue queue;
	unsigned int flags;
} __attribute__((preserve_access_index));

struct uvc_streaming_control {
	__u32 dwMaxVideoFrameSize;
} __attribute__((preserve_access_index));

struct uvc_format {
	__u32 flags;
} __attribute__((preserve_access_index));

struct uvc_streaming {
	struct uvc_device *dev;
	struct uvc_streaming_control ctrl;
	const struct uvc_format *cur_format;
	struct uvc_video_queue queue;
} __attribute__((preserve_access_index));

struct uvc_buffer {
	struct vb2_v4l2_buffer buf;
	unsigned int error;
	unsigned int bytesused;
	struct kref ref;
} __attribute__((preserve_access_index));

struct uvc_urb {
	struct urb *urb;
	struct uvc_streaming *stream;
} __attribute__((preserve_access_index));

#endif /* __USBTRACE_UVC_BPF_H */

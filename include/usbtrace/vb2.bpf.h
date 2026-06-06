/* SPDX-License-Identifier: GPL-2.0 */
/*
 * videobuf2 types for uvc module BPF (module-BTF tier).
 *
 * Minimal CO-RE declarations for fields we read from struct vb2_buffer /
 * struct vb2_queue in videobuf2_common. Layout varies across kernels; only
 * access fields confirmed via module BTF (preserve_access_index relocates).
 */
#ifndef __USBTRACE_VB2_BPF_H
#define __USBTRACE_VB2_BPF_H

/* Matches enum vb2_buffer_state in <media/videobuf2-core.h>. */
enum vb2_buffer_state {
	VB2_BUF_STATE_DEQUEUED = 0,
	VB2_BUF_STATE_IN_REQUEST = 1,
	VB2_BUF_STATE_PREPARING = 2,
	VB2_BUF_STATE_QUEUED = 3,
	VB2_BUF_STATE_ACTIVE = 4,
	VB2_BUF_STATE_DONE = 5,
	VB2_BUF_STATE_ERROR = 6,
};

struct vb2_plane {
	void *mem_priv;
	void *dbuf;		/* struct dma_buf *; opaque here */
	unsigned int dbuf_mapped;
	unsigned int bytesused;
	unsigned int length;
} __attribute__((preserve_access_index));

/* V4L2 buffer types we care about (capture, incl. MPLANE). */
#define VB2_TYPE_VIDEO_CAPTURE		1
#define VB2_TYPE_VIDEO_CAPTURE_MPLANE	9

typedef struct {
	int counter;
} vb2_atomic_t;

struct vb2_queue {
	void *drv_priv;
	unsigned int num_buffers;
	unsigned int queued_count;
	vb2_atomic_t owned_by_drv_count;
} __attribute__((preserve_access_index));

struct v4l2_timecode {
	__u32 type;
	__u32 flags;
	__u8 frames;
	__u8 seconds;
	__u8 minutes;
	__u8 hours;
	__u8 userbits[4];
} __attribute__((preserve_access_index));

struct vb2_buffer {
	struct vb2_queue *vb2_queue;
	unsigned int index;
	unsigned int type;
	unsigned int memory;
	unsigned int num_planes;
	__u64 timestamp;
	struct vb2_plane planes[8];
} __attribute__((preserve_access_index));

/* videobuf2-v4l2: raw_tp passes struct vb2_buffer * = &vbuf->vb2_buf */
struct vb2_v4l2_buffer {
	struct vb2_buffer vb2_buf;
	__u32 flags;
	__u32 field;
	struct v4l2_timecode timecode;
	__u32 sequence;
} __attribute__((preserve_access_index));

#endif /* __USBTRACE_VB2_BPF_H */

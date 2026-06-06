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

struct vb2_queue;

struct vb2_buffer {
	struct vb2_queue *vb2_queue;
	unsigned int index;
	unsigned int type;
	unsigned int memory;
	unsigned int num_planes;
	__u64 timestamp;
	/* sequence lives in vb2_v4l2_buffer on 5.15, not vb2_buffer; PR-1 uses
	 * per-queue done_count instead (PR-2 may read kernel seq via tracepoint).
	 */
	struct vb2_plane planes[8];
} __attribute__((preserve_access_index));

#endif /* __USBTRACE_VB2_BPF_H */

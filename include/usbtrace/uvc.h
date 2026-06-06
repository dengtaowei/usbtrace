/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uvc-specific event model (frame-level diagnosis).
 *
 * The uvc module emits record kinds on its one ring buffer:
 *   - struct class_urb_event (hdr.kind = USBTRACE_EVT_CLASS)  -- per-URB isoc
 *     transfer health, shared with uac/hid/storage (see class.h).
 *   - struct uvc_frame_event (hdr.kind = USBTRACE_EVT_UVC_FRAME) -- one record
 *     per assembled video frame, reconstructed in BPF from the UVC payload
 *     headers carried in each isoc packet. This is the "depth" layer that the
 *     shared class record cannot express (real FPS, frame drops, PTS/SCR).
 *   - struct uvc_vb2_event (hdr.kind = USBTRACE_EVT_UVC_VB2) -- one record per
 *     videobuf2 buffer completion (stage 3); see Phase D in docs/uvc.md.
 *
 * This split is the intended extensibility pattern: a class module rides the
 * shared foundation for basic health AND may add its own richer event without
 * touching the shared struct (so uac/hid/storage are unaffected).
 *
 * BPF-safe: fixed-width ints only; included from both .bpf.c and user space.
 */
#ifndef __USBTRACE_UVC_H
#define __USBTRACE_UVC_H

#include "usbtrace/common.h"

/*
 * One reconstructed UVC video frame. `errored` is set when the frame ended
 * without a clean EOF (FID toggled mid-frame) or any contributing isoc packet
 * had an error / the UVC ERR bit. `interval_ns` (previous frame end -> this
 * frame end) is the FPS source; `pts`/`scr_stc` enable latency/jitter analysis.
 */
struct uvc_frame_event {
	struct usbtrace_event_hdr hdr;	/* kind = USBTRACE_EVT_UVC_FRAME */

	__u32 bytes;		/* payload bytes in this frame (excludes headers) */
	__u32 packets;		/* isoc packets that carried this frame */
	__u32 err_packets;	/* of those, how many had errors */
	__u32 duration_ns;	/* first -> last payload of this frame */
	__u32 interval_ns;	/* previous frame end -> this frame end (0 = first) */
	__u32 pts;		/* dwPresentationTime (90 kHz), 0 if absent */
	__u32 scr_stc;		/* SCR source time clock, 0 if absent */
	__u16 scr_sof;		/* SCR SOF token */

	__u16 vid;
	__u16 product;
	__u16 busnum;
	__u16 devnum;

	__u8 ep;
	__u8 errored;		/* 1 = dropped/corrupt (no clean EOF or pkt error) */
	__u8 eof;		/* 1 = ended on a clean End-of-Frame */
	__u8 fid;		/* UVC frame-id toggle bit */

	char comm[USBTRACE_COMM_LEN];
};

/* vb2 ring-buffer record subtype (hdr.kind is always USBTRACE_EVT_UVC_VB2). */
enum uvc_vb2_op {
	UVC_VB2_DONE = 0,
	UVC_VB2_QUEUE = 1,	/* driver took buffer from queued list (ACTIVE) */
	UVC_VB2_QBUF = 2,	/* userspace VIDIOC_QBUF */
	UVC_VB2_DQBUF = 3,	/* userspace VIDIOC_DQBUF */
	UVC_VB2_STARVED = 4,	/* wire frame arrived, no queued buffer for driver */
};

/*
 * One videobuf2 buffer transition (stage 3). `sequence` is the kernel
 * vb2_v4l2_buffer.sequence when module BTF allows CO-RE; otherwise a per-queue
 * delivery ordinal. `seq_gap` is 1 when kernel sequence jumped (authoritative
 * vb2-side drop). `interval_ns` drives vb2-side FPS (prev done -> this done).
 *
 * `queued` / `drv_owned` / `num_buffers` are snapshots from struct vb2_queue
 * (queued_count / owned_by_drv_count / num_buffers) for buffer-pool accounting.
 */
struct uvc_vb2_event {
	struct usbtrace_event_hdr hdr;	/* kind = USBTRACE_EVT_UVC_VB2 */

	__u32 sequence;
	__u32 bytesused;
	__u64 vb2_timestamp;
	__u8  state;		/* enum vb2_buffer_state at completion */
	__u32 interval_ns;
	__u8  buf_index;	/* vb2_buffer->index */
	__u8  seq_gap;		/* 1 = kernel sequence != last + 1 (see PR-2) */
	__u8  vb2_op;		/* enum uvc_vb2_op */
	__u8  starved;		/* 1 = driver had no queued buffer (pool starved) */
	__u16 num_buffers;	/* queue pool size */
	__u16 queued;		/* queued_count: ready for driver */
	__u16 drv_owned;	/* owned_by_drv_count: driver filling */
	__u32 wire_to_vb2_ns;	/* recent wire EOF -> this vb2 done (0 = none) */

	__u16 vid;		/* filled from stream_corr when wire-correlated */
	__u16 product;
	__u16 busnum;
	__u16 devnum;

	char comm[USBTRACE_COMM_LEN];
};

/*
 * uvc BPF config (.rodata). Layout-compatible PREFIX with
 * struct usbtrace_class_config (filter_vid, filter_pid) so diag's generic
 * class-source setup can set the filter through a usbtrace_class_config*.
 *
 * `no_frames` / `no_vb2` are inverted on purpose: 0 (default) means emit frame
 * / vb2 events; the standalone module disables via --no-frames / --no-vb2.
 */
struct uvc_config {
	__u16 filter_vid;	/* 0 = any */
	__u16 filter_pid;	/* 0 = any */
	__u8 no_frames;		/* 1 = skip wire frame parsing (URB health only) */
	__u8 no_vb2;		/* 1 = skip vb2 tracepoint (wire layer only) */
	__u16 _pad;
	__u32 fps_target;	/* informational; <=0 = off (used user-side) */
};

#endif /* __USBTRACE_UVC_H */

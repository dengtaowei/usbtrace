/* SPDX-License-Identifier: GPL-2.0 */
/*
 * uvc-specific event model (frame-level diagnosis).
 *
 * The uvc module emits TWO record kinds on its one ring buffer:
 *   - struct class_urb_event (hdr.kind = USBTRACE_EVT_CLASS)  -- per-URB isoc
 *     transfer health, shared with uac/hid/storage (see class.h).
 *   - struct uvc_frame_event (hdr.kind = USBTRACE_EVT_UVC_FRAME) -- one record
 *     per assembled video frame, reconstructed in BPF from the UVC payload
 *     headers carried in each isoc packet. This is the "depth" layer that the
 *     shared class record cannot express (real FPS, frame drops, PTS/SCR).
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

/*
 * uvc BPF config (.rodata). Layout-compatible PREFIX with
 * struct usbtrace_class_config (filter_vid, filter_pid) so diag's generic
 * class-source setup can set the filter through a usbtrace_class_config*.
 *
 * `no_frames` is inverted on purpose: 0 (default) means parse frames, so diag
 * gets frame events without special-casing uvc; the standalone module turns it
 * on via --no-frames.
 */
struct uvc_config {
	__u16 filter_vid;	/* 0 = any */
	__u16 filter_pid;	/* 0 = any */
	__u8 no_frames;		/* 1 = skip Tier-1 payload parsing (URB health only) */
	__u8 _pad[3];
	__u32 fps_target;	/* informational; <=0 = off (used user-side) */
};

#endif /* __USBTRACE_UVC_H */

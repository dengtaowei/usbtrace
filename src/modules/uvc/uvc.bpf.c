// SPDX-License-Identifier: GPL-2.0
/*
 * uvc module BPF program (USB Video Class) — frame-level diagnosis.
 *
 * Hook: uvc_video_complete(struct urb *urb), the uvcvideo streaming URB
 * completion every isoc video URB funnels through. From the one URB we produce:
 *
 *   1. struct class_urb_event  -- per-URB isoc transfer health (shared with
 *      uac/hid/storage via usbtrace_class_urb_emit; see class.h).
 *   2. struct uvc_frame_event  -- reconstructed video frames, by walking the
 *      isoc packet descriptors and parsing the UVC payload header in each
 *      packet (FID/EOF/ERR + PTS/SCR). This yields real FPS, frame drops and
 *      timestamp jitter.
 *
 * CO-RE only: we read struct urb / usb_iso_packet_descriptor (both in vmlinux
 * BTF) and the payload bytes via bpf_probe_read_kernel; no uvcvideo module BTF.
 * Descriptor addresses use bpf_core_field_offset (not a hardcoded offset) so the
 * flexible-array access stays portable across kernels. See docs/class.md.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/class_urb.bpf.h"
#include "usbtrace/uvc.h"

char LICENSE[] SEC("license") = "GPL";

const volatile struct uvc_config cfg = {};

/* Isoc URBs for UVC carry up to ~32 packets; bound the loop for the verifier. */
#define UVC_MAX_ISOC_PKTS 32
/* UVC payload header bmHeaderInfo (byte 1) bits. */
#define UVC_FID 0x01
#define UVC_EOF 0x02
#define UVC_PTS 0x04
#define UVC_SCR 0x08
#define UVC_ERR 0x40

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Per-stream (bus,dev,ep) frame-assembly state. */
struct uvc_stream_state {
	__u64 frame_start_ts;
	__u64 last_frame_end_ts;
	__u32 cur_bytes;
	__u32 cur_packets;
	__u32 cur_err_packets;
	__u32 cur_pts;
	__u32 cur_scr_stc;
	__u16 cur_scr_sof;
	__u8 cur_fid;
	__u8 have_fid;
	__u8 saw_err;
	__u8 active;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct uvc_stream_state);
} streams SEC(".maps");

static __always_inline __u32 le32(const __u8 *p)
{
	return (__u32)p[0] | ((__u32)p[1] << 8) | ((__u32)p[2] << 16) |
	       ((__u32)p[3] << 24);
}
static __always_inline __u16 le16(const __u8 *p)
{
	return (__u16)p[0] | ((__u16)p[1] << 8);
}

static __always_inline void
uvc_emit_frame(struct uvc_stream_state *st, __u8 eof, __u16 vid, __u16 pid,
	       __u16 bus, __u16 dev, __u8 ep, __u64 now)
{
	struct uvc_frame_event *fe;

	fe = bpf_ringbuf_reserve(&events, sizeof(*fe), 0);
	if (fe) {
		__builtin_memset(fe, 0, sizeof(*fe));
		fe->hdr.kind = USBTRACE_EVT_UVC_FRAME;
		fe->hdr.size = sizeof(*fe);
		fe->hdr.ts_ns = now;
		fe->bytes = st->cur_bytes;
		fe->packets = st->cur_packets;
		fe->err_packets = st->cur_err_packets;
		fe->duration_ns = (__u32)(now - st->frame_start_ts);
		fe->interval_ns = st->last_frame_end_ts ?
			(__u32)(now - st->last_frame_end_ts) : 0;
		fe->pts = st->cur_pts;
		fe->scr_stc = st->cur_scr_stc;
		fe->scr_sof = st->cur_scr_sof;
		fe->errored = (!eof || st->saw_err) ? 1 : 0;
		fe->eof = eof;
		fe->fid = st->cur_fid;
		fe->vid = vid;
		fe->product = pid;
		fe->busnum = bus;
		fe->devnum = dev;
		fe->ep = ep;
		bpf_get_current_comm(&fe->comm, sizeof(fe->comm));
		bpf_ringbuf_submit(fe, 0);
	}

	/* reset for the next frame; keep last_frame_end_ts for interval */
	st->last_frame_end_ts = now;
	st->cur_bytes = 0;
	st->cur_packets = 0;
	st->cur_err_packets = 0;
	st->cur_pts = 0;
	st->cur_scr_stc = 0;
	st->cur_scr_sof = 0;
	st->saw_err = 0;
	st->active = 0;
}

static __always_inline void uvc_parse_frames(struct urb *urb)
{
	struct uvc_stream_state init = {};
	struct uvc_stream_state *st;
	struct usb_device *dev;
	__u16 vid = 0, pid = 0, bus, devnum;
	__u32 key, tblen, pipe;
	__u64 descs_off, now;
	void *tbuf;
	int npkts, i;
	__u8 ep;

	dev = BPF_CORE_READ(urb, dev);
	if (!usbtrace_dev_match(dev, cfg.filter_vid, cfg.filter_pid, &vid, &pid))
		return;

	pipe = BPF_CORE_READ(urb, pipe);
	ep = (pipe >> 15) & 0xf;
	bus = BPF_CORE_READ(dev, bus, busnum);
	devnum = BPF_CORE_READ(dev, devnum);
	key = ((__u32)bus << 16) | ((__u32)devnum << 8) | ep;

	st = bpf_map_lookup_elem(&streams, &key);
	if (!st) {
		bpf_map_update_elem(&streams, &key, &init, BPF_ANY);
		st = bpf_map_lookup_elem(&streams, &key);
		if (!st)
			return;
	}

	npkts = BPF_CORE_READ(urb, number_of_packets);
	tbuf = BPF_CORE_READ(urb, transfer_buffer);
	tblen = BPF_CORE_READ(urb, transfer_buffer_length);
	descs_off = bpf_core_field_offset(struct urb, iso_frame_desc);
	now = bpf_ktime_get_ns();
	if (!tbuf)
		return;

	for (i = 0; i < UVC_MAX_ISOC_PKTS; i++) {
		struct usb_iso_packet_descriptor d;
		__u8 hdr[12];
		__u8 hlen, bfh, fid;
		__u32 off, pbytes;

		if (i >= npkts)
			break;

		if (bpf_probe_read_kernel(&d, sizeof(d),
					  (char *)urb + descs_off +
						  (__u64)i * sizeof(d)))
			continue;

		if (d.status) {
			st->saw_err = 1;
			st->cur_err_packets++;
		}
		if (d.actual_length == 0)
			continue; /* empty packet between frames: normal */

		off = d.offset;
		if (off + 2 > tblen)
			continue;
		/* Read the header; full 12 bytes when the buffer has room (for
		 * PTS/SCR), otherwise just the 2 flag bytes. */
		__builtin_memset(hdr, 0, sizeof(hdr));
		if (off + 12 <= tblen) {
			if (bpf_probe_read_kernel(hdr, 12, (char *)tbuf + off))
				continue;
		} else {
			if (bpf_probe_read_kernel(hdr, 2, (char *)tbuf + off))
				continue;
		}

		hlen = hdr[0];
		bfh = hdr[1];
		if (hlen < 2 || hlen > d.actual_length)
			continue; /* not a well-formed payload header */
		fid = bfh & UVC_FID;

		if (!st->active) {
			st->active = 1;
			st->have_fid = 1;
			st->cur_fid = fid;
			st->frame_start_ts = now;
		} else if (st->have_fid && fid != st->cur_fid) {
			/* FID toggled without a prior EOF: previous frame lost
			 * its end -> emit it as errored, then start fresh. */
			uvc_emit_frame(st, 0, vid, pid, bus, devnum, ep, now);
			st->active = 1;
			st->have_fid = 1;
			st->cur_fid = fid;
			st->frame_start_ts = now;
		}

		pbytes = d.actual_length - hlen;
		st->cur_bytes += pbytes;
		st->cur_packets++;
		if (bfh & UVC_ERR)
			st->saw_err = 1;

		if ((bfh & UVC_PTS) && hlen >= 6)
			st->cur_pts = le32(&hdr[2]);
		if ((bfh & UVC_PTS) && (bfh & UVC_SCR) && hlen >= 12) {
			st->cur_scr_stc = le32(&hdr[6]);
			st->cur_scr_sof = le16(&hdr[10]);
		}

		if (bfh & UVC_EOF)
			uvc_emit_frame(st, 1, vid, pid, bus, devnum, ep, now);
	}
}

SEC("kprobe/uvc_video_complete")
int BPF_KPROBE(on_video_complete, struct urb *urb)
{
	if (!urb)
		return 0;
	/* Per-URB transfer health (shared class record). */
	usbtrace_class_urb_emit(&events, urb, cfg.filter_vid, cfg.filter_pid,
				USBTRACE_CLASS_VIDEO);
	/* Per-frame reconstruction (uvc-specific). */
	if (!cfg.no_frames)
		uvc_parse_frames(urb);
	return 0;
}

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
 * Wire layer (stages 1–2): CO-RE on struct urb / usb_iso_packet_descriptor
 * (vmlinux BTF) and payload bytes via bpf_probe_read_kernel.
 *
 * vb2 layer (stage 3, Phase D): raw_tracepoint on vb2_buf_done (6.x) or
 * vb2_v4l2_buf_done (5.15) passes struct vb2_buffer *; fields read via
 * module BTF (videobuf2_common). Disabled when cfg.no_vb2 or when
 * usbtrace_autoload_filter() skips the absent tracepoint.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "usbtrace/class_urb.bpf.h"
#include "usbtrace/vb2.bpf.h"
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

/* --- stage 3: videobuf2 (Phase D PR-1) ------------------------------------ */

#define VB2_MIN_BYTES  100000u	/* drop tiny virtual_video noise */
#define VB2_MAX_BYTES  (32u * 1024u * 1024u)

struct vb2_qstate {
	__u32 done_count;	/* delivery ordinal when kernel sequence absent */
	__u64 last_done_ns;
	__u32 last_sequence;	/* previous kernel vb2 sequence (PR-2) */
	__u8  have_last_seq;
	__u8  _pad[3];
};

/* Kernel vb2_v4l2_buffer.sequence via embedded vb2_buf pointer (module BTF). */
static __always_inline __u32 vb2_kernel_sequence(struct vb2_buffer *b, __u8 *ok)
{
	struct vb2_v4l2_buffer *vbuf;
	__u64 off;

	*ok = 0;
	if (!b)
		return 0;
	off = bpf_core_field_offset(struct vb2_v4l2_buffer, vb2_buf);
	if ((long)off < 0)
		return 0;
	vbuf = (struct vb2_v4l2_buffer *)((char *)b - off);
	*ok = 1;
	return BPF_CORE_READ(vbuf, sequence);
}

static __always_inline __u8 vb2_seq_gap(__u32 last, __u32 cur)
{
	__u32 expected;

	if (cur == last)
		return 0;
	expected = last + 1;
	if (last == 0xffffffff)
		expected = 0;
	return cur != expected;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);	/* vb2_queue * */
	__type(value, struct vb2_qstate);
} vb2_queues SEC(".maps");

/* Wire EOF -> vb2 done correlation (PR-3). Key 0 = last wire frame globally. */
#define WIRE_VB2_MAX_NS 100000000ULL	/* 100ms pairing window */

struct stream_corr {
	__u64 last_wire_done_ns;
	__u32 last_wire_bytes;
	__u16 vid;
	__u16 pid;
	__u16 busnum;
	__u16 devnum;
	__u32 _pad;	/* 24-byte map value for verifier */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);	/* 0 global, or (bus << 16) | devnum */
	__type(value, struct stream_corr);
} stream_corr SEC(".maps");

static __always_inline __u32 uvc_wire_to_vb2_ns(__u64 now, __u32 bytesused)
{
	struct stream_corr *corr;
	__u32 key = 0;
	__u64 delta;

	corr = bpf_map_lookup_elem(&stream_corr, &key);
	if (!corr || !corr->last_wire_done_ns || !bytesused)
		return 0;
	if (bytesused != corr->last_wire_bytes)
		return 0;
	delta = now - corr->last_wire_done_ns;
	if (delta > WIRE_VB2_MAX_NS)
		return 0;
	return (__u32)delta;
}

static __always_inline void uvc_corr_store(__u32 key, __u16 vid, __u16 pid,
					   __u16 bus, __u16 devnum,
					   __u32 bytes, __u64 now)
{
	struct stream_corr init = {}, *c;

	bpf_map_update_elem(&stream_corr, &key, &init, BPF_ANY);
	c = bpf_map_lookup_elem(&stream_corr, &key);
	if (!c)
		return;
	c->last_wire_done_ns = now;
	c->last_wire_bytes = bytes;
	c->vid = vid;
	c->pid = pid;
	c->busnum = bus;
	c->devnum = devnum;
}

static __always_inline void uvc_note_wire_frame(__u16 bus, __u16 devnum,
						__u16 vid, __u16 pid,
						__u32 bytes, __u64 now)
{
	__u32 gkey = 0, devkey = ((__u32)bus << 16) | devnum;

	uvc_corr_store(gkey, vid, pid, bus, devnum, bytes, now);
	uvc_corr_store(devkey, vid, pid, bus, devnum, bytes, now);
}

static __always_inline void uvc_vb2_fill_device(struct uvc_vb2_event *ve,
						__u64 now)
{
	struct stream_corr *corr;
	__u32 key = 0;
	__u64 delta;

	corr = bpf_map_lookup_elem(&stream_corr, &key);
	if (!corr || !corr->last_wire_done_ns)
		return;
	delta = now - corr->last_wire_done_ns;
	if (delta > WIRE_VB2_MAX_NS)
		return;
	ve->vid = corr->vid;
	ve->product = corr->pid;
	ve->busnum = corr->busnum;
	ve->devnum = corr->devnum;
}

static __always_inline void uvc_emit_vb2(struct vb2_buffer *b, __u8 state)
{
	struct vb2_qstate init = {}, *st;
	struct vb2_queue *q;
	struct uvc_vb2_event *ve;
	__u64 now, key;
	__u32 bytesused, seq, interval = 0;
	__u8 kernel_seq_ok = 0, seq_gap = 0;

	if (state != VB2_BUF_STATE_DONE)
		return;

	bytesused = BPF_CORE_READ(b, planes[0].bytesused);
	if (bytesused && (bytesused < VB2_MIN_BYTES || bytesused > VB2_MAX_BYTES))
		return;

	q = BPF_CORE_READ(b, vb2_queue);
	if (!q)
		return;

	key = (__u64)(unsigned long)q;
	st = bpf_map_lookup_elem(&vb2_queues, &key);
	if (!st) {
		bpf_map_update_elem(&vb2_queues, &key, &init, BPF_ANY);
		st = bpf_map_lookup_elem(&vb2_queues, &key);
		if (!st)
			return;
	}

	now = bpf_ktime_get_ns();
	st->done_count++;
	seq = vb2_kernel_sequence(b, &kernel_seq_ok);
	if (kernel_seq_ok) {
		if (st->have_last_seq)
			seq_gap = vb2_seq_gap(st->last_sequence, seq);
		st->last_sequence = seq;
		st->have_last_seq = 1;
	} else {
		seq = st->done_count;
	}
	if (st->last_done_ns)
		interval = (__u32)(now - st->last_done_ns);
	st->last_done_ns = now;

	ve = bpf_ringbuf_reserve(&events, sizeof(*ve), 0);
	if (!ve)
		return;
	__builtin_memset(ve, 0, sizeof(*ve));
	ve->hdr.kind = USBTRACE_EVT_UVC_VB2;
	ve->hdr.size = sizeof(*ve);
	ve->hdr.ts_ns = now;
	ve->sequence = seq;
	ve->bytesused = bytesused;
	ve->vb2_timestamp = BPF_CORE_READ(b, timestamp);
	ve->state = state;
	ve->interval_ns = interval;
	ve->buf_index = (__u8)BPF_CORE_READ(b, index);
	ve->seq_gap = seq_gap;
	ve->wire_to_vb2_ns = uvc_wire_to_vb2_ns(now, bytesused);
	uvc_vb2_fill_device(ve, now);
	bpf_get_current_comm(&ve->comm, sizeof(ve->comm));
	bpf_ringbuf_submit(ve, 0);
}

/*
 * TP_PROTO(struct vb2_queue *q, struct vb2_buffer *vb) on both kernels; only
 * one tracepoint name exists per kernel generation (probe skips the other).
 */
static __always_inline int uvc_vb2_raw_done(struct bpf_raw_tracepoint_args *ctx)
{
	struct vb2_buffer *b;

	if (cfg.no_vb2 || !ctx)
		return 0;
	b = (struct vb2_buffer *)ctx->args[1];
	if (!b)
		return 0;
	uvc_emit_vb2(b, VB2_BUF_STATE_DONE);
	return 0;
}

SEC("raw_tracepoint/vb2_v4l2_buf_done")
int raw_vb2_v4l2_buf_done(struct bpf_raw_tracepoint_args *ctx)
{
	return uvc_vb2_raw_done(ctx);
}

SEC("raw_tracepoint/vb2_buf_done")
int raw_vb2_buf_done(struct bpf_raw_tracepoint_args *ctx)
{
	return uvc_vb2_raw_done(ctx);
}

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
		uvc_note_wire_frame(bus, dev, vid, pid, st->cur_bytes, now);
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

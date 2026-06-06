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
#include "usbtrace/filter.bpf.h"
#include "usbtrace/vb2.bpf.h"
#include "usbtrace/uvc.bpf.h"
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
	__u64 last_starve_ns;	/* anti-spam for starvation events */
	__u32 last_sequence;	/* previous kernel vb2 sequence (PR-2) */
	__u8  have_last_seq;
	__u8  _pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);	/* (bus << 16) | devnum */
	__type(value, __u64);	/* vb2_queue * */
} vb2_dev_queue SEC(".maps");

#define VB2_STARVE_COOLDOWN_NS 100000000ULL	/* 100ms between starve emits */

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

static __always_inline __u8 vb2_is_capture(struct vb2_buffer *b)
{
	__u32 type;

	if (!b)
		return 0;
	type = BPF_CORE_READ(b, type);
	return type == VB2_TYPE_VIDEO_CAPTURE ||
	       type == VB2_TYPE_VIDEO_CAPTURE_MPLANE;
}

static __always_inline void vb2_read_pool(struct vb2_queue *q,
					  __u16 *num_buffers, __u16 *queued,
					  __u16 *drv_owned)
{
	__u32 nb, qc;
	int owned;

	if (!q) {
		*num_buffers = 0;
		*queued = 0;
		*drv_owned = 0;
		return;
	}
	nb = BPF_CORE_READ(q, num_buffers);
	qc = BPF_CORE_READ(q, queued_count);
	owned = BPF_CORE_READ(q, owned_by_drv_count.counter);
	*num_buffers = (__u16)nb;
	*queued = (__u16)qc;
	*drv_owned = (__u16)owned;
}

static __always_inline struct vb2_qstate *uvc_vb2_qstate(__u64 key)
{
	struct vb2_qstate init = {}, *st;

	st = bpf_map_lookup_elem(&vb2_queues, &key);
	if (st)
		return st;
	bpf_map_update_elem(&vb2_queues, &key, &init, BPF_ANY);
	return bpf_map_lookup_elem(&vb2_queues, &key);
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

static __always_inline void uvc_vb2_bind_dev(struct vb2_queue *q,
					   __u16 bus, __u16 dev)
{
	__u32 dkey = ((__u32)bus << 16) | dev;
	__u64 qkey = (__u64)(unsigned long)q;

	if (!bus && !dev)
		return;
	bpf_map_update_elem(&vb2_dev_queue, &dkey, &qkey, BPF_ANY);
}

static __always_inline void uvc_vb2_submit(struct vb2_queue *q,
					 struct vb2_buffer *b, __u8 op,
					 __u8 state, __u8 starved, __u64 now,
					 __u32 seq, __u8 seq_gap,
					 __u32 interval, __u32 wire_to_vb2_ns)
{
	struct uvc_vb2_event *ve;
	__u16 nb = 0, qu = 0, drv = 0;
	__u32 bytesused = 0;

	if (q)
		vb2_read_pool(q, &nb, &qu, &drv);
	if (b)
		bytesused = BPF_CORE_READ(b, planes[0].bytesused);

	ve = bpf_ringbuf_reserve(&events, sizeof(*ve), 0);
	if (!ve)
		return;
	__builtin_memset(ve, 0, sizeof(*ve));
	ve->hdr.kind = USBTRACE_EVT_UVC_VB2;
	ve->hdr.size = sizeof(*ve);
	ve->hdr.ts_ns = now;
	ve->vb2_op = op;
	ve->starved = starved;
	ve->num_buffers = nb;
	ve->queued = qu;
	ve->drv_owned = drv;
	ve->sequence = seq;
	ve->seq_gap = seq_gap;
	ve->interval_ns = interval;
	ve->wire_to_vb2_ns = wire_to_vb2_ns;
	ve->state = state;
	if (b) {
		ve->bytesused = bytesused;
		ve->vb2_timestamp = BPF_CORE_READ(b, timestamp);
		ve->buf_index = (__u8)BPF_CORE_READ(b, index);
	}
	uvc_vb2_fill_device(ve, now);
	if (ve->busnum || ve->devnum)
		uvc_vb2_bind_dev(q, ve->busnum, ve->devnum);
	bpf_get_current_comm(&ve->comm, sizeof(ve->comm));
	bpf_ringbuf_submit(ve, 0);
}

static __always_inline void uvc_check_starvation(__u16 bus, __u16 dev,
						 __u64 now)
{
	__u32 dkey = ((__u32)bus << 16) | dev;
	__u64 *qkeyp;
	struct vb2_queue *q;
	struct vb2_qstate *st;
	__u16 nb, qu, drv;

	if (!bus && !dev)
		return;
	qkeyp = bpf_map_lookup_elem(&vb2_dev_queue, &dkey);
	if (!qkeyp)
		return;
	q = (struct vb2_queue *)(unsigned long)*qkeyp;
	if (!q)
		return;
	vb2_read_pool(q, &nb, &qu, &drv);
	if (qu > 0)
		return;

	st = uvc_vb2_qstate(*qkeyp);
	if (!st)
		return;
	if (st->last_starve_ns &&
	    now - st->last_starve_ns < VB2_STARVE_COOLDOWN_NS)
		return;
	st->last_starve_ns = now;
	uvc_vb2_submit(q, NULL, UVC_VB2_STARVED, 0, 1, now, 0, 0, 0, 0);
}

static __always_inline void uvc_emit_vb2_done(struct vb2_buffer *b, __u8 state)
{
	struct vb2_qstate *st;
	struct vb2_queue *q;
	__u64 now, key;
	__u32 bytesused, seq, interval = 0, wire_to_vb2_ns = 0;
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
	st = uvc_vb2_qstate(key);
	if (!st)
		return;

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
	wire_to_vb2_ns = uvc_wire_to_vb2_ns(now, bytesused);
	uvc_vb2_submit(q, b, UVC_VB2_DONE, state, 0, now, seq, seq_gap,
			interval, wire_to_vb2_ns);
}

static __always_inline void uvc_emit_vb2_xact(struct vb2_queue *q,
					      struct vb2_buffer *b, __u8 op,
					      __u8 state)
{
	__u64 now = bpf_ktime_get_ns();

	if (!q || !b || !vb2_is_capture(b))
		return;
	uvc_vb2_submit(q, b, op, state, 0, now, 0, 0, 0, 0);
}

/*
 * TP_PROTO(struct vb2_queue *q, struct vb2_buffer *vb) on vb2 tracepoints.
 */
static __always_inline int uvc_vb2_raw_done(struct bpf_raw_tracepoint_args *ctx)
{
	struct vb2_buffer *b;

	if (cfg.no_vb2 || !ctx)
		return 0;
	b = (struct vb2_buffer *)ctx->args[1];
	if (!b)
		return 0;
	uvc_emit_vb2_done(b, VB2_BUF_STATE_DONE);
	return 0;
}

static __always_inline int uvc_vb2_raw_qvb(struct bpf_raw_tracepoint_args *ctx,
					   __u8 op, __u8 state)
{
	struct vb2_queue *q;
	struct vb2_buffer *b;

	if (cfg.no_vb2 || !ctx)
		return 0;
	q = (struct vb2_queue *)ctx->args[0];
	b = (struct vb2_buffer *)ctx->args[1];
	if (!q || !b)
		return 0;
	uvc_emit_vb2_xact(q, b, op, state);
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

SEC("raw_tracepoint/vb2_buf_queue")
int raw_vb2_buf_queue(struct bpf_raw_tracepoint_args *ctx)
{
	return uvc_vb2_raw_qvb(ctx, UVC_VB2_QUEUE, VB2_BUF_STATE_ACTIVE);
}

SEC("raw_tracepoint/vb2_qbuf")
int raw_vb2_qbuf(struct bpf_raw_tracepoint_args *ctx)
{
	return uvc_vb2_raw_qvb(ctx, UVC_VB2_QBUF, VB2_BUF_STATE_QUEUED);
}

SEC("raw_tracepoint/vb2_dqbuf")
int raw_vb2_dqbuf(struct bpf_raw_tracepoint_args *ctx)
{
	return uvc_vb2_raw_qvb(ctx, UVC_VB2_DQBUF, VB2_BUF_STATE_DEQUEUED);
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
		uvc_check_starvation(bus, dev, now);
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

/* --- uvcvideo driver: recv/drop counters only (module-BTF tier) ------------ */

static __always_inline __u8 uvc_buf_is_video(struct uvc_buffer *buf)
{
	__u32 type;

	if (!buf)
		return 0;
	type = BPF_CORE_READ(buf, buf.vb2_buf.type);
	return type == VB2_TYPE_VIDEO_CAPTURE ||
	       type == VB2_TYPE_VIDEO_CAPTURE_MPLANE;
}

static __always_inline int uvc_stream_usb(struct uvc_streaming *stream,
					  __u16 *vid, __u16 *pid,
					  __u16 *bus, __u16 *devnum)
{
	struct uvc_device *dev;
	struct usb_device *udev;

	if (!stream)
		return 0;
	dev = BPF_CORE_READ(stream, dev);
	if (!dev)
		return 0;
	udev = BPF_CORE_READ(dev, udev);
	if (!usbtrace_dev_match(udev, cfg.filter_vid, cfg.filter_pid, vid, pid))
		return 0;
	*bus = BPF_CORE_READ(udev, bus, busnum);
	*devnum = BPF_CORE_READ(udev, devnum);
	return 1;
}

static __always_inline struct uvc_buffer *uvc_buf_from_ref(struct kref *ref)
{
	__u64 off;

	if (!ref)
		return NULL;
	off = bpf_core_field_offset(struct uvc_buffer, ref);
	if ((long)off < 0)
		return NULL;
	return (struct uvc_buffer *)((char *)ref - off);
}

static __always_inline struct uvc_video_queue *
uvc_buf_video_queue(struct uvc_buffer *buf)
{
	struct vb2_v4l2_buffer *vbuf;
	struct vb2_buffer *vb;
	struct vb2_queue *vq;
	__u64 off;

	if (!buf)
		return NULL;
	off = bpf_core_field_offset(struct uvc_buffer, buf);
	if ((long)off < 0)
		return NULL;
	vbuf = (struct vb2_v4l2_buffer *)((char *)buf + off);
	off = bpf_core_field_offset(struct vb2_v4l2_buffer, vb2_buf);
	if ((long)off < 0)
		return NULL;
	vb = (struct vb2_buffer *)((char *)vbuf + off);
	vq = BPF_CORE_READ(vb, vb2_queue);
	if (!vq)
		return NULL;
	return (struct uvc_video_queue *)BPF_CORE_READ(vq, drv_priv);
}

/* Per-buffer error cause, set at the decode source, read+cleared at complete.
 * Key = (u64)uvc_buffer*; value = UVC_DROP_* bits gathered before complete. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u64);
	__type(value, __u8);
} drv_drop_cause SEC(".maps");

static __always_inline void uvc_drop_cause_add(struct uvc_buffer *buf, __u8 bit)
{
	__u64 key = (__u64)(unsigned long)buf;
	__u8 *cur, init;

	cur = bpf_map_lookup_elem(&drv_drop_cause, &key);
	if (cur) {
		*cur |= bit;
		return;
	}
	init = bit;
	bpf_map_update_elem(&drv_drop_cause, &key, &init, BPF_ANY);
}

static __always_inline __u8 uvc_drop_cause_take(struct uvc_buffer *buf)
{
	__u64 key = (__u64)(unsigned long)buf;
	__u8 *cur, val = 0;

	cur = bpf_map_lookup_elem(&drv_drop_cause, &key);
	if (cur) {
		val = *cur;
		bpf_map_delete_elem(&drv_drop_cause, &key);
	}
	return val;
}

static __always_inline void uvc_drv_emit(__u8 op, __u8 reason, __u16 vid,
					 __u16 pid, __u16 bus, __u16 devnum,
					 __u64 now)
{
	struct uvc_drv_event *de;

	de = bpf_ringbuf_reserve(&events, sizeof(*de), 0);
	if (!de)
		return;
	__builtin_memset(de, 0, sizeof(*de));
	de->hdr.kind = USBTRACE_EVT_UVC_DRV;
	de->hdr.size = sizeof(*de);
	de->hdr.ts_ns = now;
	de->drv_op = op;
	de->reason = reason;
	de->vid = vid;
	de->product = pid;
	de->busnum = bus;
	de->devnum = devnum;
	bpf_ringbuf_submit(de, 0);
}

/* Decode finished a video frame (uvc_video_decode_isoc/bulk path). */
SEC("kprobe/uvc_queue_next_buffer")
int BPF_KPROBE(on_queue_next, struct uvc_video_queue *queue,
	       struct uvc_buffer *buf)
{
	struct uvc_streaming *stream;
	__u16 vid = 0, pid = 0, bus = 0, devnum = 0;
	__u64 off, now;

	if (!queue || !buf || !uvc_buf_is_video(buf))
		return 0;

	off = bpf_core_field_offset(struct uvc_streaming, queue);
	if ((long)off < 0)
		return 0;
	stream = (struct uvc_streaming *)((char *)queue - off);
	if (!uvc_stream_usb(stream, &vid, &pid, &bus, &devnum))
		return 0;

	now = bpf_ktime_get_ns();
	uvc_drv_emit(UVC_DRV_RECV, 0, vid, pid, bus, devnum, now);
	return 0;
}

/*
 * Tag a buffer with UVC_DROP_ISO when this URB lost isoc packets, mirroring
 * uvc_video_decode_isoc(): iso_frame_desc[i].status < 0 -> buf->error = 1.
 * Runs once per URB; only touches the map when a loss is actually seen.
 */
SEC("kprobe/uvc_video_decode_isoc")
int BPF_KPROBE(on_decode_isoc, struct uvc_urb *uvc_urb, struct uvc_buffer *buf)
{
	struct urb *urb;
	struct uvc_streaming *stream;
	__u16 vid = 0, pid = 0, bus = 0, devnum = 0;
	__u64 descs_off;
	int npkts, i;

	if (!uvc_urb || !buf || !uvc_buf_is_video(buf))
		return 0;

	stream = BPF_CORE_READ(uvc_urb, stream);
	if (!uvc_stream_usb(stream, &vid, &pid, &bus, &devnum))
		return 0;

	urb = BPF_CORE_READ(uvc_urb, urb);
	if (!urb)
		return 0;
	npkts = BPF_CORE_READ(urb, number_of_packets);
	descs_off = bpf_core_field_offset(struct urb, iso_frame_desc);

	for (i = 0; i < UVC_MAX_ISOC_PKTS; i++) {
		struct usb_iso_packet_descriptor d;

		if (i >= npkts)
			break;
		if (bpf_probe_read_kernel(&d, sizeof(d),
					  (char *)urb + descs_off +
						  (__u64)i * sizeof(d)))
			continue;
		if ((int)d.status < 0) {
			uvc_drop_cause_add(buf, UVC_DROP_ISO);
			break;
		}
	}
	return 0;
}

/*
 * Frame drop decision: uvc_queue_buffer_complete() requeues when
 * DROP_CORRUPTED && buf->error (validate_buffer short, decode hdr/iso/ovf…).
 * Only runs as kref finalizer — not per async memcpy chunk.
 */
SEC("kprobe/uvc_queue_buffer_complete")
int BPF_KPROBE(on_queue_complete, struct kref *ref)
{
	struct uvc_buffer *buf;
	struct uvc_video_queue *queue;
	struct uvc_streaming *stream;
	const struct uvc_format *fmt;
	__u16 vid = 0, pid = 0, bus = 0, devnum = 0;
	__u64 off, now;
	__u32 qflags, bytesused, maxsize, fmtflags = 0;
	__u8 err, reason;

	buf = uvc_buf_from_ref(ref);
	if (!buf || !uvc_buf_is_video(buf)) {
		uvc_drop_cause_take(buf);	/* keep the map from leaking */
		return 0;
	}

	queue = uvc_buf_video_queue(buf);
	if (!queue) {
		uvc_drop_cause_take(buf);
		return 0;
	}

	off = bpf_core_field_offset(struct uvc_streaming, queue);
	if ((long)off < 0)
		return 0;
	stream = (struct uvc_streaming *)((char *)queue - off);
	if (!uvc_stream_usb(stream, &vid, &pid, &bus, &devnum)) {
		uvc_drop_cause_take(buf);
		return 0;
	}

	/* Pop any decode-time cause regardless, so requeued/good buffers that
	 * are reused don't carry stale bits into a later frame. */
	reason = uvc_drop_cause_take(buf);

	qflags = BPF_CORE_READ(queue, flags);
	err = (__u8)BPF_CORE_READ(buf, error);
	if (!(qflags & UVC_QUEUE_DROP_CORRUPTED) || !err)
		return 0;

	/* Short frame: matches kernel uvc_video_validate_buffer() (inlined). */
	bytesused = BPF_CORE_READ(buf, bytesused);
	maxsize = BPF_CORE_READ(stream, ctrl.dwMaxVideoFrameSize);
	fmt = BPF_CORE_READ(stream, cur_format);
	if (fmt)
		fmtflags = BPF_CORE_READ(fmt, flags);
	if (!(fmtflags & UVC_FMT_FLAG_COMPRESSED) && maxsize &&
	    bytesused != maxsize)
		reason |= UVC_DROP_SHORT;

	if (!reason)
		reason = UVC_DROP_OTHER;	/* header err bit / overflow / lost EOF */

	now = bpf_ktime_get_ns();
	uvc_drv_emit(UVC_DRV_DROP, reason, vid, pid, bus, devnum, now);
	return 0;
}

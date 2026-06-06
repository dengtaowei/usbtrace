// SPDX-License-Identifier: GPL-2.0
/*
 * uvc module user-space side (USB Video Class).
 *
 * Consumes three record kinds off the one ring buffer: shared class_urb_event
 * (per-URB transfer health), uvc_frame_event (wire-layer frames), and
 * uvc_vb2_event (videobuf2 buffer done, stage 3). The load/attach/poll lifecycle
 * is the shared usbtrace_run() harness.
 */
#include <stdio.h>
#include <stdbool.h>
#include <getopt.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "usbtrace/class_stream.h"
#include "usbtrace/uvc.h"
#include "uvc.skel.h"

static struct usbtrace_filter g_filt;
static struct class_stream_ctx g_ctx;	/* URB-health tally + --all */
static bool g_no_frames;
static bool g_no_vb2;
static unsigned int g_fps_target;
static struct uvc_bpf *g_skel;	/* for post-load hook-availability checks */

/* Frame-level running stats for the exit summary. */
static struct {
	unsigned long frames;	   /* frames seen */
	unsigned long errored;	   /* dropped/corrupt frames */
	unsigned long long bytes;  /* total frame payload bytes */
	unsigned long intervals;   /* frames with a measured interval */
	unsigned long long sum_interval_ns;
	unsigned int min_interval_ns;
	unsigned int max_interval_ns;
} g_fstats;

/* vb2 buffer-done running stats for the exit summary. */
static struct {
	unsigned long done;
	unsigned long seq_gaps;
	unsigned long starved;
	unsigned long wire_corr;
	unsigned long long bytes;
	unsigned long intervals;
	unsigned long long sum_interval_ns;
	unsigned long long sum_wire_to_vb2_ns;
	unsigned int min_interval_ns;
	unsigned int max_interval_ns;
} g_vbstats;

/* uvcvideo driver recv/drop (internal hooks; summary only). */
static struct {
	unsigned long received;
	unsigned long dropped;
	unsigned long drop_short;	/* size != dwMaxVideoFrameSize */
	unsigned long drop_iso;		/* isoc packet status < 0 */
	unsigned long drop_other;	/* header err bit / overflow / lost EOF */
} g_drvstats;

static const char *vb2_op_str(__u8 op)
{
	switch (op) {
	case UVC_VB2_QUEUE:	return "queue";
	case UVC_VB2_QBUF:	return "qbuf";
	case UVC_VB2_DQBUF:	return "dqbuf";
	case UVC_VB2_STARVED:	return "starve";
	default:		return "done";
	}
}

static void uvc_usage(void)
{
	fprintf(stderr,
		"usbtrace uvc - trace USB Video Class streaming + frame health\n\n"
		"Hooks uvc_video_complete and reports per-URB isoc health AND\n"
		"reconstructs video frames from UVC payload headers: real FPS,\n"
		"frame drops/corruption, frame size and PTS/SCR. Requires uvcvideo\n"
		"loaded and a UVC camera streaming.\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (e.g. 0x046d)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --all           print every URB and every frame (default:\n"
		"                  anomalies only)\n"
		"  --no-frames     URB transfer health only (skip frame parsing)\n"
		"  --no-vb2        skip vb2 buffer-done tracepoint (wire layer only)\n"
		"  --fps <n>       target fps; frames slower than this are flagged\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace uvc --all --vid 0x046d\n"
		"  sudo usbtrace uvc --fps 30 --vid 0x046d\n"
		"  sudo usbtrace --json uvc | jq\n");
}

static int uvc_parse_args(int argc, char **argv)
{
	static const struct option lo[] = {
		USBTRACE_FILTER_LONGOPTS,
		{ "all", no_argument, 0, 'a' },
		{ "no-frames", no_argument, 0, 'F' },
		{ "no-vb2", no_argument, 0, 'B' },
		{ "fps", required_argument, 0, 'f' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "ah", lo, NULL)) != -1) {
		if (usbtrace_filter_getopt(c, optarg, &g_filt))
			continue;
		switch (c) {
		case 'a':
			g_ctx.all = true;
			break;
		case 'F':
			g_no_frames = true;
			break;
		case 'B':
			g_no_vb2 = true;
			break;
		case 'f':
			g_fps_target = (unsigned int)strtoul(optarg, NULL, 0);
			break;
		case 'h':
			return 1;
		default:
			return -1;
		}
	}
	return 0;
}

static void tally_frame(const struct uvc_frame_event *e)
{
	g_fstats.frames++;
	g_fstats.bytes += e->bytes;
	if (e->errored)
		g_fstats.errored++;
	if (e->interval_ns) {
		g_fstats.intervals++;
		g_fstats.sum_interval_ns += e->interval_ns;
		if (!g_fstats.min_interval_ns ||
		    e->interval_ns < g_fstats.min_interval_ns)
			g_fstats.min_interval_ns = e->interval_ns;
		if (e->interval_ns > g_fstats.max_interval_ns)
			g_fstats.max_interval_ns = e->interval_ns;
	}
}

static double fps_of(unsigned int interval_ns)
{
	return interval_ns ? 1e9 / interval_ns : 0.0;
}

static int handle_frame(const struct uvc_frame_event *e, size_t len)
{
	bool slow, anomaly;

	if (len < sizeof(*e))
		return 0;
	tally_frame(e);

	slow = g_fps_target && e->interval_ns &&
	       fps_of(e->interval_ns) < (double)g_fps_target;
	anomaly = e->errored || slow;

	if (!g_ctx.all && !anomaly)
		return 0;

	if (usbtrace_json) {
		char comm[2 * USBTRACE_COMM_LEN + 1];

		printf("{\"event\":\"uvc_frame\",\"errored\":%u,\"eof\":%u,"
		       "\"bytes\":%u,\"packets\":%u,\"err_packets\":%u,"
		       "\"duration_us\":%.1f,\"interval_us\":%.1f,\"fps\":%.1f,"
		       "\"pts\":%u,\"scr_stc\":%u,\"vid\":\"0x%04x\","
		       "\"pid\":\"0x%04x\",\"bus\":%u,\"dev\":%u,\"comm\":\"%s\"}\n",
		       e->errored, e->eof, e->bytes, e->packets, e->err_packets,
		       e->duration_ns / 1000.0, e->interval_ns / 1000.0,
		       fps_of(e->interval_ns), e->pts, e->scr_stc, e->vid,
		       e->product, e->busnum, e->devnum,
		       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
	} else {
		printf("frame  %-4s %7uB pkts=%-3u dur=%5.1fms intv=%6.1fms "
		       "fps=%5.1f pts=%-10u %04x:%04x %u-%u %s\n",
		       e->errored ? "DROP" : "ok", e->bytes, e->packets,
		       e->duration_ns / 1e6, e->interval_ns / 1e6,
		       fps_of(e->interval_ns), e->pts, e->vid, e->product,
		       e->busnum, e->devnum, e->comm);
	}
	return 0;
}

static void tally_vb2(const struct uvc_vb2_event *e)
{
	if (e->vb2_op == UVC_VB2_DONE)
		g_vbstats.done++;
	if (e->seq_gap)
		g_vbstats.seq_gaps++;
	if (e->starved || e->vb2_op == UVC_VB2_STARVED)
		g_vbstats.starved++;
	if (e->wire_to_vb2_ns) {
		g_vbstats.wire_corr++;
		g_vbstats.sum_wire_to_vb2_ns += e->wire_to_vb2_ns;
	}
	if (e->vb2_op == UVC_VB2_DONE)
		g_vbstats.bytes += e->bytesused;
	if (e->vb2_op == UVC_VB2_DONE && e->interval_ns) {
		g_vbstats.intervals++;
		g_vbstats.sum_interval_ns += e->interval_ns;
		if (!g_vbstats.min_interval_ns ||
		    e->interval_ns < g_vbstats.min_interval_ns)
			g_vbstats.min_interval_ns = e->interval_ns;
		if (e->interval_ns > g_vbstats.max_interval_ns)
			g_vbstats.max_interval_ns = e->interval_ns;
	}
}

static int handle_vb2(const struct uvc_vb2_event *e, size_t len)
{
	if (len < sizeof(*e))
		return 0;
	tally_vb2(e);

	if (!g_ctx.all && !e->seq_gap && !e->starved &&
	    e->vb2_op != UVC_VB2_STARVED)
		return 0;

	if (usbtrace_json) {
		char comm[2 * USBTRACE_COMM_LEN + 1];

		printf("{\"event\":\"uvc_vb2\",\"op\":\"%s\",\"sequence\":%u,"
		       "\"seq_gap\":%u,\"starved\":%u,"
		       "\"num_buffers\":%u,\"queued\":%u,\"drv_owned\":%u,"
		       "\"bytesused\":%u,\"interval_us\":%.1f,\"fps\":%.1f,"
		       "\"wire_to_vb2_us\":%.1f,\"state\":%u,\"buf_index\":%u,"
		       "\"vb2_ts\":%llu,\"vid\":\"0x%04x\",\"pid\":\"0x%04x\","
		       "\"bus\":%u,\"dev\":%u,\"comm\":\"%s\"}\n",
		       vb2_op_str(e->vb2_op), e->sequence, e->seq_gap,
		       e->starved, e->num_buffers, e->queued, e->drv_owned,
		       e->bytesused, e->interval_ns / 1000.0,
		       fps_of(e->interval_ns), e->wire_to_vb2_ns / 1000.0,
		       e->state, e->buf_index,
		       (unsigned long long)e->vb2_timestamp,
		       e->vid, e->product, e->busnum, e->devnum,
		       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
	} else if (e->vb2_op == UVC_VB2_STARVED || e->starved) {
		printf("vb2    STARVE pool=%u q=%u drv=%u  "
		       "(wire frame, no queued buffer) %04x:%04x %u-%u\n",
		       e->num_buffers, e->queued, e->drv_owned,
		       e->vid, e->product, e->busnum, e->devnum);
	} else if (e->vb2_op != UVC_VB2_DONE) {
		printf("vb2    %-5s idx=%u pool=%u q=%u drv=%u %s\n",
		       vb2_op_str(e->vb2_op), e->buf_index, e->num_buffers,
		       e->queued, e->drv_owned, e->comm);
	} else {
		printf("vb2    %-4s seq=%-5u %7uB intv=%6.1fms fps=%5.1f "
		       "w2v=%5.1fms pool=%u q=%u drv=%u idx=%u %s\n",
		       e->seq_gap ? "GAP" : "ok", e->sequence, e->bytesused,
		       e->interval_ns / 1e6, fps_of(e->interval_ns),
		       e->wire_to_vb2_ns / 1e6, e->num_buffers, e->queued,
		       e->drv_owned, e->buf_index, e->comm);
	}
	return 0;
}

static void tally_drv(const struct uvc_drv_event *e)
{
	if (e->drv_op == UVC_DRV_RECV) {
		g_drvstats.received++;
	} else if (e->drv_op == UVC_DRV_DROP) {
		g_drvstats.dropped++;
		if (e->reason & UVC_DROP_SHORT)
			g_drvstats.drop_short++;
		if (e->reason & UVC_DROP_ISO)
			g_drvstats.drop_iso++;
		if (e->reason & UVC_DROP_OTHER)
			g_drvstats.drop_other++;
	}
}

static int handle_drv(const struct uvc_drv_event *e, size_t len)
{
	if (len < sizeof(*e))
		return 0;
	tally_drv(e);
	return 0;
}

/* Route by record kind: frames/vb2 here, URB-health to the shared class consumer. */
static int uvc_on_event(void *ctx, void *data, size_t len)
{
	const struct usbtrace_event_hdr *h = data;

	if (len < sizeof(*h))
		return 0;
	if (h->kind == USBTRACE_EVT_UVC_FRAME)
		return handle_frame(data, len);
	if (h->kind == USBTRACE_EVT_UVC_VB2)
		return handle_vb2(data, len);
	if (h->kind == USBTRACE_EVT_UVC_DRV)
		return handle_drv(data, len);
	return class_stream_on_event(ctx, data, len);
}

static void uvc_on_start(void)
{
	const char *mode = " + frames + vb2";

	if (g_no_frames && g_no_vb2)
		mode = " (URB health only)";
	else if (g_no_frames)
		mode = " + vb2";
	else if (g_no_vb2)
		mode = " + frames";

	ut_info("tracing UVC stream%s... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		mode, g_filt.vid, g_filt.pid);
}

static void uvc_frame_summary(void)
{
	double avg = g_fstats.intervals ?
		(double)g_fstats.sum_interval_ns / g_fstats.intervals : 0;

	if (usbtrace_json) {
		printf("{\"event\":\"uvc_frame_summary\",\"frames\":%lu,"
		       "\"errored\":%lu,\"bytes\":%llu,\"avg_fps\":%.1f,"
		       "\"min_fps\":%.1f,\"max_fps\":%.1f}\n",
		       g_fstats.frames, g_fstats.errored, g_fstats.bytes,
		       fps_of((unsigned int)avg), fps_of(g_fstats.max_interval_ns),
		       fps_of(g_fstats.min_interval_ns));
		return;
	}

	fprintf(stderr,
		"\n--- uvc frame summary ---\n"
		"frames:          %lu\n"
		"dropped/corrupt: %lu\n"
		"avg frame size:  %llu B\n",
		g_fstats.frames, g_fstats.errored,
		g_fstats.frames ? g_fstats.bytes / g_fstats.frames : 0);
	if (g_fstats.intervals) {
		fprintf(stderr,
			"fps (avg):       %.1f\n"
			"fps (worst):     %.1f  (max interval %.1fms)\n"
			"fps (best):      %.1f  (min interval %.1fms)\n",
			fps_of((unsigned int)avg),
			fps_of(g_fstats.max_interval_ns),
			g_fstats.max_interval_ns / 1e6,
			fps_of(g_fstats.min_interval_ns),
			g_fstats.min_interval_ns / 1e6);
	}
}

static void uvc_vb2_summary(void)
{
	double avg = g_vbstats.intervals ?
		(double)g_vbstats.sum_interval_ns / g_vbstats.intervals : 0;

	if (usbtrace_json) {
		printf("{\"event\":\"uvc_vb2_summary\",\"done\":%lu,"
		       "\"seq_gaps\":%lu,\"starved\":%lu,\"bytes\":%llu,"
		       "\"avg_fps\":%.1f,\"min_fps\":%.1f,\"max_fps\":%.1f}\n",
		       g_vbstats.done, g_vbstats.seq_gaps, g_vbstats.starved,
		       g_vbstats.bytes,
		       fps_of((unsigned int)avg), fps_of(g_vbstats.max_interval_ns),
		       fps_of(g_vbstats.min_interval_ns));
		return;
	}

	fprintf(stderr,
		"\n--- uvc vb2 summary ---\n"
		"buffers done:    %lu\n"
		"seq gaps:        %lu\n"
		"starvation:      %lu\n"
		"avg bytesused:   %llu B\n",
		g_vbstats.done, g_vbstats.seq_gaps, g_vbstats.starved,
		g_vbstats.done ? g_vbstats.bytes / g_vbstats.done : 0);
	if (g_vbstats.intervals) {
		fprintf(stderr,
			"fps (avg):       %.1f\n"
			"fps (worst):     %.1f  (max interval %.1fms)\n"
			"fps (best):      %.1f  (min interval %.1fms)\n",
			fps_of((unsigned int)avg),
			fps_of(g_vbstats.max_interval_ns),
			g_vbstats.max_interval_ns / 1e6,
			fps_of(g_vbstats.min_interval_ns),
			g_vbstats.min_interval_ns / 1e6);
	}
}

/* The drop hook (uvc_queue_buffer_complete) is static; on some kernels it is
 * inlined and the kprobe can't attach. Detect that so "dropped: 0" isn't read
 * as "no drops" when it actually means "drop detection unavailable". */
static bool uvc_drop_hook_active(void)
{
	return g_skel &&
	       bpf_program__autoload(g_skel->progs.on_queue_complete);
}

static void uvc_drv_summary(void)
{
	bool drop_ok = uvc_drop_hook_active();

	if (usbtrace_json) {
		printf("{\"event\":\"uvc_drv_summary\",\"received\":%lu,"
		       "\"dropped\":%lu,\"drop_short\":%lu,\"drop_iso\":%lu,"
		       "\"drop_other\":%lu,\"drop_hook\":%s}\n",
		       g_drvstats.received, g_drvstats.dropped,
		       g_drvstats.drop_short, g_drvstats.drop_iso,
		       g_drvstats.drop_other, drop_ok ? "true" : "false");
		return;
	}

	fprintf(stderr,
		"\n--- uvc driver summary ---\n"
		"frames received: %lu\n",
		g_drvstats.received);
	if (!drop_ok) {
		fprintf(stderr,
			"frames dropped:  n/a  (uvc_queue_buffer_complete hook "
			"unavailable on this kernel)\n");
		return;
	}
	fprintf(stderr, "frames dropped:  %lu\n", g_drvstats.dropped);
	if (g_drvstats.dropped) {
		fprintf(stderr,
			"  short frame:   %lu  (bytesused != dwMaxVideoFrameSize)\n"
			"  isoc loss:     %lu  (USB packet status < 0)\n"
			"  other:         %lu  (header error bit / overflow / lost EOF)\n",
			g_drvstats.drop_short, g_drvstats.drop_iso,
			g_drvstats.drop_other);
	}
}

static void uvc_gap_summary(void)
{
	double wire_fps = 0, vb2_fps = 0, wire_vb2_ms = 0;

	if (g_fstats.intervals)
		wire_fps = fps_of((unsigned int)((double)g_fstats.sum_interval_ns /
						 g_fstats.intervals));
	if (g_vbstats.intervals)
		vb2_fps = fps_of((unsigned int)((double)g_vbstats.sum_interval_ns /
						g_vbstats.intervals));
	if (g_vbstats.wire_corr)
		wire_vb2_ms = (double)g_vbstats.sum_wire_to_vb2_ns /
			      g_vbstats.wire_corr / 1e6;

	if (usbtrace_json) {
		printf("{\"event\":\"uvc_gap_summary\",\"wire_fps\":%.1f,"
		       "\"vb2_fps\":%.1f,\"wire_drops\":%lu,"
		       "\"vb2_seq_gaps\":%lu,\"vb2_starved\":%lu,"
		       "\"avg_wire_to_vb2_ms\":%.2f}\n",
		       wire_fps, vb2_fps, g_fstats.errored, g_vbstats.seq_gaps,
		       g_vbstats.starved, wire_vb2_ms);
	} else {
		fprintf(stderr,
			"\n--- uvc wire vs vb2 (gap analysis) ---\n"
			"wire fps (avg):      %.1f\n"
			"vb2 fps (avg):       %.1f\n"
			"wire drops:          %lu\n"
			"vb2 seq gaps:        %lu\n"
			"vb2 starvation:      %lu\n"
			"wire->vb2 (avg):     %.2f ms  (%lu paired)\n",
			wire_fps, vb2_fps, g_fstats.errored, g_vbstats.seq_gaps,
			g_vbstats.starved, wire_vb2_ms, g_vbstats.wire_corr);
		if (g_vbstats.starved)
			fprintf(stderr,
				"note: vb2 starvation — app may be slow to "
				"QBUF; driver had no queued buffer at wire EOF.\n");
		if (uvc_drop_hook_active() && g_drvstats.dropped &&
		    g_drvstats.dropped == g_vbstats.seq_gaps)
			fprintf(stderr,
				"note: %lu frame(s) dropped by uvcvideo "
				"(DROP_CORRUPTED requeue) — matches vb2 seq "
				"gaps; not a USB-wire loss.\n",
				g_drvstats.dropped);
		else if (g_vbstats.seq_gaps && g_fstats.errored == 0)
			fprintf(stderr,
				"note: vb2 gaps with no wire drops — USB path "
				"may be fine; check driver queue / scheduling.\n");
		else if (g_vbstats.seq_gaps > g_fstats.errored)
			fprintf(stderr,
				"note: more vb2 gaps than wire drops — losses "
				"likely after USB (driver/vb2/host).\n");
	}
}

static void uvc_on_stop(void)
{
	class_stream_summary("uvc", &g_ctx.stats);

	if (!g_no_frames)
		uvc_frame_summary();
	uvc_drv_summary();
	if (!g_no_vb2)
		uvc_vb2_summary();
	if (!g_no_frames && !g_no_vb2)
		uvc_gap_summary();
}

static int uvc_run(volatile bool *running)
{
	struct uvc_bpf *skel = uvc_bpf__open();
	int rc;

	if (!skel) {
		ut_err("failed to open BPF skeleton");
		return 1;
	}
	skel->rodata->cfg.filter_vid = (unsigned short)g_filt.vid;
	skel->rodata->cfg.filter_pid = (unsigned short)g_filt.pid;
	skel->rodata->cfg.no_frames = g_no_frames ? 1 : 0;
	skel->rodata->cfg.no_vb2 = g_no_vb2 ? 1 : 0;
	skel->rodata->cfg.fps_target = g_fps_target;
	g_skel = skel;

	rc = usbtrace_run(&(struct usbtrace_run){
		.skeleton = skel->skeleton,
		.events = skel->maps.events,
		.on_event = uvc_on_event,
		.ctx = &g_ctx,
		.on_start = uvc_on_start,
		.on_stop = uvc_on_stop,
	}, running);

	g_skel = NULL;
	uvc_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module uvc_module = {
	.name = "uvc",
	.summary = "trace UVC streaming + frames + vb2 (fps, drops, PTS/SCR)",
	.parse_args = uvc_parse_args,
	.usage = uvc_usage,
	.run = uvc_run,
};

USBTRACE_MODULE_REGISTER(uvc_module);

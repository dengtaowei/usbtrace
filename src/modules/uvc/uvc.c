// SPDX-License-Identifier: GPL-2.0
/*
 * uvc module user-space side (USB Video Class).
 *
 * Consumes two record kinds off the one ring buffer: shared class_urb_event
 * (per-URB transfer health, handled by the shared class consumer) and
 * uvc_frame_event (per assembled frame, handled here). Frame events drive real
 * FPS, drop and PTS/SCR-jitter reporting and the exit summary. The load/attach/
 * poll lifecycle is the shared usbtrace_run() harness.
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
static unsigned int g_fps_target;

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

/* Route by record kind: frames here, URB-health to the shared class consumer. */
static int uvc_on_event(void *ctx, void *data, size_t len)
{
	const struct usbtrace_event_hdr *h = data;

	if (len < sizeof(*h))
		return 0;
	if (h->kind == USBTRACE_EVT_UVC_FRAME)
		return handle_frame(data, len);
	return class_stream_on_event(ctx, data, len);
}

static void uvc_on_start(void)
{
	ut_info("tracing UVC stream%s... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		g_no_frames ? " (URB health only)" : " + frames", g_filt.vid,
		g_filt.pid);
}

static void uvc_on_stop(void)
{
	class_stream_summary("uvc", &g_ctx.stats);

	if (g_no_frames)
		return;

	if (usbtrace_json) {
		double avg = g_fstats.intervals ?
			(double)g_fstats.sum_interval_ns / g_fstats.intervals : 0;

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
		double avg = (double)g_fstats.sum_interval_ns /
			     g_fstats.intervals;

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
	skel->rodata->cfg.fps_target = g_fps_target;

	rc = usbtrace_run(&(struct usbtrace_run){
		.skeleton = skel->skeleton,
		.events = skel->maps.events,
		.on_event = uvc_on_event,
		.ctx = &g_ctx,
		.on_start = uvc_on_start,
		.on_stop = uvc_on_stop,
	}, running);

	uvc_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module uvc_module = {
	.name = "uvc",
	.summary = "trace UVC streaming + frames (real fps, drops, PTS/SCR)",
	.parse_args = uvc_parse_args,
	.usage = uvc_usage,
	.run = uvc_run,
};

USBTRACE_MODULE_REGISTER(uvc_module);

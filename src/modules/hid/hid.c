// SPDX-License-Identifier: GPL-2.0
/*
 * hid module user-space side (USB HID).
 *
 * Builds on the shared class-stream consumer, and adds a realtime IN report-rate
 * meter (Hz / interval) per endpoint — enough to tell keyboard vs mouse apart
 * on a composite device without decoding report descriptors.
 *
 * The meter only counts successful IN completions, and reports silences longer
 * than HID_RATE_GAP_NS as gaps instead of averaging them into the interval, so
 * a single unlink or suspend cannot make a steady stream look slow.
 */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "usbtrace/class_stream.h"
#include "hid.skel.h"

#define HID_RATE_SLOTS		16
#define HID_RATE_DEFAULT_SEC	1U

/*
 * Inter-arrival gaps above this are stream breaks (idle device, host-side URB
 * unlink, suspend/resume), not report intervals: averaging them in would hide
 * the real rate behind one huge sample.
 */
#define HID_RATE_GAP_NS		(50ULL * 1000 * 1000)

/* Windows shorter than this fraction of --interval are not worth printing. */
#define HID_RATE_MIN_WIN_FRAC	0.25

enum hid_role {
	HID_ROLE_UNK = 0,
	HID_ROLE_MOUSE,
	HID_ROLE_KBD,
};

struct hid_rate_slot {
	__u16 busnum;
	__u16 devnum;
	__u8 ep;
	__u8 role;
	__u16 vid;
	__u16 product;

	__u64 last_ts_ns;
	__u64 win_count;
	__u64 win_iv_count;
	__u64 win_sum_iv_ns;
	__u32 win_min_iv_ns;
	__u32 win_max_iv_ns;
	__u64 win_gaps;

	__u64 total_count;
	__u64 total_iv_count;
	__u64 total_sum_iv_ns;
	__u32 total_min_iv_ns;
	__u32 total_max_iv_ns;
	__u64 total_gaps;

	/* URBs that completed with an error: counted, but kept out of the rate */
	__u64 err_urbs;

	/* majority vote on actual_length for role guess */
	__u32 len_mouse;
	__u32 len_kbd;
	__u32 len_other;
};

static struct usbtrace_filter g_filt;
static struct class_stream_ctx g_ctx;
static bool g_rate = true;	/* default on: the point of this enhancement */
static unsigned int g_rate_sec = HID_RATE_DEFAULT_SEC;
static struct hid_rate_slot g_slots[HID_RATE_SLOTS];
static int g_nslots;
static __u64 g_window_start_ns;

static __u64 rate_window_ns(void)
{
	return (unsigned long long)g_rate_sec * 1000ULL * 1000ULL * 1000ULL;
}

static const char *role_str(unsigned char role)
{
	switch (role) {
	case HID_ROLE_MOUSE:	return "mouse";
	case HID_ROLE_KBD:	return "kbd";
	default:		return "hid";
	}
}

static void hid_usage(void)
{
	fprintf(stderr,
		"usbtrace hid - trace USB HID report flow + report rate\n\n"
		"Hooks hid_irq_in / hid_irq_out (usbhid interrupt URB callbacks).\n"
		"By default prints a realtime report-rate line per IN endpoint\n"
		"(keyboard vs mouse guessed from report size). Requires usbhid.\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --all           print every report (default: anomalies only)\n"
		"  --rate          enable realtime Hz (default)\n"
		"  --no-rate       disable realtime Hz meter\n"
		"  --interval <s>  rate print period in seconds (default: 1)\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace hid --vid 0x1c4f\n"
		"  sudo usbtrace hid --interval 5 --vid 0x0ffe --pid 0x0001\n"
		"  sudo usbtrace hid --all --no-rate --vid 0x1c4f\n"
		"  sudo usbtrace --json hid --vid 0x1c4f | jq\n");
}

static int hid_parse_args(int argc, char **argv)
{
	static const struct option lo[] = {
		USBTRACE_FILTER_LONGOPTS,
		{ "all", no_argument, 0, 'a' },
		{ "rate", no_argument, 0, 'R' },
		{ "no-rate", no_argument, 0, 'N' },
		{ "interval", required_argument, 0, 'I' },
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
		case 'R':
			g_rate = true;
			break;
		case 'N':
			g_rate = false;
			break;
		case 'I': {
			unsigned long v = strtoul(optarg, NULL, 0);

			if (v == 0 || v > 3600) {
				ut_err("--interval must be 1..3600 seconds");
				return -1;
			}
			g_rate_sec = (unsigned int)v;
			break;
		}
		case 'h':
			return 1;
		default:
			return -1;
		}
	}
	return 0;
}

static struct hid_rate_slot *slot_get(__u16 bus, __u16 dev, __u8 ep,
				     __u16 vid, __u16 product)
{
	int i;

	for (i = 0; i < g_nslots; i++) {
		if (g_slots[i].busnum == bus && g_slots[i].devnum == dev &&
		    g_slots[i].ep == ep)
			return &g_slots[i];
	}
	if (g_nslots >= HID_RATE_SLOTS)
		return NULL;
	memset(&g_slots[g_nslots], 0, sizeof(g_slots[0]));
	g_slots[g_nslots].busnum = bus;
	g_slots[g_nslots].devnum = dev;
	g_slots[g_nslots].ep = ep;
	g_slots[g_nslots].vid = vid;
	g_slots[g_nslots].product = product;
	return &g_slots[g_nslots++];
}

static void slot_note_len(struct hid_rate_slot *s, __u32 len)
{
	/*
	 * Boot mouse reports 4 bytes; boot keyboard 8 (9 with a report ID), and
	 * a bitmap keyboard (modifier byte + 120-bit keycode bitmap) 17.
	 */
	if (len == 4)
		s->len_mouse++;
	else if (len == 8 || len == 9 || len == 17)
		s->len_kbd++;
	else
		s->len_other++;

	/* sticky classify once we have a few samples */
	if (s->role != HID_ROLE_UNK)
		return;
	if (s->len_mouse + s->len_kbd + s->len_other < 8)
		return;
	if (s->len_mouse >= s->len_kbd && s->len_mouse >= s->len_other)
		s->role = HID_ROLE_MOUSE;
	else if (s->len_kbd >= s->len_other)
		s->role = HID_ROLE_KBD;
}

static void slot_note_interval(struct hid_rate_slot *s, __u64 iv)
{
	if (!iv)
		return;

	if (iv > HID_RATE_GAP_NS) {
		s->win_gaps++;
		s->total_gaps++;
		return;
	}

	s->win_iv_count++;
	s->total_iv_count++;
	s->win_sum_iv_ns += iv;
	s->total_sum_iv_ns += iv;
	if (!s->win_min_iv_ns || iv < s->win_min_iv_ns)
		s->win_min_iv_ns = iv;
	if (iv > s->win_max_iv_ns)
		s->win_max_iv_ns = iv;
	if (!s->total_min_iv_ns || iv < s->total_min_iv_ns)
		s->total_min_iv_ns = iv;
	if (iv > s->total_max_iv_ns)
		s->total_max_iv_ns = iv;
}

static void print_rate_line(const struct hid_rate_slot *s, double win_s)
{
	double hz, avg_us, min_us, max_us;
	char gaps[32] = "";

	if (win_s <= 0.0 || !s->win_count)
		return;
	hz = (double)s->win_count / win_s;
	avg_us = s->win_iv_count
		 ? (double)s->win_sum_iv_ns / (double)s->win_iv_count / 1e3
		 : 0.0;
	min_us = s->win_min_iv_ns / 1e3;
	max_us = s->win_max_iv_ns / 1e3;

	if (usbtrace_json) {
		printf("{\"event\":\"hid_rate\",\"role\":\"%s\",\"ep\":%u,"
		       "\"hz\":%.1f,\"avg_us\":%.1f,\"min_us\":%.1f,\"max_us\":%.1f,"
		       "\"reports\":%llu,\"gaps\":%llu,\"window_s\":%u,"
		       "\"vid\":\"0x%04x\",\"pid\":\"0x%04x\",\"bus\":%u,\"dev\":%u}\n",
		       role_str(s->role), s->ep, hz, avg_us, min_us, max_us,
		       (unsigned long long)s->win_count,
		       (unsigned long long)s->win_gaps, g_rate_sec, s->vid,
		       s->product, s->busnum, s->devnum);
		return;
	}

	if (s->win_gaps)
		snprintf(gaps, sizeof(gaps), " gaps=%llu",
			 (unsigned long long)s->win_gaps);

	printf("rate   %-5s ep%-2u %7.1f Hz  avg=%6.1fus min=%6.1f max=%6.1f  "
	       "%04x:%04x %u-%u%s\n",
	       role_str(s->role), s->ep, hz, avg_us, min_us, max_us,
	       s->vid, s->product, s->busnum, s->devnum, gaps);
}

static void rate_flush_window(__u64 now_ns, bool final)
{
	int i;
	double win_s;

	if (!g_window_start_ns || now_ns <= g_window_start_ns)
		return;

	win_s = (double)(now_ns - g_window_start_ns) / 1e9;

	/*
	 * The last window ends wherever the user hit Ctrl-C, so it can be a few
	 * microseconds long: one report over that span reads as tens of kHz.
	 */
	if (final && win_s < HID_RATE_MIN_WIN_FRAC * (double)g_rate_sec)
		return;

	for (i = 0; i < g_nslots; i++) {
		print_rate_line(&g_slots[i], win_s);
		g_slots[i].win_count = 0;
		g_slots[i].win_iv_count = 0;
		g_slots[i].win_sum_iv_ns = 0;
		g_slots[i].win_min_iv_ns = 0;
		g_slots[i].win_max_iv_ns = 0;
		g_slots[i].win_gaps = 0;
	}
	g_window_start_ns = now_ns;
}

static void rate_on_in(const struct class_urb_event *e)
{
	struct hid_rate_slot *s;
	__u64 ts = e->hdr.ts_ns;

	if (!g_rate || !e->dir_in)
		return;

	s = slot_get(e->busnum, e->devnum, e->ep, e->vid, e->product);
	if (!s)
		return;

	/*
	 * A failed URB carries no report: -ENOENT/-ECONNRESET from a host-side
	 * unlink would otherwise land in the rate as a zero-length "report" and
	 * leave a stale timestamp behind.
	 */
	if (e->status != 0) {
		s->err_urbs++;
		return;
	}

	slot_note_len(s, e->actual_length);
	if (s->last_ts_ns && ts > s->last_ts_ns)
		slot_note_interval(s, ts - s->last_ts_ns);
	s->last_ts_ns = ts;
	s->win_count++;
	s->total_count++;

	if (!g_window_start_ns)
		g_window_start_ns = ts;
	if (ts - g_window_start_ns >= rate_window_ns())
		rate_flush_window(ts, false);
}

static void rate_summary(void)
{
	int i;

	if (!g_rate || !g_nslots)
		return;

	if (usbtrace_json) {
		for (i = 0; i < g_nslots; i++) {
			const struct hid_rate_slot *s = &g_slots[i];
			double hz = 0.0, avg_us = 0.0;

			if (s->total_iv_count) {
				avg_us = (double)s->total_sum_iv_ns /
					 (double)s->total_iv_count / 1e3;
				hz = avg_us > 0.0 ? 1e6 / avg_us : 0.0;
			}
			printf("{\"event\":\"hid_rate_summary\",\"role\":\"%s\","
			       "\"ep\":%u,\"hz\":%.1f,\"avg_us\":%.1f,"
			       "\"min_us\":%.1f,\"max_us\":%.1f,\"reports\":%llu,"
			       "\"gaps\":%llu,\"err_urbs\":%llu,"
			       "\"vid\":\"0x%04x\",\"pid\":\"0x%04x\","
			       "\"bus\":%u,\"dev\":%u}\n",
			       role_str(s->role), s->ep, hz, avg_us,
			       s->total_min_iv_ns / 1e3, s->total_max_iv_ns / 1e3,
			       (unsigned long long)s->total_count,
			       (unsigned long long)s->total_gaps,
			       (unsigned long long)s->err_urbs, s->vid,
			       s->product, s->busnum, s->devnum);
		}
		return;
	}

	fprintf(stderr, "\n--- hid rate summary ---\n");
	for (i = 0; i < g_nslots; i++) {
		const struct hid_rate_slot *s = &g_slots[i];
		double hz = 0.0, avg_us = 0.0;
		char extra[64] = "";

		if (s->total_iv_count) {
			avg_us = (double)s->total_sum_iv_ns /
				 (double)s->total_iv_count / 1e3;
			hz = avg_us > 0.0 ? 1e6 / avg_us : 0.0;
		}

		if (s->total_gaps || s->err_urbs)
			snprintf(extra, sizeof(extra), "  gaps=%llu err=%llu",
				 (unsigned long long)s->total_gaps,
				 (unsigned long long)s->err_urbs);

		fprintf(stderr,
			"%-5s ep%-2u  ~%.1f Hz  avg=%.1fus min=%.1f max=%.1f  "
			"reports=%llu%s  %04x:%04x %u-%u\n",
			role_str(s->role), s->ep, hz, avg_us,
			s->total_min_iv_ns / 1e3, s->total_max_iv_ns / 1e3,
			(unsigned long long)s->total_count, extra, s->vid,
			s->product, s->busnum, s->devnum);
	}
}

static int hid_on_event(void *ctx, void *data, size_t len)
{
	const struct class_urb_event *e = data;

	if (len >= sizeof(*e) && e->hdr.kind == USBTRACE_EVT_CLASS &&
	    e->klass == USBTRACE_CLASS_HID)
		rate_on_in(e);

	return class_stream_on_event(ctx, data, len);
}

static void hid_on_start(void)
{
	ut_info("tracing HID reports... vid=0x%04x pid=0x%04x rate=%s interval=%us (Ctrl-C to stop)",
		g_filt.vid, g_filt.pid, g_rate ? "on" : "off", g_rate_sec);
	if (g_rate && !usbtrace_json)
		fprintf(stderr,
			"# rate lines: role ep Hz avg/min/max interval (%us window)\n",
			g_rate_sec);
}

static void hid_on_stop(void)
{
	if (g_rate && g_window_start_ns) {
		/* flush partial last window using last sample times */
		__u64 now = 0;
		int i;

		for (i = 0; i < g_nslots; i++) {
			if (g_slots[i].last_ts_ns > now)
				now = g_slots[i].last_ts_ns;
		}
		if (now > g_window_start_ns)
			rate_flush_window(now, true);
	}
	class_stream_summary("hid", &g_ctx.stats);
	rate_summary();
}

static int hid_run(volatile bool *running)
{
	struct hid_bpf *skel = hid_bpf__open();
	int rc;

	if (!skel) {
		ut_err("failed to open BPF skeleton");
		return 1;
	}
	skel->rodata->cfg.filter_vid = (unsigned short)g_filt.vid;
	skel->rodata->cfg.filter_pid = (unsigned short)g_filt.pid;

	rc = usbtrace_run(&(struct usbtrace_run){
		.skeleton = skel->skeleton,
		.events = skel->maps.events,
		.on_event = hid_on_event,
		.ctx = &g_ctx,
		.on_start = hid_on_start,
		.on_stop = hid_on_stop,
	}, running);

	hid_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module hid_module = {
	.name = "hid",
	.summary = "trace USB HID report flow + realtime kbd/mouse Hz",
	.parse_args = hid_parse_args,
	.usage = hid_usage,
	.run = hid_run,
};

USBTRACE_MODULE_REGISTER(hid_module);

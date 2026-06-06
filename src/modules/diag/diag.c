// SPDX-License-Identifier: GPL-2.0
/*
 * diag module: nettrace-style USB diagnosis.
 *
 * Unlike a tracing module, diag loads SEVERAL existing BPF skeletons at once
 * (urb/enum/lifecycle/power), merges their ring buffers into one poll loop, and
 * feeds the normalized event stream to a YAML-driven rule engine. The engine
 * correlates events per device and emits conclusions + evidence chains live,
 * with a summary at exit. No new BPF is written; diag reuses the verified
 * programs of the tracing modules.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <bpf/libbpf.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/probe.h"

#include "diag.h"
#include "engine.h"
#include "rules.h"

/* per-module shared types + generated skeletons */
#include "usbtrace/class.h"
#include "usbtrace/uvc.h"
#include "urb/urb.h"
#include "enum/enum.h"
#include "lifecycle/lifecycle.h"
#include "power/power.h"
#include "urb.skel.h"
#include "enum.skel.h"
#include "lifecycle.skel.h"
#include "power.skel.h"
/* class-traffic skeletons (all share struct usbtrace_class_config) */
#include "uvc.skel.h"
#include "uac.skel.h"
#include "hid.skel.h"
#include "storage.skel.h"

#define TICK_INTERVAL_NS (500ULL * 1000000ULL)

/*
 * Extensible class-source table. Every class module's skeleton is uniform
 * (same usbtrace_class_config cfg, same maps.events, same __open/load/attach/
 * destroy naming), so we drive them generically. Adding a new class module to
 * diag is one DIAG_CLASS_SRC() + one row in diag_class_srcs[] — no changes to
 * the load/poll logic below. See docs/class.md.
 */
struct diag_class_src {
	const char *name;
	void *(*open)(void);
	int (*load)(void *);
	int (*attach)(void *);
	void (*destroy)(void *);
	struct usbtrace_class_config *(*cfg)(void *);
	int (*events_fd)(void *);
	struct bpf_object *(*obj)(void *);
};

#define DIAG_CLASS_SRC(SK)                                                     \
	static void *diag_##SK##_open(void) { return SK##__open(); }           \
	static int diag_##SK##_load(void *s) { return SK##__load(s); }         \
	static int diag_##SK##_attach(void *s) { return SK##__attach(s); }     \
	static void diag_##SK##_destroy(void *s) { SK##__destroy(s); }         \
	static struct usbtrace_class_config *diag_##SK##_cfg(void *s)          \
	{                                                                     \
		/* cast tolerates a layout-compatible prefix (e.g. uvc_config) */\
		return (struct usbtrace_class_config *)                       \
			&((struct SK *)s)->rodata->cfg;                       \
	}                                                                     \
	static int diag_##SK##_fd(void *s)                                    \
	{                                                                     \
		return bpf_map__fd(((struct SK *)s)->maps.events);            \
	}                                                                     \
	static struct bpf_object *diag_##SK##_obj(void *s)                    \
	{                                                                     \
		return ((struct SK *)s)->obj;                                 \
	}

DIAG_CLASS_SRC(uvc_bpf)
DIAG_CLASS_SRC(uac_bpf)
DIAG_CLASS_SRC(hid_bpf)
DIAG_CLASS_SRC(storage_bpf)

#define DIAG_CLASS_ROW(SK, NAME)                                               \
	{                                                                     \
		NAME, diag_##SK##_open, diag_##SK##_load, diag_##SK##_attach,  \
		diag_##SK##_destroy, diag_##SK##_cfg, diag_##SK##_fd,         \
		diag_##SK##_obj                                               \
	}

static const struct diag_class_src diag_class_srcs[] = {
	DIAG_CLASS_ROW(uvc_bpf, "uvc"),
	DIAG_CLASS_ROW(uac_bpf, "uac"),
	DIAG_CLASS_ROW(hid_bpf, "hid"),
	DIAG_CLASS_ROW(storage_bpf, "storage"),
};
#define DIAG_N_CLASS_SRCS                                                      \
	((int)(sizeof(diag_class_srcs) / sizeof(diag_class_srcs[0])))

static struct {
	struct usbtrace_filter filt;
	const char *rules_path;
} opts;

static void diag_usage(void)
{
	fprintf(stderr,
		"usbtrace diag - correlate USB events into diagnoses\n\n"
		"Loads the urb/enum/lifecycle/power probes together and runs a\n"
		"YAML rule engine over the merged, per-device event stream,\n"
		"emitting conclusions + evidence live and a summary at exit.\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (e.g. 0x0403)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --rules <path>  load rules from a YAML file (else built-in)\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace diag\n"
		"  sudo usbtrace diag --vid 0x0403 --rules ./rules.yaml\n"
		"  sudo usbtrace --json diag | jq\n");
}

static int diag_parse_args(int argc, char **argv)
{
	static const struct option lo[] = {
		USBTRACE_FILTER_LONGOPTS,
		{ "rules", required_argument, 0, 'r' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "hr:", lo, NULL)) != -1) {
		if (usbtrace_filter_getopt(c, optarg, &opts.filt))
			continue;
		switch (c) {
		case 'r':
			opts.rules_path = optarg;
			break;
		case 'h':
			return 1;
		default:
			return -1;
		}
	}
	return 0;
}

/* ---- event normalization ------------------------------------------------- */

static int normalize(const void *data, size_t len, struct diag_event *out)
{
	const struct usbtrace_event_hdr *h = data;

	if (len < sizeof(*h))
		return -1;
	memset(out, 0, sizeof(*out));
	out->kind = h->kind;
	out->ts_ns = h->ts_ns;

	switch (h->kind) {
	case USBTRACE_EVT_URB: {
		const struct urb_event *e = data;

		if (len < sizeof(*e))
			return -1;
		out->vid = e->vid;
		out->pid = e->product;
		out->busnum = e->busnum;
		out->devnum = e->devnum;
		out->status = e->status;
		out->latency_ns = e->latency_ns;
		out->actual = e->actual;
		out->length = e->length;
		out->xfer_type = e->xfer_type;
		out->dir_in = e->dir_in;
		out->ep = e->ep;
		out->is_submit = e->is_submit;
		memcpy(out->comm, e->comm, sizeof(out->comm));
		break;
	}
	case USBTRACE_EVT_ENUM: {
		const struct enum_event *e = data;

		if (len < sizeof(*e))
			return -1;
		out->vid = e->vid;
		out->pid = e->product;
		out->busnum = e->busnum;
		out->devnum = e->devnum;
		out->speed = e->speed;
		out->portnum = e->portnum;
		out->old_state = e->old_state;
		out->new_state = e->new_state;
		memcpy(out->devpath, e->devpath, sizeof(out->devpath));
		memcpy(out->comm, e->comm, sizeof(out->comm));
		break;
	}
	case USBTRACE_EVT_POWER: {
		const struct power_event *e = data;

		if (len < sizeof(*e))
			return -1;
		out->vid = e->vid;
		out->pid = e->product;
		out->busnum = e->busnum;
		out->devnum = e->devnum;
		out->speed = e->speed;
		out->portnum = e->portnum;
		out->action = e->action;
		memcpy(out->devpath, e->devpath, sizeof(out->devpath));
		memcpy(out->comm, e->comm, sizeof(out->comm));
		break;
	}
	case USBTRACE_EVT_LIFECYCLE: {
		const struct lifecycle_event *e = data;

		if (len < sizeof(*e))
			return -1;
		out->vid = e->vid;
		out->pid = e->product;
		out->busnum = e->busnum;
		out->devnum = e->devnum;
		out->speed = e->speed;
		out->portnum = e->portnum;
		out->action = e->action;
		memcpy(out->devpath, e->devpath, sizeof(out->devpath));
		memcpy(out->comm, e->comm, sizeof(out->comm));
		break;
	}
	case USBTRACE_EVT_CLASS: {
		/* One case for ALL class modules (uvc/uac/hid/storage/...) — the
		 * unified class_urb_event makes diag cooperation free; cls tells
		 * rules which class it was. */
		const struct class_urb_event *e = data;

		if (len < sizeof(*e))
			return -1;
		out->vid = e->vid;
		out->pid = e->product;
		out->busnum = e->busnum;
		out->devnum = e->devnum;
		out->status = e->status;
		out->error_count = e->error_count;
		out->actual = e->actual_length;
		out->length = e->actual_length;
		out->xfer_type = e->xfer_type;
		out->dir_in = e->dir_in;
		out->ep = e->ep;
		out->cls = e->klass;
		out->is_submit = 0; /* class events are completions */
		memcpy(out->comm, e->comm, sizeof(out->comm));
		break;
	}
	case USBTRACE_EVT_UVC_FRAME: {
		/* uvc rides the class path for URB health AND emits this richer
		 * per-frame record; cls=VIDEO so frame rules read like class rules. */
		const struct uvc_frame_event *e = data;

		if (len < sizeof(*e))
			return -1;
		out->vid = e->vid;
		out->pid = e->product;
		out->busnum = e->busnum;
		out->devnum = e->devnum;
		out->ep = e->ep;
		out->cls = USBTRACE_CLASS_VIDEO;
		out->actual = e->bytes;
		out->frame_bytes = e->bytes;
		out->frame_interval_ns = e->interval_ns;
		out->frame_errored = e->errored;
		memcpy(out->comm, e->comm, sizeof(out->comm));
		break;
	}
	case USBTRACE_EVT_UVC_VB2: {
		const struct uvc_vb2_event *e = data;

		if (len < sizeof(*e))
			return -1;
		out->vid = e->vid;
		out->pid = e->product;
		out->busnum = e->busnum;
		out->devnum = e->devnum;
		out->cls = USBTRACE_CLASS_VIDEO;
		out->actual = e->bytesused;
		out->vb2_sequence = e->sequence;
		out->vb2_bytesused = e->bytesused;
		out->vb2_interval_ns = e->interval_ns;
		out->vb2_seq_gap = e->seq_gap;
		out->wire_to_vb2_ns = e->wire_to_vb2_ns;
		memcpy(out->comm, e->comm, sizeof(out->comm));
		break;
	}
	default:
		return -1;
	}
	return 0;
}

static int on_event(void *ctx, void *data, size_t len)
{
	struct diag_engine *eng = ctx;
	struct diag_event ev;

	if (normalize(data, len, &ev) == 0)
		diag_engine_ingest(eng, &ev);
	return 0;
}

static int add_src(struct ring_buffer **rb, int fd, void *ctx)
{
	if (*rb)
		return ring_buffer__add(*rb, fd, on_event, ctx);
	*rb = ring_buffer__new(fd, on_event, ctx, NULL);
	return *rb ? 0 : -1;
}

/* ---- run ----------------------------------------------------------------- */

static int diag_run(volatile bool *running)
{
	struct urb_bpf *urb = NULL;
	struct enum_bpf *en = NULL;
	struct lifecycle_bpf *lc = NULL;
	struct power_bpf *pw = NULL;
	void *class_h[DIAG_N_CLASS_SRCS] = { 0 };
	struct ring_buffer *rb = NULL;
	struct diag_engine *eng = NULL;
	struct diag_rule *rules = NULL;
	int nrules, nsrc = 0, err = 0, i;
	char errbuf[256];
	uint64_t last_tick;

	/* Load the knowledge base (external file overrides built-in). */
	if (opts.rules_path)
		nrules = diag_rules_load_file(opts.rules_path, &rules, errbuf,
					      sizeof(errbuf));
	else
		nrules = diag_rules_load_default(&rules, errbuf,
						 sizeof(errbuf));
	if (nrules < 0) {
		ut_err("diag: failed to load rules: %s", errbuf);
		return 1;
	}
	ut_info("diag: loaded %d rule(s)%s", nrules,
		opts.rules_path ? "" : " (built-in)");

	eng = diag_engine_create(rules, nrules);
	if (!eng) {
		ut_err("diag: out of memory");
		diag_rules_free(rules, nrules);
		return 1;
	}

	/* Bring up each probe; a missing kprobe target warns and is skipped
	 * (graceful degradation across kernels). */
	urb = urb_bpf__open();
	if (urb) {
		urb->rodata->cfg.filter_vid = (unsigned short)opts.filt.vid;
		urb->rodata->cfg.filter_pid = (unsigned short)opts.filt.pid;
		urb->rodata->cfg.emit_submit = 1; /* need submits for correlation */
		if (usbtrace_autoload_filter(urb->obj) == 0 ||
		    urb_bpf__load(urb) || urb_bpf__attach(urb)) {
			ut_warn("diag: urb probe unavailable, skipping");
			urb_bpf__destroy(urb);
			urb = NULL;
		}
	}
	en = enum_bpf__open();
	if (en) {
		en->rodata->cfg.filter_vid = (unsigned short)opts.filt.vid;
		en->rodata->cfg.filter_pid = (unsigned short)opts.filt.pid;
		if (usbtrace_autoload_filter(en->obj) == 0 ||
		    enum_bpf__load(en) || enum_bpf__attach(en)) {
			ut_warn("diag: enum probe unavailable, skipping");
			enum_bpf__destroy(en);
			en = NULL;
		}
	}
	lc = lifecycle_bpf__open();
	if (lc) {
		lc->rodata->cfg.filter_vid = (unsigned short)opts.filt.vid;
		lc->rodata->cfg.filter_pid = (unsigned short)opts.filt.pid;
		if (usbtrace_autoload_filter(lc->obj) == 0 ||
		    lifecycle_bpf__load(lc) || lifecycle_bpf__attach(lc)) {
			ut_warn("diag: lifecycle probe unavailable, skipping");
			lifecycle_bpf__destroy(lc);
			lc = NULL;
		}
	}
	pw = power_bpf__open();
	if (pw) {
		pw->rodata->cfg.filter_vid = (unsigned short)opts.filt.vid;
		pw->rodata->cfg.filter_pid = (unsigned short)opts.filt.pid;
		if (usbtrace_autoload_filter(pw->obj) == 0 ||
		    power_bpf__load(pw) || power_bpf__attach(pw)) {
			ut_warn("diag: power probe unavailable, skipping");
			power_bpf__destroy(pw);
			pw = NULL;
		}
	}

	/* Class-traffic sources (uvc/uac/hid/storage): uniform, table-driven.
	 * Each skeleton is feature-probed per program first, so a missing hook
	 * disables just that program; a source with no usable hook (or that
	 * fails to attach, e.g. its driver isn't loaded) is skipped entirely. */
	for (i = 0; i < DIAG_N_CLASS_SRCS; i++) {
		const struct diag_class_src *s = &diag_class_srcs[i];
		void *h = s->open();

		if (!h)
			continue;
		s->cfg(h)->filter_vid = (unsigned short)opts.filt.vid;
		s->cfg(h)->filter_pid = (unsigned short)opts.filt.pid;
		if (usbtrace_autoload_filter(s->obj(h)) == 0 ||
		    s->load(h) || s->attach(h)) {
			ut_warn("diag: %s probe unavailable, skipping", s->name);
			s->destroy(h);
			continue;
		}
		class_h[i] = h;
	}

	if (urb && add_src(&rb, bpf_map__fd(urb->maps.events), eng) == 0)
		nsrc++;
	if (en && add_src(&rb, bpf_map__fd(en->maps.events), eng) == 0)
		nsrc++;
	if (lc && add_src(&rb, bpf_map__fd(lc->maps.events), eng) == 0)
		nsrc++;
	if (pw && add_src(&rb, bpf_map__fd(pw->maps.events), eng) == 0)
		nsrc++;
	for (i = 0; i < DIAG_N_CLASS_SRCS; i++) {
		if (class_h[i] &&
		    add_src(&rb, diag_class_srcs[i].events_fd(class_h[i]),
			    eng) == 0)
			nsrc++;
	}

	if (!rb || nsrc == 0) {
		ut_err("diag: no probes could be attached (need root + BTF?)");
		err = 1;
		goto cleanup;
	}

	ut_info("diag: %d source(s) active, vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		nsrc, opts.filt.vid, opts.filt.pid);

	last_tick = diag_now_ns();
	while (*running) {
		uint64_t now;

		err = ring_buffer__poll(rb, 200 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			ut_err("diag: ring buffer poll error: %d", err);
			break;
		}
		now = diag_now_ns();
		if (now - last_tick >= TICK_INTERVAL_NS) {
			diag_engine_tick(eng, now);
			last_tick = now;
		}
	}
	if (err > 0)
		err = 0;

	diag_engine_report(eng);

cleanup:
	ring_buffer__free(rb);
	urb_bpf__destroy(urb);
	enum_bpf__destroy(en);
	lifecycle_bpf__destroy(lc);
	power_bpf__destroy(pw);
	for (i = 0; i < DIAG_N_CLASS_SRCS; i++)
		if (class_h[i])
			diag_class_srcs[i].destroy(class_h[i]);
	diag_engine_destroy(eng); /* frees rules too */
	return err ? 1 : 0;
}

static struct usbtrace_module diag_module = {
	.name = "diag",
	.summary = "correlate URB/enum/lifecycle/power/class into diagnoses (rule engine)",
	.parse_args = diag_parse_args,
	.usage = diag_usage,
	.run = diag_run,
};

USBTRACE_MODULE_REGISTER(diag_module);

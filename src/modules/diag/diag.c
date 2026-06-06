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

#include "diag.h"
#include "engine.h"
#include "rules.h"

/* per-module shared types + generated skeletons */
#include "urb/urb.h"
#include "enum/enum.h"
#include "lifecycle/lifecycle.h"
#include "power/power.h"
#include "urb.skel.h"
#include "enum.skel.h"
#include "lifecycle.skel.h"
#include "power.skel.h"

#define TICK_INTERVAL_NS (500ULL * 1000000ULL)

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
	struct ring_buffer *rb = NULL;
	struct diag_engine *eng = NULL;
	struct diag_rule *rules = NULL;
	int nrules, nsrc = 0, err = 0;
	char errbuf[256];
	uint64_t last_tick;

	libbpf_set_print(usbtrace_libbpf_print);

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
		if (urb_bpf__load(urb) || urb_bpf__attach(urb)) {
			ut_warn("diag: urb probe unavailable, skipping");
			urb_bpf__destroy(urb);
			urb = NULL;
		}
	}
	en = enum_bpf__open();
	if (en) {
		en->rodata->cfg.filter_vid = (unsigned short)opts.filt.vid;
		en->rodata->cfg.filter_pid = (unsigned short)opts.filt.pid;
		if (enum_bpf__load(en) || enum_bpf__attach(en)) {
			ut_warn("diag: enum probe unavailable, skipping");
			enum_bpf__destroy(en);
			en = NULL;
		}
	}
	lc = lifecycle_bpf__open();
	if (lc) {
		lc->rodata->cfg.filter_vid = (unsigned short)opts.filt.vid;
		lc->rodata->cfg.filter_pid = (unsigned short)opts.filt.pid;
		if (lifecycle_bpf__load(lc) || lifecycle_bpf__attach(lc)) {
			ut_warn("diag: lifecycle probe unavailable, skipping");
			lifecycle_bpf__destroy(lc);
			lc = NULL;
		}
	}
	pw = power_bpf__open();
	if (pw) {
		pw->rodata->cfg.filter_vid = (unsigned short)opts.filt.vid;
		pw->rodata->cfg.filter_pid = (unsigned short)opts.filt.pid;
		if (power_bpf__load(pw) || power_bpf__attach(pw)) {
			ut_warn("diag: power probe unavailable, skipping");
			power_bpf__destroy(pw);
			pw = NULL;
		}
	}

	if (urb && add_src(&rb, bpf_map__fd(urb->maps.events), eng) == 0)
		nsrc++;
	if (en && add_src(&rb, bpf_map__fd(en->maps.events), eng) == 0)
		nsrc++;
	if (lc && add_src(&rb, bpf_map__fd(lc->maps.events), eng) == 0)
		nsrc++;
	if (pw && add_src(&rb, bpf_map__fd(pw->maps.events), eng) == 0)
		nsrc++;

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
	diag_engine_destroy(eng); /* frees rules too */
	return err ? 1 : 0;
}

static struct usbtrace_module diag_module = {
	.name = "diag",
	.summary = "correlate URB/enum/lifecycle/power into diagnoses (rule engine)",
	.parse_args = diag_parse_args,
	.usage = diag_usage,
	.run = diag_run,
};

USBTRACE_MODULE_REGISTER(diag_module);

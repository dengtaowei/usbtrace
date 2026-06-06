// SPDX-License-Identifier: GPL-2.0
/*
 * urb module user-space side: configure, load & attach the BPF program, then
 * consume URB events from the ring buffer and print them.
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
#include "usbtrace/run.h"
#include "urb.h"
#include "urb.skel.h"

static struct {
	struct usbtrace_filter filt;
	bool emit_submit;
} opts;

static const char *xfer_str(__u8 t)
{
	switch (t) {
	case USBTRACE_XFER_ISOC:
		return "ISOC";
	case USBTRACE_XFER_INT:
		return "INT";
	case USBTRACE_XFER_CONTROL:
		return "CTRL";
	case USBTRACE_XFER_BULK:
		return "BULK";
	default:
		return "?";
	}
}

static void urb_usage(void)
{
	fprintf(stderr,
		"usbtrace urb - trace USB Request Block submit/complete\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (e.g. 0x0403)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --submit        also print submission records\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace urb --vid 0x0403\n"
		"  sudo usbtrace --json urb --vid 0x0403\n");
}

static int urb_parse_args(int argc, char **argv)
{
	static const struct option lo[] = {
		USBTRACE_FILTER_LONGOPTS,
		{ "submit", no_argument, 0, 's' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};
	int c;

	/* argv[0] is "urb"; let getopt scan from there. */
	optind = 1;
	while ((c = getopt_long(argc, argv, "h", lo, NULL)) != -1) {
		if (usbtrace_filter_getopt(c, optarg, &opts.filt))
			continue;
		switch (c) {
		case 's':
			opts.emit_submit = true;
			break;
		case 'h':
			return 1; /* request help */
		default:
			return -1;
		}
	}
	return 0;
}

static void print_text(const struct urb_event *e, char dir)
{
	if (e->is_submit) {
		printf("%-6s %-4s ep%-2u %c %5u B            %04x:%04x %u-%u %s\n",
		       "SUBMIT", xfer_str(e->xfer_type), e->ep, dir, e->length,
		       e->vid, e->product, e->busnum, e->devnum, e->comm);
	} else {
		printf("%-6s %-4s ep%-2u %c %5u/%-5u st=%-3d %6.1fus %04x:%04x %u-%u %s\n",
		       "CMPLT", xfer_str(e->xfer_type), e->ep, dir, e->actual,
		       e->length, e->status, e->latency_ns / 1000.0, e->vid,
		       e->product, e->busnum, e->devnum, e->comm);
	}
}

static void print_json(const struct urb_event *e)
{
	char comm[2 * USBTRACE_COMM_LEN + 1];

	printf("{\"event\":\"%s\",\"type\":\"%s\",\"ep\":%u,\"dir\":\"%s\","
	       "\"actual\":%u,\"length\":%u,\"status\":%d,\"latency_us\":%.1f,"
	       "\"vid\":\"0x%04x\",\"pid\":\"0x%04x\",\"bus\":%u,\"dev\":%u,"
	       "\"comm\":\"%s\"}\n",
	       e->is_submit ? "submit" : "complete", xfer_str(e->xfer_type),
	       e->ep, e->dir_in ? "in" : "out", e->actual, e->length, e->status,
	       e->latency_ns / 1000.0, e->vid, e->product, e->busnum, e->devnum,
	       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
}

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	if (len < sizeof(struct usbtrace_event_hdr))
		return 0;

	const struct urb_event *e = data;

	if (e->hdr.kind != USBTRACE_EVT_URB || len < sizeof(*e))
		return 0;

	if (usbtrace_json)
		print_json(e);
	else
		print_text(e, e->dir_in ? '<' : '>'); /* < IN (dev->host), > OUT */
	return 0;
}

static void urb_on_start(void)
{
	ut_info("tracing URBs... vid=0x%04x pid=0x%04x submit=%d (Ctrl-C to stop)",
		opts.filt.vid, opts.filt.pid, opts.emit_submit);
	if (!usbtrace_json)
		printf("%-6s %-4s %-4s %s %s\n", "EVENT", "TYPE", "EP", "D",
		       "BYTES ...");
}

static int urb_run(volatile bool *running)
{
	struct urb_bpf *skel = urb_bpf__open();
	int rc;

	if (!skel) {
		ut_err("failed to open BPF skeleton");
		return 1;
	}
	skel->rodata->cfg.filter_vid = (unsigned short)opts.filt.vid;
	skel->rodata->cfg.filter_pid = (unsigned short)opts.filt.pid;
	skel->rodata->cfg.emit_submit = opts.emit_submit ? 1 : 0;

	rc = usbtrace_run(&(struct usbtrace_run){
		.skeleton = skel->skeleton,
		.events = skel->maps.events,
		.on_event = handle_event,
		.on_start = urb_on_start,
	}, running);

	urb_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module urb_module = {
	.name = "urb",
	.summary = "trace USB Request Block submit/complete + latency",
	.parse_args = urb_parse_args,
	.usage = urb_usage,
	.run = urb_run,
};

USBTRACE_MODULE_REGISTER(urb_module);

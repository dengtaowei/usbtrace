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
#include "urb.h"
#include "urb.skel.h"

static struct {
	unsigned int vid;
	unsigned int pid;
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
		"  sudo usbtrace urb --vid 0x0403\n");
}

static int urb_parse_args(int argc, char **argv)
{
	static const struct option lo[] = {
		{ "vid", required_argument, 0, 'V' },
		{ "pid", required_argument, 0, 'P' },
		{ "submit", no_argument, 0, 's' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};
	int c;

	/* argv[0] is "urb"; let getopt scan from there. */
	optind = 1;
	while ((c = getopt_long(argc, argv, "h", lo, NULL)) != -1) {
		switch (c) {
		case 'V':
			opts.vid = strtoul(optarg, NULL, 0);
			break;
		case 'P':
			opts.pid = strtoul(optarg, NULL, 0);
			break;
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

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	if (len < sizeof(struct usbtrace_event_hdr))
		return 0;

	const struct urb_event *e = data;

	if (e->hdr.kind != USBTRACE_EVT_URB || len < sizeof(*e))
		return 0;

	char dir = e->dir_in ? '<' : '>'; /* < IN (dev->host), > OUT */

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
	return 0;
}

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt,
			va_list args)
{
	if (lvl == LIBBPF_DEBUG && !usbtrace_verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static int urb_run(volatile bool *running)
{
	struct urb_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	libbpf_set_print(libbpf_print);

	skel = urb_bpf__open();
	if (!skel) {
		ut_err("failed to open BPF skeleton");
		return 1;
	}

	skel->rodata->cfg.filter_vid = (unsigned short)opts.vid;
	skel->rodata->cfg.filter_pid = (unsigned short)opts.pid;
	skel->rodata->cfg.emit_submit = opts.emit_submit ? 1 : 0;

	err = urb_bpf__load(skel);
	if (err) {
		ut_err("failed to load BPF skeleton: %d (need root + BTF?)", err);
		goto cleanup;
	}

	err = urb_bpf__attach(skel);
	if (err) {
		ut_err("failed to attach BPF programs: %d", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      NULL, NULL);
	if (!rb) {
		err = -1;
		ut_err("failed to create ring buffer");
		goto cleanup;
	}

	ut_info("tracing URBs... vid=0x%04x pid=0x%04x submit=%d (Ctrl-C to stop)",
		opts.vid, opts.pid, opts.emit_submit);
	printf("%-6s %-4s %-4s %s %s\n", "EVENT", "TYPE", "EP", "D", "BYTES ...");

	while (*running) {
		err = ring_buffer__poll(rb, 200 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			ut_err("ring buffer poll error: %d", err);
			break;
		}
	}
	if (err > 0)
		err = 0;

cleanup:
	ring_buffer__free(rb);
	urb_bpf__destroy(skel);
	return err ? 1 : 0;
}

static struct usbtrace_module urb_module = {
	.name = "urb",
	.summary = "trace USB Request Block submit/complete + latency",
	.parse_args = urb_parse_args,
	.usage = urb_usage,
	.run = urb_run,
};

USBTRACE_MODULE_REGISTER(urb_module);

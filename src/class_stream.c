// SPDX-License-Identifier: GPL-2.0
/*
 * Shared event consumer for class-traffic modules. See
 * include/usbtrace/class_stream.h. Keeping arg parsing, printing, the health
 * tally and the summary here means each class module (uvc/uac/hid/storage) only
 * opens its skeleton and runs the generic harness with these callbacks.
 */
#include <stdio.h>
#include <getopt.h>

#include "usbtrace/class_stream.h"

static const char *xfer_str(unsigned char t)
{
	switch (t) {
	case USBTRACE_XFER_ISOC:	return "ISOC";
	case USBTRACE_XFER_INT:		return "INT";
	case USBTRACE_XFER_CONTROL:	return "CTRL";
	case USBTRACE_XFER_BULK:	return "BULK";
	default:			return "?";
	}
}

const char *usbtrace_class_str(unsigned char klass)
{
	switch (klass) {
	case USBTRACE_CLASS_VIDEO:	return "video";
	case USBTRACE_CLASS_AUDIO:	return "audio";
	case USBTRACE_CLASS_HID:	return "hid";
	case USBTRACE_CLASS_STORAGE:	return "storage";
	default:			return "class";
	}
}

int class_stream_parse_args(int argc, char **argv, struct usbtrace_filter *filt,
			    bool *all)
{
	static const struct option lo[] = {
		USBTRACE_FILTER_LONGOPTS,
		{ "all", no_argument, 0, 'a' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "ah", lo, NULL)) != -1) {
		if (usbtrace_filter_getopt(c, optarg, filt))
			continue;
		switch (c) {
		case 'a':
			*all = true;
			break;
		case 'h':
			return 1;
		default:
			return -1;
		}
	}
	return 0;
}

static void print_event(const struct class_urb_event *e)
{
	char dir = e->dir_in ? '<' : '>';

	if (usbtrace_json) {
		char comm[2 * USBTRACE_COMM_LEN + 1];

		printf("{\"event\":\"class\",\"class\":\"%s\",\"xfer\":\"%s\","
		       "\"ep\":%u,\"dir\":\"%s\",\"status\":%d,\"error_count\":%d,"
		       "\"packets\":%u,\"bytes\":%u,\"start_frame\":%d,"
		       "\"vid\":\"0x%04x\",\"pid\":\"0x%04x\",\"bus\":%u,\"dev\":%u,"
		       "\"comm\":\"%s\"}\n",
		       usbtrace_class_str(e->klass), xfer_str(e->xfer_type),
		       e->ep, e->dir_in ? "in" : "out", e->status,
		       e->error_count, e->number_of_packets, e->actual_length,
		       e->start_frame, e->vid, e->product, e->busnum, e->devnum,
		       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
	} else {
		printf("%-7s %-4s ep%-2u %c pkts=%-3u err=%-3d %7uB st=%-4d "
		       "%04x:%04x %u-%u %s\n",
		       usbtrace_class_str(e->klass), xfer_str(e->xfer_type),
		       e->ep, dir, e->number_of_packets, e->error_count,
		       e->actual_length, e->status, e->vid, e->product,
		       e->busnum, e->devnum, e->comm);
	}
}

int class_stream_on_event(void *ctx, void *data, size_t len)
{
	struct class_stream_ctx *c = ctx;
	const struct class_urb_event *e = data;
	bool anomaly;

	if (len < sizeof(struct usbtrace_event_hdr))
		return 0;
	if (e->hdr.kind != USBTRACE_EVT_CLASS || len < sizeof(*e))
		return 0;

	anomaly = e->status != 0 || e->error_count > 0;
	c->stats.urbs++;
	c->stats.bytes += e->actual_length;
	if (e->error_count > 0)
		c->stats.isoc_err++;
	if (e->status != 0)
		c->stats.status_err++;

	if (c->all || anomaly)
		print_event(e);
	return 0;
}

void class_stream_summary(const char *modname, const struct class_stats *st)
{
	if (usbtrace_json) {
		printf("{\"event\":\"%s_summary\",\"urbs\":%lu,\"isoc_err\":%lu,"
		       "\"status_err\":%lu,\"bytes\":%llu}\n",
		       modname, st->urbs, st->isoc_err, st->status_err,
		       st->bytes);
		return;
	}
	fprintf(stderr,
		"\n--- %s summary ---\n"
		"URBs:            %lu\n"
		"isoc errors:     %lu (error_count > 0)\n"
		"status errors:   %lu (status != 0)\n"
		"bytes:           %llu\n",
		modname, st->urbs, st->isoc_err, st->status_err, st->bytes);
	if (!st->urbs)
		fprintf(stderr,
			"note: no URBs seen. Is the driver loaded and the "
			"device active?\n");
}

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
	bool ctrl_only;
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
		"Control URBs include the 8-byte setup packet, decoded as\n"
		"SET_FEATURE / CLEAR_FEATURE / GET_STATUS / ... so suspend\n"
		"and resume control traffic is visible by name.\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (e.g. 0x0403)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --submit        also print submission records\n"
		"  --ctrl          only control (ep0) URBs\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace urb --vid 0x0403\n"
		"  sudo usbtrace urb --ctrl --submit --vid 0x1a2c\n"
		"  sudo usbtrace --json urb --vid 0x0403\n");
}

static int urb_parse_args(int argc, char **argv)
{
	static const struct option lo[] = {
		USBTRACE_FILTER_LONGOPTS,
		{ "submit", no_argument, 0, 's' },
		{ "ctrl", no_argument, 0, 'c' },
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
		case 'c':
			opts.ctrl_only = true;
			break;
		case 'h':
			return 1; /* request help */
		default:
			return -1;
		}
	}
	return 0;
}

static unsigned setup_le16(const __u8 *s, int off)
{
	return (unsigned)s[off] | ((unsigned)s[off + 1] << 8);
}

static const char *std_req_name(__u8 req)
{
	switch (req) {
	case 0x00: return "GET_STATUS";
	case 0x01: return "CLEAR_FEATURE";
	case 0x03: return "SET_FEATURE";
	case 0x05: return "SET_ADDRESS";
	case 0x06: return "GET_DESCRIPTOR";
	case 0x07: return "SET_DESCRIPTOR";
	case 0x08: return "GET_CONFIGURATION";
	case 0x09: return "SET_CONFIGURATION";
	case 0x0a: return "GET_INTERFACE";
	case 0x0b: return "SET_INTERFACE";
	case 0x0c: return "SYNCH_FRAME";
	case 0x30: return "SET_SEL";
	case 0x31: return "SET_ISOCH_DELAY";
	default:   return NULL;
	}
}

static const char *desc_type_name(__u8 dt)
{
	switch (dt) {
	case 1:  return "DEVICE";
	case 2:  return "CONFIG";
	case 3:  return "STRING";
	case 4:  return "INTERFACE";
	case 5:  return "ENDPOINT";
	case 6:  return "DEVICE_QUALIFIER";
	case 7:  return "OTHER_SPEED";
	case 8:  return "INTERFACE_POWER";
	case 9:  return "OTG";
	case 15: return "BOS";
	case 33: return "HID";
	case 34: return "HID_REPORT";
	default: return NULL;
	}
}

static const char *feature_name(__u8 type, __u8 recip, unsigned value)
{
	if (type == 0) { /* standard */
		if (recip == 0) { /* device */
			switch (value) {
			case 1:  return "DEVICE_REMOTE_WAKEUP";
			case 2:  return "TEST_MODE";
			case 48: return "U1_ENABLE";
			case 49: return "U2_ENABLE";
			case 50: return "LTM_ENABLE";
			}
		} else if (recip == 1 && value == 0) {
			return "FUNCTION_SUSPEND";
		} else if (recip == 2 && value == 0) {
			return "ENDPOINT_HALT";
		}
	} else if (type == 1 && recip == 3) { /* class, other = hub port */
		switch (value) {
		case 1: return "PORT_ENABLE";
		case 2: return "PORT_SUSPEND";
		case 4: return "PORT_RESET";
		case 5: return "PORT_LINK_STATE";
		case 8: return "PORT_POWER";
		}
	} else if (type == 1 && recip == 0) { /* class, device = hub */
		if (value == 0)
			return "C_HUB_LOCAL_POWER";
		if (value == 1)
			return "C_HUB_OVER_CURRENT";
	}
	return NULL;
}

static const char *link_state_name(unsigned wIndex)
{
	/* wIndex = port | (USB_SS_PORT_LS_* << 3); PLS sits in bits 8-9. */
	switch ((wIndex >> 8) & 0x3) {
	case 0: return "U0";
	case 1: return "U1";
	case 2: return "U2";
	case 3: return "U3";
	default: return NULL;
	}
}

/*
 * Decode an 8-byte usb_ctrlrequest into a short name, e.g.
 * "SET_FEATURE DEVICE_REMOTE_WAKEUP" or "GET_DESCRIPTOR DEVICE".
 * buf is always NUL-terminated; returns buf.
 */
static const char *format_setup(const __u8 *s, char *buf, size_t n)
{
	__u8 rt = s[0];
	__u8 req = s[1];
	unsigned value = setup_le16(s, 2);
	unsigned index = setup_le16(s, 4);
	unsigned length = setup_le16(s, 6);
	__u8 type = (rt >> 5) & 0x3;
	__u8 recip = rt & 0x1f;
	const char *rname = (type == 0) ? std_req_name(req) : NULL;
	const char *fname;
	const char *dname;
	const char *ls;

	if (type == 1 && (req == 0x03 || req == 0x01))
		rname = (req == 0x03) ? "SET_FEATURE" : "CLEAR_FEATURE";
	else if (type == 1 && req == 0x00 && recip == 3)
		rname = "GET_PORT_STATUS";
	else if (type == 1 && recip == 1 && req == 0x09)
		rname = "SET_REPORT";
	else if (type == 1 && recip == 1 && req == 0x0a)
		rname = "SET_IDLE";
	else if (type == 2)
		rname = "VENDOR";

	if (!rname) {
		snprintf(buf, n, "rt=0x%02x req=0x%02x val=%u idx=%u len=%u",
			 rt, req, value, index, length);
		return buf;
	}

	if (req == 0x03 || req == 0x01) {
		fname = feature_name(type, recip, value);
		if (fname && value == 5 && type == 1 && recip == 3) {
			ls = link_state_name(index);
			if (ls)
				snprintf(buf, n, "%s %s %s port%u", rname, fname,
					 ls, index & 0xff);
			else
				snprintf(buf, n, "%s %s port%u", rname, fname,
					 index & 0xff);
		} else if (fname && recip == 1 && value == 0) {
			/* FUNCTION_SUSPEND flags live in wIndex bits 8-9. */
			snprintf(buf, n, "%s %s%s%s iface%u", rname, fname,
				 (index & (1u << 8)) ? "+LP" : "",
				 (index & (1u << 9)) ? "+RW" : "",
				 index & 0xff);
		} else if (fname) {
			snprintf(buf, n, "%s %s", rname, fname);
		} else {
			snprintf(buf, n, "%s val=%u idx=%u", rname, value, index);
		}
		return buf;
	}

	if (type == 0 && (req == 0x06 || req == 0x07)) {
		dname = desc_type_name(value >> 8);
		if (dname)
			snprintf(buf, n, "%s %s", rname, dname);
		else
			snprintf(buf, n, "%s dt=%u", rname, value >> 8);
		return buf;
	}

	if (type == 0 && req == 0x09)
		snprintf(buf, n, "%s %u", rname, value);
	else if (type == 0 && req == 0x0b)
		snprintf(buf, n, "%s iface%u alt%u", rname, index, value);
	else if (type == 0 && req == 0x05)
		snprintf(buf, n, "%s %u", rname, value);
	else if (req == 0x00 && recip == 3)
		snprintf(buf, n, "%s port%u", rname, index);
	else if (req == 0x00)
		snprintf(buf, n, "%s recip=%u", rname, recip);
	else
		snprintf(buf, n, "%s val=%u idx=%u len=%u", rname, value, index,
			 length);
	return buf;
}

static void print_text(const struct urb_event *e, char dir)
{
	char req[96];

	req[0] = '\0';
	if (e->has_setup)
		format_setup(e->setup, req, sizeof(req));

	if (e->is_submit) {
		printf("%-6s %-4s ep%-2u %c %5u B            %-36s %04x:%04x %u-%u %s\n",
		       "SUBMIT", xfer_str(e->xfer_type), e->ep, dir, e->length,
		       req[0] ? req : "-", e->vid, e->product, e->busnum,
		       e->devnum, e->comm);
	} else {
		printf("%-6s %-4s ep%-2u %c %5u/%-5u st=%-3d %6.1fus %-36s %04x:%04x %u-%u %s\n",
		       "CMPLT", xfer_str(e->xfer_type), e->ep, dir, e->actual,
		       e->length, e->status, e->latency_ns / 1000.0,
		       req[0] ? req : "-", e->vid, e->product, e->busnum,
		       e->devnum, e->comm);
	}
}

static void print_json(const struct urb_event *e)
{
	char comm[2 * USBTRACE_COMM_LEN + 1];
	char req[96];

	req[0] = '\0';
	if (e->has_setup)
		format_setup(e->setup, req, sizeof(req));

	printf("{\"event\":\"%s\",\"type\":\"%s\",\"ep\":%u,\"dir\":\"%s\","
	       "\"actual\":%u,\"length\":%u,\"status\":%d,\"latency_us\":%.1f,"
	       "\"vid\":\"0x%04x\",\"pid\":\"0x%04x\",\"bus\":%u,\"dev\":%u,"
	       "\"comm\":\"%s\"",
	       e->is_submit ? "submit" : "complete", xfer_str(e->xfer_type),
	       e->ep, e->dir_in ? "in" : "out", e->actual, e->length, e->status,
	       e->latency_ns / 1000.0, e->vid, e->product, e->busnum, e->devnum,
	       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
	if (e->has_setup) {
		char reqj[2 * sizeof(req) + 1];

		printf(",\"bmRequestType\":\"0x%02x\",\"bRequest\":%u,"
		       "\"wValue\":%u,\"wIndex\":%u,\"wLength\":%u,"
		       "\"request\":\"%s\"",
		       e->setup[0], e->setup[1], setup_le16(e->setup, 2),
		       setup_le16(e->setup, 4), setup_le16(e->setup, 6),
		       usbtrace_json_escape(req, reqj, sizeof(reqj)));
	}
	printf("}\n");
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
	ut_info("tracing URBs... vid=0x%04x pid=0x%04x submit=%d ctrl=%d (Ctrl-C to stop)",
		opts.filt.vid, opts.filt.pid, opts.emit_submit, opts.ctrl_only);
	if (!usbtrace_json)
		printf("%-6s %-4s %-4s %s %s\n", "EVENT", "TYPE", "EP", "D",
		       "BYTES ... REQUEST");
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
	skel->rodata->cfg.ctrl_only = opts.ctrl_only ? 1 : 0;

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

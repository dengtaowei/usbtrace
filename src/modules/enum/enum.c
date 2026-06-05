// SPDX-License-Identifier: GPL-2.0
/*
 * enum module user-space side: configure, load & attach the BPF program, then
 * consume enumeration state-transition events and print them as a timeline.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/libbpf.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "enum.h"
#include "enum.skel.h"

static struct usbtrace_filter opts;

static const char *state_str(__u8 s)
{
	switch (s) {
	case 0: return "NOTATTACHED";
	case 1: return "ATTACHED";
	case 2: return "POWERED";
	case 3: return "RECONNECTING";
	case 4: return "UNAUTHED";
	case 5: return "DEFAULT";
	case 6: return "ADDRESS";
	case 7: return "CONFIGURED";
	case 8: return "SUSPENDED";
	default: return "?";
	}
}

static void enum_usage(void)
{
	fprintf(stderr,
		"usbtrace enum - trace USB enumeration state timeline\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (e.g. 0x0403)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace enum --vid 0x04ca\n"
		"  sudo usbtrace --json enum\n");
}

static int enum_parse_args(int argc, char **argv)
{
	static const struct option lo[] = {
		USBTRACE_FILTER_LONGOPTS,
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 },
	};
	int c;

	optind = 1;
	while ((c = getopt_long(argc, argv, "h", lo, NULL)) != -1) {
		if (usbtrace_filter_getopt(c, optarg, &opts))
			continue;
		switch (c) {
		case 'h':
			return 1;
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

	const struct enum_event *e = data;

	if (e->hdr.kind != USBTRACE_EVT_ENUM || len < sizeof(*e))
		return 0;

	if (usbtrace_json) {
		char comm[2 * USBTRACE_COMM_LEN + 1];
		char path[2 * sizeof(e->devpath) + 1];

		printf("{\"event\":\"enum\",\"from\":\"%s\",\"to\":\"%s\","
		       "\"speed\":\"%s\",\"vid\":\"0x%04x\",\"pid\":\"0x%04x\","
		       "\"bus\":%u,\"dev\":%u,\"port\":%u,\"path\":\"%s\","
		       "\"comm\":\"%s\"}\n",
		       state_str(e->old_state), state_str(e->new_state),
		       usbtrace_speed_str(e->speed), e->vid, e->product,
		       e->busnum, e->devnum, e->portnum,
		       usbtrace_json_escape(e->devpath, path, sizeof(path)),
		       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
	} else {
		printf("%-12s -> %-12s %-6s %04x:%04x %u-%u port%u path=%s %s\n",
		       state_str(e->old_state), state_str(e->new_state),
		       usbtrace_speed_str(e->speed), e->vid, e->product,
		       e->busnum, e->devnum, e->portnum,
		       e->devpath[0] ? e->devpath : "-", e->comm);
	}
	return 0;
}

static int enum_run(volatile bool *running)
{
	struct enum_bpf *skel;
	struct ring_buffer *rb = NULL;
	int err;

	libbpf_set_print(usbtrace_libbpf_print);

	skel = enum_bpf__open();
	if (!skel) {
		ut_err("failed to open BPF skeleton");
		return 1;
	}

	skel->rodata->cfg.filter_vid = (unsigned short)opts.vid;
	skel->rodata->cfg.filter_pid = (unsigned short)opts.pid;

	err = enum_bpf__load(skel);
	if (err) {
		ut_err("failed to load BPF skeleton: %d (need root + BTF?)", err);
		goto cleanup;
	}

	err = enum_bpf__attach(skel);
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

	ut_info("tracing USB enumeration... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		opts.vid, opts.pid);
	if (!usbtrace_json)
		printf("%-12s    %-12s %-6s %s\n", "FROM", "TO", "SPEED",
		       "VID:PID  BUS-DEV PORT PATH COMM");

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
	enum_bpf__destroy(skel);
	return err ? 1 : 0;
}

static struct usbtrace_module enum_module = {
	.name = "enum",
	.summary = "trace USB enumeration state timeline (connect->configured)",
	.parse_args = enum_parse_args,
	.usage = enum_usage,
	.run = enum_run,
};

USBTRACE_MODULE_REGISTER(enum_module);

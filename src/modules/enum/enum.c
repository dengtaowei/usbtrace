// SPDX-License-Identifier: GPL-2.0
/*
 * enum module user-space side: configure, load & attach the BPF program, then
 * consume enumeration state-transition events and print them as a timeline.
 */
#include <stdio.h>

#include <bpf/libbpf.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
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
	return usbtrace_filter_parse(argc, argv, &opts);
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

static void enum_on_start(void)
{
	ut_info("tracing USB enumeration... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		opts.vid, opts.pid);
	if (!usbtrace_json)
		printf("%-12s    %-12s %-6s %s\n", "FROM", "TO", "SPEED",
		       "VID:PID  BUS-DEV PORT PATH COMM");
}

static int enum_run(volatile bool *running)
{
	struct enum_bpf *skel = enum_bpf__open();
	int rc;

	if (!skel) {
		ut_err("failed to open BPF skeleton");
		return 1;
	}
	skel->rodata->cfg.filter_vid = (unsigned short)opts.vid;
	skel->rodata->cfg.filter_pid = (unsigned short)opts.pid;

	rc = usbtrace_run(&(struct usbtrace_run){
		.skeleton = skel->skeleton,
		.events = skel->maps.events,
		.on_event = handle_event,
		.on_start = enum_on_start,
	}, running);

	enum_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module enum_module = {
	.name = "enum",
	.summary = "trace USB enumeration state timeline (connect->configured)",
	.parse_args = enum_parse_args,
	.usage = enum_usage,
	.run = enum_run,
};

USBTRACE_MODULE_REGISTER(enum_module);

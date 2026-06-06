// SPDX-License-Identifier: GPL-2.0
/*
 * lifecycle module user-space side: configure, load & attach the BPF program,
 * then consume connect/disconnect events and print them.
 */
#include <stdio.h>

#include <bpf/libbpf.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "lifecycle.h"
#include "lifecycle.skel.h"

static struct usbtrace_filter opts;

static const char *action_str(__u8 a)
{
	switch (a) {
	case LIFECYCLE_CONNECT:
		return "CONNECT";
	case LIFECYCLE_DISCONNECT:
		return "DISCONNECT";
	default:
		return "?";
	}
}

static void lifecycle_usage(void)
{
	fprintf(stderr,
		"usbtrace lifecycle - trace USB connect/disconnect events\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (e.g. 0x0403)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace lifecycle\n"
		"  sudo usbtrace --json lifecycle\n");
}

static int lifecycle_parse_args(int argc, char **argv)
{
	return usbtrace_filter_parse(argc, argv, &opts);
}

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	if (len < sizeof(struct usbtrace_event_hdr))
		return 0;

	const struct lifecycle_event *e = data;

	if (e->hdr.kind != USBTRACE_EVT_LIFECYCLE || len < sizeof(*e))
		return 0;

	if (usbtrace_json) {
		char comm[2 * USBTRACE_COMM_LEN + 1];
		char path[2 * sizeof(e->devpath) + 1];

		printf("{\"event\":\"lifecycle\",\"action\":\"%s\","
		       "\"speed\":\"%s\",\"vid\":\"0x%04x\",\"pid\":\"0x%04x\","
		       "\"bus\":%u,\"dev\":%u,\"port\":%u,\"path\":\"%s\","
		       "\"comm\":\"%s\"}\n",
		       action_str(e->action), usbtrace_speed_str(e->speed),
		       e->vid, e->product, e->busnum, e->devnum, e->portnum,
		       usbtrace_json_escape(e->devpath, path, sizeof(path)),
		       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
	} else {
		printf("%-10s %-6s %04x:%04x %u-%u port%u path=%s %s\n",
		       action_str(e->action), usbtrace_speed_str(e->speed),
		       e->vid, e->product, e->busnum, e->devnum, e->portnum,
		       e->devpath[0] ? e->devpath : "-", e->comm);
	}
	return 0;
}

static void lifecycle_on_start(void)
{
	ut_info("tracing USB connect/disconnect... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		opts.vid, opts.pid);
	if (!usbtrace_json)
		printf("%-10s %-6s %s\n", "ACTION", "SPEED",
		       "VID:PID  BUS-DEV PORT PATH COMM");
}

static int lifecycle_run(volatile bool *running)
{
	struct lifecycle_bpf *skel = lifecycle_bpf__open();
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
		.on_start = lifecycle_on_start,
	}, running);

	lifecycle_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module lifecycle_module = {
	.name = "lifecycle",
	.summary = "trace USB connect/disconnect events",
	.parse_args = lifecycle_parse_args,
	.usage = lifecycle_usage,
	.run = lifecycle_run,
};

USBTRACE_MODULE_REGISTER(lifecycle_module);

// SPDX-License-Identifier: GPL-2.0
/*
 * power module user-space side: configure, load & attach the BPF program, then
 * consume autosuspend/autoresume events and print them.
 */
#include <stdio.h>

#include <bpf/libbpf.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "power.h"
#include "power.skel.h"

static struct usbtrace_filter opts;

static const char *action_str(__u8 a)
{
	switch (a) {
	case POWER_AUTOSUSPEND:
		return "AUTOSUSPEND";
	case POWER_AUTORESUME:
		return "AUTORESUME";
	default:
		return "?";
	}
}

static void power_usage(void)
{
	fprintf(stderr,
		"usbtrace power - trace USB autosuspend/autoresume events\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (e.g. 0x0403)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace power\n"
		"  sudo usbtrace --json power\n");
}

static int power_parse_args(int argc, char **argv)
{
	return usbtrace_filter_parse(argc, argv, &opts);
}

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	if (len < sizeof(struct usbtrace_event_hdr))
		return 0;

	const struct power_event *e = data;

	if (e->hdr.kind != USBTRACE_EVT_POWER || len < sizeof(*e))
		return 0;

	if (usbtrace_json) {
		char comm[2 * USBTRACE_COMM_LEN + 1];
		char path[2 * sizeof(e->devpath) + 1];

		printf("{\"event\":\"power\",\"action\":\"%s\","
		       "\"speed\":\"%s\",\"vid\":\"0x%04x\",\"pid\":\"0x%04x\","
		       "\"bus\":%u,\"dev\":%u,\"port\":%u,\"path\":\"%s\","
		       "\"comm\":\"%s\"}\n",
		       action_str(e->action), usbtrace_speed_str(e->speed),
		       e->vid, e->product, e->busnum, e->devnum, e->portnum,
		       usbtrace_json_escape(e->devpath, path, sizeof(path)),
		       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
	} else {
		printf("%-11s %-6s %04x:%04x %u-%u port%u path=%s %s\n",
		       action_str(e->action), usbtrace_speed_str(e->speed),
		       e->vid, e->product, e->busnum, e->devnum, e->portnum,
		       e->devpath[0] ? e->devpath : "-", e->comm);
	}
	return 0;
}

static void power_on_start(void)
{
	ut_info("tracing USB power events... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		opts.vid, opts.pid);
	if (!usbtrace_json)
		printf("%-11s %-6s %s\n", "ACTION", "SPEED",
		       "VID:PID  BUS-DEV PORT PATH COMM");
}

static int power_run(volatile bool *running)
{
	struct power_bpf *skel = power_bpf__open();
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
		.on_start = power_on_start,
	}, running);

	power_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module power_module = {
	.name = "power",
	.summary = "trace USB autosuspend/autoresume events",
	.parse_args = power_parse_args,
	.usage = power_usage,
	.run = power_run,
};

USBTRACE_MODULE_REGISTER(power_module);

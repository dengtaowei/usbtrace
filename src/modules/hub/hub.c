// SPDX-License-Identifier: GPL-2.0
/*
 * hub module user-space side: port reset / disable / VBUS power / overcurrent.
 */
#include <stdio.h>

#include <bpf/libbpf.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "hub.h"
#include "hub.skel.h"

static struct usbtrace_filter opts;

static const char *action_str(__u8 a)
{
	switch (a) {
	case HUB_RESET:		return "RESET";
	case HUB_DISABLE:	return "DISABLE";
	case HUB_POWER_OFF:	return "POWER_OFF";
	case HUB_POWER_ON:	return "POWER_ON";
	case HUB_OVERCURRENT:	return "OVERCURRENT";
	default:		return "?";
	}
}

static void hub_usage(void)
{
	fprintf(stderr,
		"usbtrace hub - trace USB hub port reset/disable/power/overcurrent\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (child device, or hub if empty)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace hub\n"
		"  sudo usbtrace --json hub\n");
}

static int hub_parse_args(int argc, char **argv)
{
	return usbtrace_filter_parse(argc, argv, &opts);
}

static int handle_event(void *ctx, void *data, size_t len)
{
	(void)ctx;
	if (len < sizeof(struct usbtrace_event_hdr))
		return 0;

	const struct hub_event *e = data;

	if (e->hdr.kind != USBTRACE_EVT_HUB || len < sizeof(*e))
		return 0;

	if (usbtrace_json) {
		char comm[2 * USBTRACE_COMM_LEN + 1];
		char path[2 * sizeof(e->devpath) + 1];

		printf("{\"event\":\"hub\",\"action\":\"%s\","
		       "\"speed\":\"%s\",\"vid\":\"0x%04x\",\"pid\":\"0x%04x\","
		       "\"bus\":%u,\"dev\":%u,\"port\":%u,\"oc_count\":%u,"
		       "\"warm\":%u,\"path\":\"%s\",\"comm\":\"%s\"}\n",
		       action_str(e->action), usbtrace_speed_str(e->speed),
		       e->vid, e->product, e->busnum, e->devnum, e->portnum,
		       e->oc_count, e->warm,
		       usbtrace_json_escape(e->devpath, path, sizeof(path)),
		       usbtrace_json_escape(e->comm, comm, sizeof(comm)));
	} else {
		if (e->action == HUB_OVERCURRENT)
			printf("%-11s %-6s %04x:%04x %u-%u port%u oc=%u path=%s %s\n",
			       action_str(e->action),
			       usbtrace_speed_str(e->speed), e->vid, e->product,
			       e->busnum, e->devnum, e->portnum, e->oc_count,
			       e->devpath[0] ? e->devpath : "-", e->comm);
		else
			printf("%-11s %-6s %04x:%04x %u-%u port%u path=%s %s\n",
			       action_str(e->action),
			       usbtrace_speed_str(e->speed), e->vid, e->product,
			       e->busnum, e->devnum, e->portnum,
			       e->devpath[0] ? e->devpath : "-", e->comm);
	}
	return 0;
}

static void hub_on_start(void)
{
	ut_info("tracing USB hub port events... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		opts.vid, opts.pid);
	if (!usbtrace_json)
		printf("%-11s %-6s %s\n", "ACTION", "SPEED",
		       "VID:PID  BUS-DEV PORT PATH COMM");
}

static int hub_run(volatile bool *running)
{
	struct hub_bpf *skel = hub_bpf__open();
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
		.on_start = hub_on_start,
	}, running);

	hub_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module hub_module = {
	.name = "hub",
	.summary = "trace USB hub port reset/disable/power/overcurrent",
	.parse_args = hub_parse_args,
	.usage = hub_usage,
	.run = hub_run,
};

USBTRACE_MODULE_REGISTER(hub_module);

// SPDX-License-Identifier: GPL-2.0
/*
 * hid module user-space side (USB HID). Thin wrapper over the shared
 * class-stream consumer + generic run harness. Both hooks (hid_irq_in/out) come
 * from usbhid and attach together. See uvc.c and docs/class.md.
 */
#include <stdio.h>
#include <stdbool.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "usbtrace/class_stream.h"
#include "hid.skel.h"

static struct usbtrace_filter g_filt;
static struct class_stream_ctx g_ctx;

static void hid_usage(void)
{
	fprintf(stderr,
		"usbtrace hid - trace USB HID report flow\n\n"
		"Hooks hid_irq_in / hid_irq_out (usbhid interrupt URB callbacks)\n"
		"and reports per-report direction, status and bytes. Requires\n"
		"usbhid loaded. Tip: input devices report ~constantly when used.\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --all           print every report (default: anomalies only)\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace hid --all --vid 0x1c4f\n"
		"  sudo usbtrace --json hid | jq\n");
}

static int hid_parse_args(int argc, char **argv)
{
	return class_stream_parse_args(argc, argv, &g_filt, &g_ctx.all);
}

static void hid_on_start(void)
{
	ut_info("tracing HID reports... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		g_filt.vid, g_filt.pid);
}

static void hid_on_stop(void)
{
	class_stream_summary("hid", &g_ctx.stats);
}

static int hid_run(volatile bool *running)
{
	struct hid_bpf *skel = hid_bpf__open();
	int rc;

	if (!skel) {
		ut_err("failed to open BPF skeleton");
		return 1;
	}
	skel->rodata->cfg.filter_vid = (unsigned short)g_filt.vid;
	skel->rodata->cfg.filter_pid = (unsigned short)g_filt.pid;

	rc = usbtrace_run(&(struct usbtrace_run){
		.skeleton = skel->skeleton,
		.events = skel->maps.events,
		.on_event = class_stream_on_event,
		.ctx = &g_ctx,
		.on_start = hid_on_start,
		.on_stop = hid_on_stop,
	}, running);

	hid_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module hid_module = {
	.name = "hid",
	.summary = "trace USB HID report flow (in/out, latency, errors)",
	.parse_args = hid_parse_args,
	.usage = hid_usage,
	.run = hid_run,
};

USBTRACE_MODULE_REGISTER(hid_module);

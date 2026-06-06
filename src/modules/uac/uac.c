// SPDX-License-Identifier: GPL-2.0
/*
 * uac module user-space side (USB Audio Class). Thin wrapper over the shared
 * class-stream consumer; see uvc.c for the template and docs/class.md.
 */
#include <stdio.h>
#include <stdbool.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "usbtrace/class_stream.h"
#include "uac.skel.h"

static struct usbtrace_filter g_filt;
static struct class_stream_ctx g_ctx;

static void uac_usage(void)
{
	fprintf(stderr,
		"usbtrace uac - trace USB Audio Class streaming health\n\n"
		"Hooks snd_complete_urb (snd-usb-audio URB callback) and reports\n"
		"per-URB status, isoc error_count, packets and bytes for both\n"
		"playback (OUT) and capture (IN). Requires snd-usb-audio loaded\n"
		"and audio streaming.\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --all           print every URB (default: anomalies only)\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace uac --all\n"
		"  sudo usbtrace --json uac | jq\n");
}

static int uac_parse_args(int argc, char **argv)
{
	return class_stream_parse_args(argc, argv, &g_filt, &g_ctx.all);
}

static void uac_on_start(void)
{
	ut_info("tracing UAC streaming... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		g_filt.vid, g_filt.pid);
}

static void uac_on_stop(void)
{
	class_stream_summary("uac", &g_ctx.stats);
}

static int uac_run(volatile bool *running)
{
	struct uac_bpf *skel = uac_bpf__open();
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
		.on_start = uac_on_start,
		.on_stop = uac_on_stop,
	}, running);

	uac_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module uac_module = {
	.name = "uac",
	.summary = "trace USB Audio Class streaming health (isoc errors, xruns)",
	.parse_args = uac_parse_args,
	.usage = uac_usage,
	.run = uac_run,
};

USBTRACE_MODULE_REGISTER(uac_module);

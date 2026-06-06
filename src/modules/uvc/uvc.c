// SPDX-License-Identifier: GPL-2.0
/*
 * uvc module user-space side (USB Video Class). Thin wrapper over the shared
 * class-stream consumer (include/usbtrace/class_stream.h): open skeleton, set
 * filter, attach the streaming hook, then let the shared code print/tally.
 */
#include <stdio.h>
#include <stdbool.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "usbtrace/class_stream.h"
#include "uvc.skel.h"

static struct usbtrace_filter g_filt;
static struct class_stream_ctx g_ctx;

static void uvc_usage(void)
{
	fprintf(stderr,
		"usbtrace uvc - trace USB Video Class streaming health\n\n"
		"Hooks uvc_video_complete (uvcvideo streaming URB callback) and\n"
		"reports per-URB status, isoc error_count, packets and bytes.\n"
		"Requires uvcvideo loaded and a UVC camera streaming.\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor (e.g. 0x046d)\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --all           print every URB (default: anomalies only)\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace uvc --all --vid 0x046d\n"
		"  sudo usbtrace --json uvc | jq\n");
}

static int uvc_parse_args(int argc, char **argv)
{
	return class_stream_parse_args(argc, argv, &g_filt, &g_ctx.all);
}

static void uvc_on_start(void)
{
	ut_info("tracing UVC streaming... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		g_filt.vid, g_filt.pid);
}

static void uvc_on_stop(void)
{
	class_stream_summary("uvc", &g_ctx.stats);
}

static int uvc_run(volatile bool *running)
{
	struct uvc_bpf *skel = uvc_bpf__open();
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
		.on_start = uvc_on_start,
		.on_stop = uvc_on_stop,
	}, running);

	uvc_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module uvc_module = {
	.name = "uvc",
	.summary = "trace USB Video Class streaming health (isoc errors, frame drops)",
	.parse_args = uvc_parse_args,
	.usage = uvc_usage,
	.run = uvc_run,
};

USBTRACE_MODULE_REGISTER(uvc_module);

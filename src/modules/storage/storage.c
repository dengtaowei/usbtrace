// SPDX-License-Identifier: GPL-2.0
/*
 * storage module user-space side (USB Mass Storage / BOT). Thin wrapper over
 * the shared class-stream consumer; see uvc.c and docs/class.md.
 */
#include <stdio.h>
#include <stdbool.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"
#include "usbtrace/run.h"
#include "usbtrace/class_stream.h"
#include "storage.skel.h"

static struct usbtrace_filter g_filt;
static struct class_stream_ctx g_ctx;

static void storage_usage(void)
{
	fprintf(stderr,
		"usbtrace storage - trace USB Mass Storage transport health\n\n"
		"Hooks usb_stor_blocking_completion (usb-storage bulk URB\n"
		"callback) and reports per-URB status and bytes across the\n"
		"CBW/data/CSW phases. Requires usb-storage loaded and a BOT mass\n"
		"storage device (note: UAS devices use a different driver).\n\n"
		"Options:\n"
		"  --vid <hex>     filter by idVendor\n"
		"  --pid <hex>     filter by idProduct\n"
		"  --all           print every URB (default: anomalies only)\n"
		"  -h, --help      this help\n\n"
		"Example:\n"
		"  sudo usbtrace storage --all\n"
		"  sudo usbtrace --json storage | jq\n");
}

static int storage_parse_args(int argc, char **argv)
{
	return class_stream_parse_args(argc, argv, &g_filt, &g_ctx.all);
}

static void storage_on_start(void)
{
	ut_info("tracing USB storage... vid=0x%04x pid=0x%04x (Ctrl-C to stop)",
		g_filt.vid, g_filt.pid);
}

static void storage_on_stop(void)
{
	class_stream_summary("storage", &g_ctx.stats);
}

static int storage_run(volatile bool *running)
{
	struct storage_bpf *skel = storage_bpf__open();
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
		.on_start = storage_on_start,
		.on_stop = storage_on_stop,
	}, running);

	storage_bpf__destroy(skel);
	return rc;
}

static struct usbtrace_module storage_module = {
	.name = "storage",
	.summary = "trace USB Mass Storage transport health (stalls, errors)",
	.parse_args = storage_parse_args,
	.usage = storage_usage,
	.run = storage_run,
};

USBTRACE_MODULE_REGISTER(storage_module);

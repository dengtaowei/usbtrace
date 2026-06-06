// SPDX-License-Identifier: GPL-2.0
/*
 * usbtrace - eBPF-based USB subsystem tracer and diagnostic tool for Linux BSP.
 *
 * Usage:
 *     usbtrace [global-opts] <module> [module-opts]
 *     usbtrace list
 *     usbtrace help [module]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>

#include "usbtrace/module.h"
#include "usbtrace/log.h"
#include "usbtrace/cli.h"

#ifndef USBTRACE_VERSION
#define USBTRACE_VERSION "0.0.1-dev"
#endif

int usbtrace_verbose;
int usbtrace_json;

static volatile bool g_running = true;

static void on_signal(int sig)
{
	(void)sig;
	g_running = false;
}

static void print_modules(void)
{
	struct usbtrace_module *m;

	fprintf(stderr, "Available modules:\n");
	for (m = usbtrace_modules(); m; m = m->next)
		fprintf(stderr, "  %-12s %s\n", m->name,
			m->summary ? m->summary : "");
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usbtrace %s - eBPF USB subsystem tracer & diagnostic tool\n\n"
		"Usage:\n"
		"  %s [global-opts] <module> [module-opts]\n"
		"  %s list\n"
		"  %s help [module]\n\n"
		"Global options:\n"
		"  -v, --verbose   verbose/debug logging\n"
		"  -j, --json      emit one JSON object per event (machine-readable)\n"
		"  -V, --version   print version and exit\n"
		"  -h, --help      this help\n\n",
		USBTRACE_VERSION, prog, prog, prog);
	print_modules();
}

int main(int argc, char **argv)
{
	const char *prog = "usbtrace";
	int i = 1;

	/* Route libbpf logs through our level-aware printer for every module. */
	libbpf_set_print(usbtrace_libbpf_print);

	/* Global options must precede the module name. */
	for (; i < argc; i++) {
		const char *a = argv[i];

		if (a[0] != '-')
			break;
		if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
			usbtrace_verbose = 1;
		} else if (!strcmp(a, "-j") || !strcmp(a, "--json")) {
			usbtrace_json = 1;
		} else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
			printf("usbtrace %s\n", USBTRACE_VERSION);
			return 0;
		} else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage(prog);
			return 0;
		} else {
			ut_err("unknown global option: %s", a);
			usage(prog);
			return 2;
		}
	}

	if (i >= argc) {
		usage(prog);
		return 2;
	}

	const char *cmd = argv[i];

	if (!strcmp(cmd, "list")) {
		print_modules();
		return 0;
	}

	if (!strcmp(cmd, "help")) {
		if (i + 1 < argc) {
			struct usbtrace_module *m =
				usbtrace_find_module(argv[i + 1]);
			if (!m) {
				ut_err("unknown module: %s", argv[i + 1]);
				return 2;
			}
			if (m->usage)
				m->usage();
			else
				fprintf(stderr, "%s: %s\n", m->name,
					m->summary ? m->summary : "(no help)");
			return 0;
		}
		usage(prog);
		return 0;
	}

	struct usbtrace_module *mod = usbtrace_find_module(cmd);

	if (!mod) {
		ut_err("unknown module: %s", cmd);
		print_modules();
		return 2;
	}

	/* Hand the rest of argv (starting at the module name) to the module. */
	int margc = argc - i;
	char **margv = &argv[i];

	if (mod->parse_args) {
		int rc = mod->parse_args(margc, margv);

		if (rc > 0) { /* module requested help */
			if (mod->usage)
				mod->usage();
			return 0;
		}
		if (rc < 0)
			return 2;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	return mod->run(&g_running);
}

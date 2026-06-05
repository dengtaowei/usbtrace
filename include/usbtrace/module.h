/* SPDX-License-Identifier: GPL-2.0 */
/*
 * usbtrace module interface.
 *
 * A "module" is a self-contained tracer/diagnoser (e.g. urb, enum, uac, uvc).
 * Each module owns its own BPF object + skeleton and registers itself at load
 * time via USBTRACE_MODULE_REGISTER(). The core (main.c) only sees this struct
 * and never needs to know the concrete module implementation.
 *
 * Lifecycle for the selected module:
 *     parse_args() -> run() ... (until *running == false) ... cleanup happens
 *     inside run() before it returns.
 */
#ifndef __USBTRACE_MODULE_H
#define __USBTRACE_MODULE_H

#include <stdbool.h>

struct usbtrace_module {
	const char *name;	/* subcommand, e.g. "urb" */
	const char *summary;	/* one-line description for `usbtrace list` */

	/* Parse module-specific argv (argv[0] is the module name). Return 0 on
	 * success, <0 on error, >0 to request help-and-exit. Optional. */
	int (*parse_args)(int argc, char **argv);

	/* Print module-specific usage. Optional. */
	void (*usage)(void);

	/* Load + attach BPF, then poll events until *running becomes false.
	 * Must perform its own cleanup. Returns process exit code. Required. */
	int (*run)(volatile bool *running);

	/* Internal: registry linkage. Do not set manually. */
	struct usbtrace_module *next;
};

void usbtrace_register_module(struct usbtrace_module *mod);
struct usbtrace_module *usbtrace_find_module(const char *name);
struct usbtrace_module *usbtrace_modules(void); /* head of the list */

#define USBTRACE_MODULE_REGISTER(modvar)                                       \
	__attribute__((constructor)) static void usbtrace__reg_##modvar(void)  \
	{                                                                      \
		usbtrace_register_module(&(modvar));                           \
	}

#endif /* __USBTRACE_MODULE_H */

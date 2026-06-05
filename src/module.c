// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include "usbtrace/module.h"

static struct usbtrace_module *g_modules;

void usbtrace_register_module(struct usbtrace_module *mod)
{
	/* Keep registration order stable by appending to the tail. Called from
	 * constructors before main(), so no locking is needed. */
	struct usbtrace_module **pp = &g_modules;

	while (*pp)
		pp = &(*pp)->next;
	mod->next = NULL;
	*pp = mod;
}

struct usbtrace_module *usbtrace_find_module(const char *name)
{
	struct usbtrace_module *m;

	for (m = g_modules; m; m = m->next) {
		if (strcmp(m->name, name) == 0)
			return m;
	}
	return NULL;
}

struct usbtrace_module *usbtrace_modules(void)
{
	return g_modules;
}

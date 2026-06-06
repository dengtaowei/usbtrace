/* SPDX-License-Identifier: GPL-2.0 */
/*
 * diag rule loader: parse a YAML knowledge base (via libyaml) into the engine's
 * rule model. Rules can come from an external file (--rules) or the default
 * knowledge base embedded at build time, so the binary works standalone yet
 * stays user-extensible without recompiling.
 */
#ifndef __USBTRACE_DIAG_RULES_H
#define __USBTRACE_DIAG_RULES_H

#include "engine.h"

/* Parse YAML text into a freshly allocated rule array. On success returns the
 * number of rules (>=0) and sets *out to a malloc'd array (free with
 * diag_rules_free). On error returns <0 and writes a message to err. */
int diag_rules_parse(const char *text, size_t len, struct diag_rule **out,
		     char *err, size_t errsz);

/* Load rules from a file path. Returns rule count or <0 on error. */
int diag_rules_load_file(const char *path, struct diag_rule **out, char *err,
			 size_t errsz);

/* Load the default knowledge base embedded at build time. */
int diag_rules_load_default(struct diag_rule **out, char *err, size_t errsz);

#endif /* __USBTRACE_DIAG_RULES_H */

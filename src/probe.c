// SPDX-License-Identifier: GPL-2.0
/*
 * Hook feature-probing + per-program graceful degradation. See usbtrace/probe.h.
 */
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "usbtrace/probe.h"
#include "usbtrace/log.h"

/* tracefs is mounted at one of these (newer kernels prefer the first). */
static const char *const TRACEFS[] = {
	"/sys/kernel/tracing",
	"/sys/kernel/debug/tracing",
	NULL,
};

/*
 * Does `name` appear as a symbol in `path`? `sym_field` is the whitespace-
 * separated token index holding the symbol (0 for available_filter_functions
 * "symbol [mod]", 2 for kallsyms "addr type symbol [mod]").
 * Returns 1 found, 0 not found, -1 if the file can't be read.
 */
static int symbol_in_file(const char *path, const char *name, int sym_field)
{
	char line[512];
	FILE *f;

	f = fopen(path, "re");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		char *save = NULL, *tok;
		int i = 0;

		for (tok = strtok_r(line, " \t\n", &save); tok;
		     tok = strtok_r(NULL, " \t\n", &save), i++) {
			if (i == sym_field) {
				if (!strcmp(tok, name)) {
					fclose(f);
					return 1;
				}
				break;
			}
		}
	}
	fclose(f);
	return 0;
}

int usbtrace_kfunc_available(const char *name)
{
	char path[256];
	int i, r, readable = 0;

	if (!name || !*name)
		return -1;

	/*
	 * Take the UNION of two sources and only declare a function absent when
	 * at least one was readable and neither matched. This avoids wrongly
	 * disabling a working hook:
	 *  - kallsyms is the ground truth for "symbol exists" (kprobe attaches
	 *    by name -> address), and lists module functions when loaded;
	 *  - available_filter_functions covers the ftrace/fentry view.
	 * kallsyms can miss notrace funcs that AFF has, and vice versa, so a
	 * hit in EITHER means available.
	 */
	r = symbol_in_file("/proc/kallsyms", name, 2);
	if (r == 1)
		return 1;
	if (r == 0)
		readable = 1;

	for (i = 0; TRACEFS[i]; i++) {
		snprintf(path, sizeof(path), "%s/available_filter_functions",
			 TRACEFS[i]);
		r = symbol_in_file(path, name, 0);
		if (r == 1)
			return 1;
		if (r == 0)
			readable = 1;
	}
	return readable ? 0 : -1;	/* -1 = nothing readable => fail-open */
}

int usbtrace_tracepoint_available(const char *subsys, const char *event)
{
	char path[256];
	int i, have_base = 0;

	if (!subsys || !event)
		return -1;

	for (i = 0; TRACEFS[i]; i++) {
		snprintf(path, sizeof(path), "%s/events", TRACEFS[i]);
		if (access(path, F_OK) == 0)
			have_base = 1;
		snprintf(path, sizeof(path), "%s/events/%s/%s", TRACEFS[i],
			 subsys, event);
		if (access(path, F_OK) == 0)
			return 1;
	}
	/* Base events dir exists but this tracepoint doesn't => absent.
	 * No tracefs at all => unknown (fail-open). */
	return have_base ? 0 : -1;
}

/*
 * Is a tracepoint with this event name present in any subsystem?
 * (e.g. "vb2_v4l2_buf_done" under v4l2 on 5.15, "vb2_buf_done" under vb2 on 6.x)
 */
int usbtrace_tracepoint_event_available(const char *event)
{
	char path[256];
	int i, have_base = 0;

	if (!event || !*event)
		return -1;

	for (i = 0; TRACEFS[i]; i++) {
		DIR *d;
		struct dirent *de;

		snprintf(path, sizeof(path), "%s/events", TRACEFS[i]);
		d = opendir(path);
		if (!d)
			continue;
		have_base = 1;
		while ((de = readdir(d)) != NULL) {
			char evtpath[384];

			if (de->d_name[0] == '.')
				continue;
			snprintf(evtpath, sizeof(evtpath), "%s/%s/%s", path,
				 de->d_name, event);
			if (access(evtpath, F_OK) == 0) {
				closedir(d);
				return 1;
			}
		}
		closedir(d);
	}
	return have_base ? 0 : -1;
}

/*
 * Map a SEC() name to an availability verdict (1/0/-1). Unknown SEC forms return
 * -1 (fail-open) so we never disable a hook we don't understand.
 */
static int sec_available(const char *sec)
{
	const char *slash;

	if (!sec)
		return -1;
	slash = strchr(sec, '/');
	if (!slash)
		return -1;	/* no target encoded; let libbpf handle it */

	/* Function-attach forms: "<kind>/<func>" */
	if (!strncmp(sec, "kprobe/", 7) || !strncmp(sec, "kretprobe/", 10) ||
	    !strncmp(sec, "fentry/", 7) || !strncmp(sec, "fexit/", 6) ||
	    !strncmp(sec, "fmod_ret/", 9))
		return usbtrace_kfunc_available(slash + 1);

	/* Tracepoint forms: "<kind>/<subsys>/<event>" */
	if (!strncmp(sec, "tracepoint/", 11) || !strncmp(sec, "tp/", 3)) {
		const char *subsys = slash + 1;
		const char *slash2 = strchr(subsys, '/');
		char sb[64];
		size_t n;

		if (!slash2)
			return -1;
		n = (size_t)(slash2 - subsys);
		if (n >= sizeof(sb))
			return -1;
		memcpy(sb, subsys, n);
		sb[n] = '\0';
		return usbtrace_tracepoint_available(sb, slash2 + 1);
	}

	/* raw_tp/tp_btf: "<kind>/<event>" — scan all tracepoint subsystems. */
	if (!strncmp(sec, "raw_tracepoint/", 15) ||
	    !strncmp(sec, "raw_tp/", 7) || !strncmp(sec, "tp_btf/", 7))
		return usbtrace_tracepoint_event_available(slash + 1);

	return -1;
}

int usbtrace_autoload_filter(struct bpf_object *obj)
{
	struct bpf_program *prog;
	int enabled = 0;

	bpf_object__for_each_program(prog, obj) {
		const char *sec = bpf_program__section_name(prog);

		if (sec_available(sec) == 0) {
			ut_warn("hook '%s' not present on this kernel; skipping",
				sec);
			bpf_program__set_autoload(prog, false);
			continue;
		}
		enabled++;
	}
	return enabled;
}

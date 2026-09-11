// SPDX-License-Identifier: GPL-2.0
/*
 * Shared module run harness. See include/usbtrace/run.h.
 *
 * Transport-agnostic: the ringbuf/perf split lives entirely in evmux.c.
 */
#include <errno.h>

#include "usbtrace/run.h"
#include "usbtrace/evmux.h"
#include "usbtrace/log.h"
#include "usbtrace/probe.h"

int usbtrace_run(const struct usbtrace_run *r, volatile bool *running)
{
	struct usbtrace_evmux *mux = NULL;
	int err;

	/* Per-program feature probe: disable hooks whose target is absent on
	 * this kernel so one missing function doesn't sink the whole module. */
	if (usbtrace_autoload_filter(*r->skeleton->obj) == 0) {
		ut_err("no supported hooks on this kernel for this module");
		return 1;
	}

	err = bpf_object__load_skeleton(r->skeleton);
	if (err) {
		ut_err("failed to load BPF skeleton: %d (need root + BTF?)", err);
		return 1;
	}

	err = bpf_object__attach_skeleton(r->skeleton);
	if (err) {
		ut_err("failed to attach BPF programs: %d", err);
		return 1;
	}

	mux = usbtrace_evmux_new(r->on_event, r->ctx);
	if (!mux) {
		ut_err("failed to allocate event consumer");
		return 1;
	}
	err = usbtrace_evmux_add(mux, r->events);
	if (err) {
		ut_err("failed to open the events map: %d", err);
		usbtrace_evmux_free(mux);
		return 1;
	}

	if (r->on_start)
		r->on_start();

	while (*running) {
		err = usbtrace_evmux_poll(mux, 200 /* ms */);
		if (err < 0) {
			/*
			 * EINTR is normal: Ctrl-C, and also system suspend /
			 * resume interrupting epoll_wait. Only stop when the
			 * signal handler cleared *running. EAGAIN is likewise
			 * transient around sleep/wake.
			 */
			if (err == -EINTR || err == -EAGAIN) {
				ut_dbg("event poll interrupted: %d", err);
				err = 0;
				continue;
			}
			ut_err("event poll error: %d", err);
			break;
		}
	}
	if (err > 0)
		err = 0;

	if (r->on_stop)
		r->on_stop();

	usbtrace_evmux_free(mux);
	return err ? 1 : 0;
}

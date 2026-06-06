// SPDX-License-Identifier: GPL-2.0
/*
 * Shared module run harness. See include/usbtrace/run.h.
 */
#include <errno.h>

#include "usbtrace/run.h"
#include "usbtrace/log.h"

int usbtrace_run(const struct usbtrace_run *r, volatile bool *running)
{
	struct ring_buffer *rb = NULL;
	int err;

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

	rb = ring_buffer__new(bpf_map__fd(r->events), r->on_event, r->ctx, NULL);
	if (!rb) {
		ut_err("failed to create ring buffer");
		return 1;
	}

	if (r->on_start)
		r->on_start();

	while (*running) {
		err = ring_buffer__poll(rb, 200 /* ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			ut_err("ring buffer poll error: %d", err);
			break;
		}
	}
	if (err > 0)
		err = 0;

	if (r->on_stop)
		r->on_stop();

	ring_buffer__free(rb);
	return err ? 1 : 0;
}

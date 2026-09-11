// SPDX-License-Identifier: GPL-2.0
/*
 * Event consumer: ringbuf or perf-event-array. See include/usbtrace/evmux.h.
 *
 * Keeping both back-ends here is deliberate: every other user-space file stays
 * free of transport #ifdefs.
 */
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/epoll.h>

#include "usbtrace/evmux.h"
#include "usbtrace/log.h"

/* Room for diag's sources (4 core + 4 class today) with headroom. */
#define EVMUX_MAX_SRCS 16

#ifdef USBTRACE_USE_PERF

/*
 * perf_buffer pages per CPU (4 KiB each). Sized to stay in the same order of
 * magnitude as the 256 KiB ringbuf, otherwise urb/uvc drop under load.
 * Override with `make USBTRACE_PERF_PAGES=<n>` (see config.mk).
 */
#ifndef USBTRACE_PERF_PAGES
#define USBTRACE_PERF_PAGES 64
#endif

/* libbpf's perf sample callback returns void; adapt to ring_buffer_sample_fn. */
struct perf_adapt {
	ring_buffer_sample_fn on_event;
	void *ctx;
};

struct usbtrace_evmux {
	ring_buffer_sample_fn on_event;
	void *ctx;
	struct perf_buffer *pbs[EVMUX_MAX_SRCS];
	struct perf_adapt adapts[EVMUX_MAX_SRCS];
	int npb;
	/*
	 * One outer epoll over each perf_buffer's own epoll fd (epoll fds are
	 * themselves pollable). This gives the same "block once, wake on any
	 * source" behaviour as the ringbuf backend, instead of walking every
	 * buffer on each iteration.
	 */
	int epfd;
};

static void perf_sample_cb(void *ctx, int cpu, void *data, __u32 size)
{
	struct perf_adapt *a = ctx;

	(void)cpu;
	a->on_event(a->ctx, data, size);
}

static void perf_lost_cb(void *ctx, int cpu, __u64 cnt)
{
	(void)ctx;
	ut_warn("perf buffer lost %llu event(s) on cpu %d (raise USBTRACE_PERF_PAGES)",
		(unsigned long long)cnt, cpu);
}

struct usbtrace_evmux *usbtrace_evmux_new(ring_buffer_sample_fn cb, void *ctx)
{
	struct usbtrace_evmux *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	m->on_event = cb;
	m->ctx = ctx;
	m->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (m->epfd < 0) {
		free(m);
		return NULL;
	}
	return m;
}

int usbtrace_evmux_add(struct usbtrace_evmux *m, struct bpf_map *events)
{
	struct epoll_event ee = { .events = EPOLLIN };
	struct perf_buffer *pb;
	int fd, err;

	if (!m || !events)
		return -EINVAL;
	fd = bpf_map__fd(events);
	if (fd < 0)
		return -EINVAL;
	if (m->npb >= EVMUX_MAX_SRCS)
		return -ENOSPC;

	m->adapts[m->npb].on_event = m->on_event;
	m->adapts[m->npb].ctx = m->ctx;
	pb = perf_buffer__new(fd, USBTRACE_PERF_PAGES, perf_sample_cb,
			      perf_lost_cb, &m->adapts[m->npb], NULL);
	if (!pb)
		return -errno;

	ee.data.u32 = (__u32)m->npb;
	err = epoll_ctl(m->epfd, EPOLL_CTL_ADD, perf_buffer__epoll_fd(pb), &ee);
	if (err) {
		err = -errno;
		perf_buffer__free(pb);
		return err;
	}
	m->pbs[m->npb++] = pb;
	return 0;
}

int usbtrace_evmux_poll(struct usbtrace_evmux *m, int timeout_ms)
{
	struct epoll_event evs[EVMUX_MAX_SRCS];
	int i, ready, n = 0;

	if (!m || m->npb == 0)
		return -EINVAL;

	ready = epoll_wait(m->epfd, evs, m->npb, timeout_ms);
	if (ready < 0)
		return -errno;

	/* Only drain the sources that actually have data; each consume is
	 * non-blocking, so a quiet source costs nothing. */
	for (i = 0; i < ready; i++) {
		struct perf_buffer *pb = m->pbs[evs[i].data.u32];
		int err = perf_buffer__poll(pb, 0);

		if (err < 0) {
			if (err == -EINTR || err == -EAGAIN)
				continue;
			return err;
		}
		n += err;
	}
	return n;
}

void usbtrace_evmux_free(struct usbtrace_evmux *m)
{
	int i;

	if (!m)
		return;
	for (i = 0; i < m->npb; i++)
		perf_buffer__free(m->pbs[i]);
	if (m->epfd >= 0)
		close(m->epfd);
	free(m);
}

#else /* ringbuf */

struct usbtrace_evmux {
	ring_buffer_sample_fn on_event;
	void *ctx;
	struct ring_buffer *rb;
};

struct usbtrace_evmux *usbtrace_evmux_new(ring_buffer_sample_fn cb, void *ctx)
{
	struct usbtrace_evmux *m = calloc(1, sizeof(*m));

	if (!m)
		return NULL;
	m->on_event = cb;
	m->ctx = ctx;
	return m;
}

int usbtrace_evmux_add(struct usbtrace_evmux *m, struct bpf_map *events)
{
	int fd;

	if (!m || !events)
		return -EINVAL;
	fd = bpf_map__fd(events);
	if (fd < 0)
		return -EINVAL;

	/* ring_buffer__new creates the epoll set; further maps just join it. */
	if (m->rb)
		return ring_buffer__add(m->rb, fd, m->on_event, m->ctx);
	m->rb = ring_buffer__new(fd, m->on_event, m->ctx, NULL);
	return m->rb ? 0 : -errno;
}

int usbtrace_evmux_poll(struct usbtrace_evmux *m, int timeout_ms)
{
	if (!m || !m->rb)
		return -EINVAL;
	return ring_buffer__poll(m->rb, timeout_ms);
}

void usbtrace_evmux_free(struct usbtrace_evmux *m)
{
	if (!m)
		return;
	ring_buffer__free(m->rb);
	free(m);
}

#endif /* USBTRACE_USE_PERF */

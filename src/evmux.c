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

/*
 * Cap on per-CPU perf fds registered into the flat epoll set.
 * events map max_entries is 128; 16 sources → plenty of headroom for online CPUs.
 */
#define EVMUX_MAX_PERF_FDS 512

/* libbpf's perf sample callback returns void; adapt to ring_buffer_sample_fn. */
struct perf_adapt {
	ring_buffer_sample_fn on_event;
	void *ctx;
	unsigned *sample_counter;
};

struct usbtrace_evmux {
	ring_buffer_sample_fn on_event;
	void *ctx;
	struct perf_buffer *pbs[EVMUX_MAX_SRCS];
	struct perf_adapt adapts[EVMUX_MAX_SRCS];
	int npb;
	/*
	 * Flat epoll over every per-CPU perf_event fd (perf_buffer__buffer_fd).
	 * Do NOT epoll_ctl a perf_buffer__epoll_fd into another epoll: nested
	 * epoll-of-epoll wakes the outer fd while the inner epoll_wait(0) still
	 * sees no ready CPUs, and unread samples sit in the mmap ring forever
	 * (observed on Linux 5.4 / ARM). Epoll here is only for sleeping;
	 * draining always goes through perf_buffer__consume() (mmap is truth).
	 */
	int epfd;
	unsigned samples;
};

static void perf_sample_cb(void *ctx, int cpu, void *data, __u32 size)
{
	struct perf_adapt *a = ctx;

	(void)cpu;
	if (a->sample_counter)
		(*a->sample_counter)++;
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
	struct perf_buffer *pb;
	size_t c, ncpu;
	int fd;

	if (!m || !events)
		return -EINVAL;
	fd = bpf_map__fd(events);
	if (fd < 0)
		return -EINVAL;
	if (m->npb >= EVMUX_MAX_SRCS)
		return -ENOSPC;

	m->adapts[m->npb].on_event = m->on_event;
	m->adapts[m->npb].ctx = m->ctx;
	m->adapts[m->npb].sample_counter = &m->samples;
	pb = perf_buffer__new(fd, USBTRACE_PERF_PAGES, perf_sample_cb,
			      perf_lost_cb, &m->adapts[m->npb], NULL);
	if (!pb)
		return -errno;

	ncpu = perf_buffer__buffer_cnt(pb);
	for (c = 0; c < ncpu; c++) {
		struct epoll_event ee = { .events = EPOLLIN };
		int cfd = perf_buffer__buffer_fd(pb, c);

		if (cfd < 0)
			continue; /* sparse offline CPU slot */
		ee.data.u32 = (__u32)m->npb; /* which source; drain uses consume() */
		if (epoll_ctl(m->epfd, EPOLL_CTL_ADD, cfd, &ee)) {
			int err = -errno;

			perf_buffer__free(pb);
			return err;
		}
	}

	m->pbs[m->npb++] = pb;
	return 0;
}

int usbtrace_evmux_poll(struct usbtrace_evmux *m, int timeout_ms)
{
	struct epoll_event evs[EVMUX_MAX_PERF_FDS];
	int i, ready;

	if (!m || m->npb == 0)
		return -EINVAL;

	m->samples = 0;

	/*
	 * Block until any per-CPU perf fd is readable (or timeout). Then drain
	 * every source via consume(): that walks the mmap rings directly and
	 * does not depend on a nested epoll_wait seeing the same readiness.
	 */
	ready = epoll_wait(m->epfd, evs, EVMUX_MAX_PERF_FDS, timeout_ms);
	if (ready < 0)
		return -errno;
	(void)evs;
	(void)ready;

	for (i = 0; i < m->npb; i++) {
		int err = perf_buffer__consume(m->pbs[i]);

		if (err < 0) {
			if (err == -EINTR || err == -EAGAIN)
				continue;
			return err;
		}
	}
	return (int)m->samples;
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

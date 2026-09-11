/* SPDX-License-Identifier: GPL-2.0 */
/*
 * BPF-side compatibility when vmlinux.h comes from an older kernel (e.g. 5.4).
 * Pick the event backend in config.mk (USBTRACE_EVENTS); do not build ringbuf
 * against a 5.4 kernel expecting it to load.
 *
 * Include after vmlinux.h / bpf_helpers.h.
 */
#ifndef __USBTRACE_COMPAT_BPF_H
#define __USBTRACE_COMPAT_BPF_H

#ifndef BPF_ANY
#define BPF_ANY 0
#endif

#ifndef BPF_EXIST
#define BPF_EXIST 1
#endif

#ifndef BPF_NOEXIST
#define BPF_NOEXIST 2
#endif

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU (0xffffffffULL)
#endif

/* Only needed when compiling the ringbuf backend against older BTF. */
#if !defined(USBTRACE_USE_PERF) && !defined(BPF_MAP_TYPE_RINGBUF)
#define BPF_MAP_TYPE_RINGBUF 27
#endif

#endif /* __USBTRACE_COMPAT_BPF_H */

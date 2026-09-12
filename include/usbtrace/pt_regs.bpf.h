/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Portable kprobe argument access for 32-bit arches.
 *
 * BPF programs are compiled with 64-bit `unsigned long`, but ARM32/i386
 * kernels store pt_regs GPRs as 32-bit slots. libbpf's PT_REGS_PARM<N>()
 * expands to `ctx->uregs[N]`, and clang scales N by sizeof(unsigned long)==8,
 * so PARM2+ hit the wrong register. PARM1 (byte offset 0) still works, which
 * is why single-arg kprobes look fine while
 * usb_hcd_giveback_urb(hcd, urb, status) gets a garbage `urb`.
 *
 * Do NOT bpf_probe_read_kernel() from (char *)ctx + N: on kernels like 5.4 the
 * kprobe context pointer is a verifier CTX, not a plain kernel pointer, and
 * those reads return 0 — every multi-arg probe then sees NULL arguments.
 * Index the CTX as `__u32 *` instead; the verifier lowers that to a CTX-relative
 * load with a 4-byte stride that matches the real pt_regs.
 *
 * Include after vmlinux.h / bpf_helpers.h / bpf_tracing.h.
 */
#ifndef __USBTRACE_PT_REGS_BPF_H
#define __USBTRACE_PT_REGS_BPF_H

#if defined(__TARGET_ARCH_arm) || defined(__TARGET_ARCH_i386)

static __always_inline __u64 usbtrace_pt_parm(const struct pt_regs *ctx, int idx)
{
	/* 4-byte GPR slots; uregs[0] is at offset 0 on arm and i386. */
	return (__u64)((const volatile __u32 *)ctx)[idx];
}

#define USBTRACE_PT_PARM1(ctx) ((unsigned long)usbtrace_pt_parm((ctx), 0))
#define USBTRACE_PT_PARM2(ctx) ((unsigned long)usbtrace_pt_parm((ctx), 1))
#define USBTRACE_PT_PARM3(ctx) ((unsigned long)usbtrace_pt_parm((ctx), 2))
#define USBTRACE_PT_PARM4(ctx) ((unsigned long)usbtrace_pt_parm((ctx), 3))
/* kretprobe return: r0 / eax — same slot as PARM1. */
#define USBTRACE_PT_RET(ctx) USBTRACE_PT_PARM1(ctx)

#define USBTRACE_PTR_KEY(p) ((__u64)(__u32)(unsigned long)(p))

/*
 * Turn a kprobe pointer argument / kernel-pointer load into a usable address.
 * BPF_KPROBE() promotes regs to 64-bit and may leave junk in the high half;
 * CORE_READ then fails on a 32-bit kernel. Always go through this before use.
 */
#define USBTRACE_KPTR(p) ((void *)(unsigned long)USBTRACE_PTR_KEY(p))

/*
 * Read a kernel-native pointer from kernel memory (4 bytes on 32-bit).
 */
static __always_inline void *usbtrace_read_kptr(const void *addr)
{
	__u32 p = 0;

	if (!addr)
		return NULL;
	bpf_probe_read_kernel(&p, sizeof(p), addr);
	return (void *)(unsigned long)p;
}

#define USBTRACE_KPTR_SIZE 4

#else /* 64-bit arches: libbpf PT_REGS_* is correct */

#define USBTRACE_PT_PARM1(ctx) ((unsigned long)PT_REGS_PARM1(ctx))
#define USBTRACE_PT_PARM2(ctx) ((unsigned long)PT_REGS_PARM2(ctx))
#define USBTRACE_PT_PARM3(ctx) ((unsigned long)PT_REGS_PARM3(ctx))
#define USBTRACE_PT_PARM4(ctx) ((unsigned long)PT_REGS_PARM4(ctx))
/* kretprobe return: rax on x86_64, x0 on arm64 (not PARM1 on x86_64). */
#define USBTRACE_PT_RET(ctx) ((unsigned long)PT_REGS_RC(ctx))

#define USBTRACE_PTR_KEY(p) ((__u64)(unsigned long)(p))
#define USBTRACE_KPTR(p) ((void *)(unsigned long)(p))

static __always_inline void *usbtrace_read_kptr(const void *addr)
{
	void *p = NULL;

	if (!addr)
		return NULL;
	bpf_probe_read_kernel(&p, sizeof(p), addr);
	return p;
}

#define USBTRACE_KPTR_SIZE 8

#endif

/*
 * Sign-extend a kretprobe return to 64-bit. BPF `unsigned long` is always 64
 * bits; ARM32/i386 r0/eax is a 32-bit slot that we zero-extend when reading
 * pt_regs, so a negative errno would look like success without this.
 */
static __always_inline long usbtrace_kret_sx(unsigned long rc)
{
#if defined(__TARGET_ARCH_arm) || defined(__TARGET_ARCH_i386)
	return (long)(__s32)rc;
#else
	return (long)rc;
#endif
}

/* Functions that return int on every supported kernel (0 / byte count / -errno). */
static __always_inline __s32 usbtrace_kret_int(unsigned long rc)
{
	return (__s32)usbtrace_kret_sx(rc);
}

/*
 * usb_get_device_descriptor ABI:
 *   pre-6.6  int: byte count (>=0) or -errno
 *   6.6+     struct usb_device_descriptor * or ERR_PTR(-errno)
 * Map both to __s32: 0 or the old byte count on success, -errno on failure.
 */
static __always_inline __s32 usbtrace_kret_ptr_or_int(unsigned long rc)
{
	unsigned long v = (unsigned long)usbtrace_kret_sx(rc);

	if (v >= (unsigned long)-4095UL)	/* IS_ERR() / negative int */
		return (__s32)(long)v;
	if (v < 4096UL)				/* 0 or byte count */
		return (__s32)v;
	return 0;				/* non-NULL pointer: success */
}

/*
 * Index a kernel pointer array. BPF sizeof(void *) is always 8; the kernel
 * slot is 4 bytes on ARM32/i386 (e.g. usb_hub.ports[]).
 */
static __always_inline void *usbtrace_kptr_idx(const void *arr, int idx)
{
	if (!arr || idx < 0 || idx > 15)
		return NULL;
	return usbtrace_read_kptr((const char *)arr + idx * USBTRACE_KPTR_SIZE);
}

#endif /* __USBTRACE_PT_REGS_BPF_H */

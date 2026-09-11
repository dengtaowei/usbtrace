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

#else /* 64-bit arches: libbpf PT_REGS_* is correct */

#define USBTRACE_PT_PARM1(ctx) ((unsigned long)PT_REGS_PARM1(ctx))
#define USBTRACE_PT_PARM2(ctx) ((unsigned long)PT_REGS_PARM2(ctx))
#define USBTRACE_PT_PARM3(ctx) ((unsigned long)PT_REGS_PARM3(ctx))
#define USBTRACE_PT_PARM4(ctx) ((unsigned long)PT_REGS_PARM4(ctx))

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

#endif

#endif /* __USBTRACE_PT_REGS_BPF_H */

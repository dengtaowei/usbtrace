#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Cross-build an ARM32 zImage for qemu-system-arm -M virt
# (multi_v7_defconfig + kconfig.fragment).
#
# Requires:
#   KERNEL_SRC      path to a Linux tree
#   CROSS_COMPILE   armhf prefix on PATH (e.g. arm-linux-gnueabihf-)
# Optional:
#   QEMU_ARM32_CACHE, JOBS, FORCE_KERNEL_REBUILD=1
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CACHE="${QEMU_ARM32_CACHE:-$ROOT/testdata/qemu-arm32}"
FRAGMENT="$HERE/kconfig.fragment"
OUT_ZIMAGE="$CACHE/zImage"
KBUILD="$CACHE/kbuild"
WT="$CACHE/linux-src"
JOBS="${JOBS:-$(nproc)}"

log() { printf '[qemu-arm32] %s\n' "$*"; }
err() { printf '[qemu-arm32] ERROR: %s\n' "$*" >&2; }

if [[ -z "${KERNEL_SRC:-}" ]]; then
	err "KERNEL_SRC is required (path to a Linux kernel tree)"
	err "See scripts/qemu-arm32/README.md"
	exit 1
fi

if [[ ! -d "$KERNEL_SRC/arch/arm" ]]; then
	err "KERNEL_SRC=$KERNEL_SRC is not an ARM Linux tree"
	exit 1
fi

if [[ -z "${CROSS_COMPILE:-}" ]]; then
	if command -v arm-linux-gnueabihf-gcc >/dev/null 2>&1; then
		CROSS_COMPILE=arm-linux-gnueabihf-
	elif command -v arm-buildroot-linux-gnueabihf-gcc >/dev/null 2>&1; then
		CROSS_COMPILE=arm-buildroot-linux-gnueabihf-
	else
		err "CROSS_COMPILE is required (e.g. CROSS_COMPILE=arm-linux-gnueabihf-)"
		exit 1
	fi
fi

if ! command -v pahole >/dev/null 2>&1; then
	err "pahole required for CONFIG_DEBUG_INFO_BTF (package: dwarves)"
	exit 1
fi

mkdir -p "$CACHE" "$KBUILD"

if [[ -f "$OUT_ZIMAGE" && -f "$CACHE/vmlinux" && "${FORCE_KERNEL_REBUILD:-0}" != 1 ]]; then
	log "using cached $OUT_ZIMAGE"
	exit 0
fi

SRC="$KERNEL_SRC"
# Board trees often have in-tree objects; O= then refuses to configure.
if ! make -C "$SRC" ARCH=arm O="$KBUILD" -s multi_v7_defconfig >/dev/null 2>&1; then
	if git -C "$KERNEL_SRC" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		if [[ ! -e "$WT/.git" ]]; then
			log "KERNEL_SRC is not clean for O=; creating detached worktree at $WT"
			rm -rf "$WT"
			git -C "$KERNEL_SRC" worktree add --detach "$WT" HEAD
		fi
		SRC="$WT"
	else
		err "KERNEL_SRC cannot be used with O= (in-tree build artifacts) and is not a git repo"
		err "Use a clean tree, or set QEMU_ARM32_KERNEL= to a prebuilt virt zImage"
		exit 1
	fi
fi

log "configuring multi_v7 + fragment (src=$SRC O=$KBUILD)"
rm -rf "$KBUILD"
mkdir -p "$KBUILD"
make -C "$SRC" ARCH=arm O="$KBUILD" multi_v7_defconfig
"$SRC/scripts/kconfig/merge_config.sh" -m -O "$KBUILD" \
	"$KBUILD/.config" "$FRAGMENT"
make -C "$SRC" ARCH=arm O="$KBUILD" olddefconfig

if grep -q '^CONFIG_ARCH_STM32=y' "$KBUILD/.config" 2>/dev/null || \
   grep -q '^CONFIG_STM32_DMA=y' "$KBUILD/.config" 2>/dev/null; then
	err "config still enables STM32 SoC drivers — use mainline linux-5.4.y, not a BSP tree"
	err "  scripts/qemu-arm32/fetch-kernel.sh"
	err "  then: rm -rf $CACHE/kbuild $CACHE/linux-src $CACHE/zImage"
	exit 1
fi

log "building zImage (CROSS_COMPILE=$CROSS_COMPILE -j$JOBS) ..."
log "first build may take a long time; result is cached under $CACHE"
make -C "$SRC" ARCH=arm CROSS_COMPILE="$CROSS_COMPILE" O="$KBUILD" \
	-j"$JOBS" zImage

cp -f "$KBUILD/arch/arm/boot/zImage" "$OUT_ZIMAGE"
cp -f "$KBUILD/vmlinux" "$CACHE/vmlinux"
log "wrote $OUT_ZIMAGE and $CACHE/vmlinux"

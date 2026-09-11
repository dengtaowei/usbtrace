#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Shallow-clone mainline stable linux-5.4.y for the QEMU ARM32 virt smoke.
# Do NOT use vendor/BSP trees here (STM32/i.MX defconfigs pull SoC drivers that
# break a virt link, e.g. stm32-dma needing __aeabi_uldivmod).
#
# Usage:
#   scripts/qemu-arm32/fetch-kernel.sh
#   KERNEL_SRC=$(pwd)/testdata/qemu-arm32/linux-5.4 ...
#
# Env:
#   QEMU_ARM32_CACHE  cache root (default: <repo>/testdata/qemu-arm32)
#   LINUX_STABLE_URI  git URL (default: GitHub mirror of stable/linux)
#   LINUX_STABLE_REF  branch/tag (default: linux-5.4.y)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CACHE="${QEMU_ARM32_CACHE:-$ROOT/testdata/qemu-arm32}"
DEST="$CACHE/linux-5.4"
# kernel.org is often very slow; GitHub mirror of stable/linux is fine for smoke.
URI="${LINUX_STABLE_URI:-https://github.com/gregkh/linux.git}"
REF="${LINUX_STABLE_REF:-linux-5.4.y}"

log() { printf '[qemu-arm32] %s\n' "$*"; }
err() { printf '[qemu-arm32] ERROR: %s\n' "$*" >&2; }

mkdir -p "$CACHE"

if [[ -d $DEST/.git ]]; then
	log "updating $DEST ($REF)"
	git -C "$DEST" fetch --depth 1 origin "$REF"
	git -C "$DEST" checkout -q FETCH_HEAD
else
	log "cloning $URI ($REF) → $DEST (shallow; large download)"
	rm -rf "$DEST"
	git clone --depth 1 --branch "$REF" "$URI" "$DEST"
fi

log "KERNEL_SRC=$DEST"
printf '%s\n' "$DEST"

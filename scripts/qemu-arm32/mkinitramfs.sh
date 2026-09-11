#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Build a gzip cpio initramfs: pinned busybox-armv7l + static arm usbtrace + init.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CACHE="${QEMU_ARM32_CACHE:-$ROOT/testdata/qemu-arm32}"
BUSYBOX="${BUSYBOX_ARM:-$CACHE/busybox}"
INITRD="$CACHE/initramfs.cpio.gz"
STAGING="$CACHE/initramfs-root"
SHA_FILE="$HERE/busybox.sha256"

BUSYBOX_URL="${BUSYBOX_URL:-https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-armv7l}"

log() { printf '[qemu-arm32] %s\n' "$*"; }
err() { printf '[qemu-arm32] ERROR: %s\n' "$*" >&2; }

resolve_usbtrace_bin() {
	if [[ -n "${USBTRACE_BIN:-}" ]]; then
		printf '%s\n' "$USBTRACE_BIN"
		return
	fi
	if [[ -x $ROOT/dist/usbtrace-armv7-linux-perf ]]; then
		printf '%s\n' "$ROOT/dist/usbtrace-armv7-linux-perf"
		return
	fi
	err "set USBTRACE_BIN to a static ARM usbtrace (USBTRACE_EVENTS=perf)"
	err "see docs/build.md and docs/testing.md"
	exit 1
}

verify_busybox() {
	local sum
	sum="$(sha256sum "$BUSYBOX" | awk '{print $1}')"
	local expect
	expect="$(awk '{print $1}' "$SHA_FILE")"
	if [[ "$sum" != "$expect" ]]; then
		err "busybox sha256 mismatch (got $sum, want $expect)"
		err "delete $BUSYBOX and retry, or set BUSYBOX_ARM="
		exit 1
	fi
}

mkdir -p "$CACHE"

USBTRACE_BIN="$(resolve_usbtrace_bin)"
if [[ ! -x "$USBTRACE_BIN" ]]; then
	err "not executable: $USBTRACE_BIN"
	exit 1
fi

case "$(file -b "$USBTRACE_BIN" 2>/dev/null || true)" in
*ARM* | *arm*) ;;
*)
	log "warning: $USBTRACE_BIN may not be an ARM binary (file(1) check)"
	;;
esac

if [[ ! -x "$BUSYBOX" ]]; then
	log "fetching busybox-armv7l ..."
	curl -fsSL -o "$BUSYBOX" "$BUSYBOX_URL"
	chmod +x "$BUSYBOX"
fi
verify_busybox

rm -rf "$STAGING"
mkdir -p "$STAGING"/{bin,sbin,dev,proc,sys,tmp}
cp -f "$BUSYBOX" "$STAGING/bin/busybox"
cp -f "$USBTRACE_BIN" "$STAGING/usbtrace"
chmod +x "$STAGING/usbtrace"
install -m 0755 "$HERE/init.sh" "$STAGING/init"

for a in sh mount umount mkdir ls cat sleep kill grep uname; do
	ln -sf busybox "$STAGING/bin/$a"
done

(
	cd "$STAGING"
	find . | cpio -o -H newc 2>/dev/null | gzip -9
) >"$INITRD"

log "wrote $INITRD ($(du -h "$INITRD" | awk '{print $1}'))"

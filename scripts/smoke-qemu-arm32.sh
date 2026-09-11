#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Boot ARM32 Linux under qemu-system-arm (-M virt) and run the guest smoke
# in scripts/qemu-arm32/init.sh.
#
# See docs/testing.md and scripts/qemu-arm32/README.md.
# Not wired into CI.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CACHE="${QEMU_ARM32_CACHE:-$ROOT/testdata/qemu-arm32}"
INITRD="$CACHE/initramfs.cpio.gz"
LOG="$CACHE/last-serial.log"
QEMU_TIMEOUT="${QEMU_TIMEOUT:-180}"

log() { printf '[smoke-qemu-arm32] %s\n' "$*"; }
err() { printf '[smoke-qemu-arm32] ERROR: %s\n' "$*" >&2; }

if ! command -v qemu-system-arm >/dev/null 2>&1; then
	err "qemu-system-arm not found (e.g. apt install qemu-system-arm)"
	exit 1
fi

mkdir -p "$CACHE"

log "building initramfs"
"$HERE/qemu-arm32/mkinitramfs.sh"

if [[ -n "${QEMU_ARM32_KERNEL:-}" ]]; then
	ZIMAGE="$QEMU_ARM32_KERNEL"
	if [[ ! -f "$ZIMAGE" ]]; then
		err "QEMU_ARM32_KERNEL=$ZIMAGE not found"
		exit 1
	fi
	log "using prebuilt kernel $ZIMAGE"
elif [[ -f $CACHE/zImage && "${FORCE_KERNEL_REBUILD:-0}" != 1 ]]; then
	ZIMAGE="$CACHE/zImage"
	log "using cached kernel $ZIMAGE"
else
	if [[ -z "${KERNEL_SRC:-}" ]]; then
		if [[ -d $CACHE/linux-5.4/arch/arm ]]; then
			export KERNEL_SRC="$CACHE/linux-5.4"
			log "KERNEL_SRC unset; using $KERNEL_SRC"
		else
			log "KERNEL_SRC unset; fetching mainline stable linux-5.4.y"
			KERNEL_SRC="$("$HERE/qemu-arm32/fetch-kernel.sh")"
			export KERNEL_SRC
		fi
	fi
	log "building virt zImage from KERNEL_SRC=$KERNEL_SRC"
	"$HERE/qemu-arm32/build-kernel.sh"
	ZIMAGE="$CACHE/zImage"
fi

if [[ ! -f "$INITRD" ]]; then
	err "missing $INITRD"
	exit 1
fi

# Do not use -nographic here: under redirected stdio, QEMU's multiplexed
# serial+monitor often stops in job-control state T with an empty serial log.
# Use a file-backed UART and no monitor; poll the log and kill qemu early so
# the host does not sit silent until QEMU_TIMEOUT (guest sleeps after PASS).
rm -f "$LOG"
: >"$LOG"
log "booting qemu -M virt (timeout ${QEMU_TIMEOUT}s) ..."
set +e
qemu-system-arm \
	-machine virt \
	-cpu cortex-a15 \
	-smp 2 \
	-m 512 \
	-display none \
	-monitor none \
	-serial "file:$LOG" \
	-no-reboot \
	-kernel "$ZIMAGE" \
	-initrd "$INITRD" \
	-append 'console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init panic=1' \
	</dev/null &
qpid=$!
deadline=$((SECONDS + QEMU_TIMEOUT))
outcome=timeout
while ((SECONDS < deadline)); do
	if ! kill -0 "$qpid" 2>/dev/null; then
		wait "$qpid"
		rc=$?
		outcome=exited
		break
	fi
	if grep -q '=== usbtrace-qemu-arm32 PASS ===' "$LOG" 2>/dev/null; then
		outcome=pass
		break
	fi
	if grep -q '=== usbtrace-qemu-arm32 FAIL ===' "$LOG" 2>/dev/null; then
		outcome=fail
		break
	fi
	sleep 1
done
if kill -0 "$qpid" 2>/dev/null; then
	kill -KILL "$qpid" 2>/dev/null
	wait "$qpid" 2>/dev/null
	rc=137
else
	rc=${rc:-$?}
fi
set -e

if [[ "$outcome" == pass ]] || grep -q '=== usbtrace-qemu-arm32 PASS ===' "$LOG"; then
	log "PASS (log: $LOG)"
	grep -E '\[guest\]|usbtrace-qemu-arm32' "$LOG" | tail -30 || true
	exit 0
fi

err "FAIL (qemu outcome=$outcome rc=$rc). Last serial lines:"
tail -80 "$LOG" >&2 || true
if [[ "$outcome" == fail ]] || grep -q '=== usbtrace-qemu-arm32 FAIL ===' "$LOG"; then
	exit 1
fi
err "guest PASS marker not found (boot failure or QEMU_TIMEOUT too short)"
exit 1

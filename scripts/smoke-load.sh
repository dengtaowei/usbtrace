#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Local smoke test: build (if needed), list modules, then load/attach each
# tracing module briefly and shut it down with SIGTERM.
#
# Usage:
#   scripts/smoke-load.sh              # uses build/usbtrace
#   USBTRACE_BIN=./dist/foo scripts/smoke-load.sh
#   scripts/smoke-load.sh --quick      # core modules only (urb/lifecycle/enum/power)
#
# Needs: root (or passwordless sudo), kernel BTF, CONFIG_KPROBES.
# Does not require a physical USB device. Class modules whose hooks are absent
# on this kernel are reported as SKIP, not FAIL.
#
# Not wired into CI yet — run by hand before a release or after BPF changes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN="${USBTRACE_BIN:-$ROOT/build/usbtrace}"
QUICK=0
TIMEOUT_SEC="${SMOKE_TIMEOUT:-3}"
DIAG_TIMEOUT_SEC="${SMOKE_DIAG_TIMEOUT:-6}"

CORE_MODS=(urb lifecycle enum power)
CLASS_MODS=(hid uac storage uvc)
# diag loads several skeletons; keep last so failures there are obvious.
EXTRA_MODS=(diag)

usage() {
	sed -n '2,16p' "$0" | sed 's/^# \?//'
	exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-h | --help) usage 0 ;;
	--quick) QUICK=1 ;;
	*)
		echo "unknown option: $1" >&2
		usage 1
		;;
	esac
	shift
done

log() { printf '[smoke] %s\n' "$*"; }
err() { printf '[smoke] ERROR: %s\n' "$*" >&2; }

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		err "missing command: $1"
		exit 1
	}
}

as_root() {
	if [[ "$(id -u)" -eq 0 ]]; then
		"$@"
	elif [[ -t 0 ]]; then
		sudo "$@"
	elif sudo -n true 2>/dev/null; then
		sudo -n "$@"
	else
		err "need root (re-run as: sudo $0${QUICK:+ --quick})"
		exit 1
	fi
}

need_cmd timeout
need_cmd make

if [[ ! -x "$BIN" ]]; then
	log "building $BIN ..."
	make -C "$ROOT"
	BIN="$ROOT/build/usbtrace"
fi

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
	err "/sys/kernel/btf/vmlinux missing (need CONFIG_DEBUG_INFO_BTF)"
	exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
	if [[ -t 0 ]]; then
		: # as_root will prompt via sudo
	elif ! sudo -n true 2>/dev/null; then
		err "need root (re-run as: sudo $0${QUICK:+ --quick})"
		exit 1
	fi
fi

log "binary=$BIN"
log "kernel=$(uname -r) arch=$(uname -m)"

log "list modules"
"$BIN" list

MODS=("${CORE_MODS[@]}")
if [[ "$QUICK" -eq 0 ]]; then
	MODS+=("${CLASS_MODS[@]}" "${EXTRA_MODS[@]}")
fi

pass=0
skip=0
fail=0
FAIL_NAMES=()
SKIP_NAMES=()

for mod in "${MODS[@]}"; do
	t="$TIMEOUT_SEC"
	[[ "$mod" == diag ]] && t="$DIAG_TIMEOUT_SEC"

	log "load $mod (timeout ${t}s) ..."
	# timeout sends SIGTERM; usbtrace handles it and should exit 0 after attach.
	set +e
	out="$(as_root timeout --signal=TERM --kill-after=2s "${t}s" \
		"$BIN" "$mod" 2>&1)"
	rc=$?
	set -e

	if echo "$out" | grep -q 'no supported hooks on this kernel'; then
		log "SKIP $mod (no hooks on this kernel)"
		SKIP_NAMES+=("$mod")
		skip=$((skip + 1))
		continue
	fi

	# 0 = clean exit after TERM; 124 = timeout escalated to KILL (still attached)
	if [[ "$rc" -eq 0 || "$rc" -eq 124 ]]; then
		log "PASS $mod (rc=$rc)"
		pass=$((pass + 1))
		continue
	fi

	err "FAIL $mod (rc=$rc)"
	printf '%s\n' "$out" | sed 's/^/  | /' >&2
	FAIL_NAMES+=("$mod")
	fail=$((fail + 1))
done

log "----"
log "pass=$pass skip=$skip fail=$fail"
if ((${#SKIP_NAMES[@]} > 0)); then
	log "skipped: ${SKIP_NAMES[*]}"
fi
if ((${#FAIL_NAMES[@]} > 0)); then
	log "failed:  ${FAIL_NAMES[*]}"
fi

if [[ "$fail" -gt 0 ]]; then
	exit 1
fi
log "OK"
exit 0

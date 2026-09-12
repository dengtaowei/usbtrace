#!/bin/sh
# Runs as PID 1 inside the ARM32 QEMU initramfs.
set -eu

/bin/busybox mkdir -p /proc /sys /dev /tmp /sys/fs/bpf
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
/bin/busybox mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

echo "=== usbtrace-qemu-arm32 BEGIN ==="
/bin/busybox uname -a

if [ ! -r /sys/kernel/btf/vmlinux ]; then
	echo "=== usbtrace-qemu-arm32 FAIL (no BTF) ==="
	exec /bin/busybox sleep 3600
fi

if [ ! -x /usbtrace ]; then
	echo "=== usbtrace-qemu-arm32 FAIL (no /usbtrace) ==="
	exec /bin/busybox sleep 3600
fi

/usbtrace list || true

pass=0
fail=0
# Core modules only inside QEMU (class hooks often absent).
for mod in urb lifecycle enum power hub; do
	echo "[guest] load $mod ..."
	/usbtrace "$mod" >/tmp/ut-"$mod".out 2>&1 &
	pid=$!
	/bin/busybox sleep 3
	/bin/busybox kill -TERM "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
	# Treat "no supported hooks" as skip; verifier/load errors as fail.
	if /bin/busybox grep -q 'no supported hooks on this kernel' /tmp/ut-"$mod".out 2>/dev/null; then
		echo "[guest] SKIP $mod"
		continue
	fi
	if /bin/busybox grep -qE 'failed to (load|attach|open)|ERROR:' /tmp/ut-"$mod".out 2>/dev/null; then
		echo "[guest] FAIL $mod"
		/bin/busybox cat /tmp/ut-"$mod".out
		fail=$((fail + 1))
		continue
	fi
	echo "[guest] PASS $mod"
	pass=$((pass + 1))
done

echo "[guest] pass=$pass fail=$fail"
if [ "$fail" -gt 0 ] || [ "$pass" -eq 0 ]; then
	echo "=== usbtrace-qemu-arm32 FAIL ==="
else
	echo "=== usbtrace-qemu-arm32 PASS ==="
fi

# Stay up so the host can scrape serial; qemu is killed by timeout.
exec /bin/busybox sleep 3600

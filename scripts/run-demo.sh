#!/usr/bin/env bash
# Build (if needed) and run the urb demo module.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x build/usbtrace ]; then
	echo "[usbtrace] building..."
	make
fi

echo "[usbtrace] running 'urb' module (requires root). Ctrl-C to stop."
exec sudo ./build/usbtrace urb "$@"

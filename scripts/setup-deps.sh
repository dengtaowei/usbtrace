#!/usr/bin/env bash
# Install build dependencies for usbtrace (libbpf + bpftool are vendored as
# git submodules; this installs the host toolchain they need).
set -euo pipefail

echo "[usbtrace] installing build dependencies..."

if command -v apt-get >/dev/null 2>&1; then
	sudo apt-get update
	sudo apt-get install -y \
		clang llvm \
		libelf-dev zlib1g-dev \
		make pkg-config \
		gcc
	# Cross toolchains (optional; ignore failures if unavailable)
	sudo apt-get install -y \
		gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf || true
elif command -v dnf >/dev/null 2>&1; then
	sudo dnf install -y clang llvm elfutils-libelf-devel zlib-devel make gcc pkgconf
elif command -v pacman >/dev/null 2>&1; then
	sudo pacman -S --needed clang llvm libelf zlib make gcc pkgconf
else
	echo "Unsupported package manager; install: clang llvm libelf-dev zlib-dev make gcc" >&2
	exit 1
fi

echo "[usbtrace] fetching git submodules (libbpf, bpftool)..."
git submodule update --init --recursive

echo "[usbtrace] done. Now run: make"

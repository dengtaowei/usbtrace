# SPDX-License-Identifier: GPL-2.0
#
# Build-time configuration. Edit here, or override per invocation:
#   make USBTRACE_EVENTS=perf
#
# Switching a value triggers a rebuild of the BPF objects and user space.

# Event transport between BPF and user space:
#   ringbuf - BPF_MAP_TYPE_RINGBUF          (Linux >= 5.8, preferred)
#   perf    - BPF_MAP_TYPE_PERF_EVENT_ARRAY (Linux 5.4+, older BSPs)
USBTRACE_EVENTS ?= ringbuf

# perf backend only: perf_buffer pages per CPU (4 KiB each). Raise this if
# "perf buffer lost N event(s)" shows up. Default is in src/evmux.c.
# USBTRACE_PERF_PAGES ?= 64

# How to link:
#   static  - one self-contained binary; scp it to a target that has no
#             libelf / libyaml installed (the usual embedded case)
#   dynamic - link against the target's shared libraries
USBTRACE_LINK ?= static

# Third-party libraries, if your distro or sysroot needs a different set.
# Default: -lelf -lz -lyaml, plus libelf's compression backends when static.
# USBTRACE_LIBS ?= -lelf -lz -lyaml -lzstd

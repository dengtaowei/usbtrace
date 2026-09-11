# SPDX-License-Identifier: GPL-2.0
#
# usbtrace - eBPF USB subsystem tracer & diagnostic tool.
#
# Build (native):      make                          # static, ringbuf
#                      make USBTRACE_LINK=dynamic    # shared libelf/libyaml
# Verbose:             make V=1
# Event backend:       edit config.mk or: make USBTRACE_EVENTS=perf
# Cross (arm64):       make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
#                           VMLINUX_BTF=/path/to/target/vmlinux
#
# Supported ARCH values: x86 (x86_64/i686), arm (armv7), arm64 (aarch64).

OUTPUT := build

# Must stay above any real target so `make` defaults to building the binary
# (EVENTS_STAMP is listed early as a prerequisite helper).
.DEFAULT_GOAL := all

# ---- Build config (event transport, etc.) ---------------------------------
-include config.mk
USBTRACE_EVENTS ?= ringbuf

ifeq ($(USBTRACE_EVENTS),perf)
EVENTS_CPPFLAGS := -DUSBTRACE_USE_PERF
# Default lives in src/evmux.c; only override when explicitly configured.
ifneq ($(USBTRACE_PERF_PAGES),)
EVENTS_CPPFLAGS += -DUSBTRACE_PERF_PAGES=$(USBTRACE_PERF_PAGES)
endif
else ifeq ($(USBTRACE_EVENTS),ringbuf)
EVENTS_CPPFLAGS :=
else
$(error USBTRACE_EVENTS must be 'ringbuf' or 'perf' (got '$(USBTRACE_EVENTS)'))
endif

# How to link the third-party libraries and libc:
#   static  - self-contained binary; scp it to a target that has no libelf /
#             libyaml (the common case for embedded boards)
#   dynamic - link against the target's shared libraries
USBTRACE_LINK ?= static

ifeq ($(USBTRACE_LINK),static)
# -no-pie: gcc --enable-default-pie would otherwise keep a PT_INTERP and
# the binary still looks dynamically linked.
LINK_MODE_FLAGS := -static -no-pie
else ifeq ($(USBTRACE_LINK),dynamic)
LINK_MODE_FLAGS :=
else
$(error USBTRACE_LINK must be 'static' or 'dynamic' (got '$(USBTRACE_LINK)'))
endif

# Config stamps. Switching a knob renames its stamp; the now-missing file is
# what makes the affected targets out of date. Keep them out of .SECONDARY (see
# the bottom of this file) or make will ignore the missing prerequisite.
EVENTS_STAMP := $(OUTPUT)/.events-$(USBTRACE_EVENTS)
LINK_STAMP := $(OUTPUT)/.link-$(USBTRACE_LINK)

$(EVENTS_STAMP):
	$(Q)mkdir -p $(OUTPUT)
	$(Q)rm -f $(OUTPUT)/.events-*
	$(Q)touch $@

$(LINK_STAMP):
	$(Q)mkdir -p $(OUTPUT)
	$(Q)rm -f $(OUTPUT)/.link-*
	$(Q)touch $@

# ---- Architecture ---------------------------------------------------------
# Normalize to the names libbpf / bpf_tracing.h expect.
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/'    \
			 | sed 's/i.86/x86/'      \
			 | sed 's/armv7.*/arm/'   \
			 | sed 's/arm\([^6].*\)/arm/' \
			 | sed 's/aarch64/arm64/')
CROSS_COMPILE ?=

CLANG ?= clang
CC := $(CROSS_COMPILE)gcc
# bpftool bootstrap is always a host tool; never inherit a cross CC=.
HOSTCC ?= cc

# Cross builds: EXTRA_CFLAGS/LDFLAGS (do not override CFLAGS — that breaks bpftool).
EXTRA_CFLAGS ?=
LDFLAGS ?=

# Third-party libraries. Static elfutils pulls in whichever compression
# backends libelf.a was built against; probe the *target* compiler so a
# cross sysroot is honoured (`-print-file-name` echoes the name unchanged
# when it finds nothing). Override USBTRACE_LIBS wholesale if needed.
have_static_lib = $(if $(filter /%,$(shell $(CC) $(LDFLAGS) \
	-print-file-name=lib$(1).a 2>/dev/null)),-l$(1))

ifeq ($(origin USBTRACE_LIBS),undefined)
ifeq ($(USBTRACE_LINK),static)
USBTRACE_LIBS := -lelf -lz -lyaml $(foreach l,zstd lzma bz2,$(call have_static_lib,$(l)))
else
USBTRACE_LIBS := -lelf -lz -lyaml
endif
endif

# ---- Vendored toolchain (git submodules) ----------------------------------
LIBBPF_SRC := $(abspath third_party/libbpf/src)
LIBBPF_UAPI := $(abspath third_party/libbpf/include/uapi)
BPFTOOL_SRC := $(abspath third_party/bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT := $(abspath $(OUTPUT)/bpftool)
BPFTOOL := $(BPFTOOL_OUTPUT)/bootstrap/bpftool

# ---- vmlinux.h (CO-RE) ----------------------------------------------------
# Priority: VMLINUX_BTF override > committed per-arch header > running kernel.
VMLINUX_DIR := $(OUTPUT)/vmlinux/$(ARCH)
VMLINUX := $(VMLINUX_DIR)/vmlinux.h
VMLINUX_BTF ?=

# ---- Sources / objects (auto-discovered) ----------------------------------
BPF_SRCS := $(shell find src -name '*.bpf.c' 2>/dev/null)
USER_SRCS := $(filter-out %.bpf.c,$(shell find src -name '*.c' 2>/dev/null))
BPF_OBJS := $(patsubst src/%.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_SRCS))
SKELS := $(BPF_OBJS:.bpf.o=.skel.h)
USER_OBJS := $(patsubst src/%.c,$(OUTPUT)/%.o,$(USER_SRCS))
SKEL_INCLUDES := $(addprefix -I,$(sort $(dir $(SKELS))))

VERSION := $(shell git -C . describe --tags --always --dirty 2>/dev/null || echo 0.0.1-dev)

# -Isrc/modules lets cross-module consumers (e.g. diag) include another
# module's shared header as "<name>/<name>.h".
INCLUDES := -I$(OUTPUT) -Iinclude -Isrc/modules -I$(LIBBPF_UAPI) -I$(VMLINUX_DIR)
CFLAGS := -g -O2 -Wall -DUSBTRACE_VERSION='"$(VERSION)"' $(EVENTS_CPPFLAGS)
BIN := $(OUTPUT)/usbtrace

# Clang's system include dirs, needed when compiling with -target bpf.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# vmlinux.h from bpftool regularly trips -Wmissing-declarations; silence that
# (and a few other noisy BPF-target diagnostics) without weakening userspace -Wall.
BPF_CFLAGS ?= -g -O2 -Wall \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-missing-declarations \
	-Wno-unknown-warning-option

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s\n' "$(1)" "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(BIN)
	$(Q)ln -sf $(BIN) usbtrace
	$(call msg,DONE,$(BIN) (arch=$(ARCH) events=$(USBTRACE_EVENTS) link=$(USBTRACE_LINK)))

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) usbtrace

.PHONY: deps
deps:
	$(Q)./scripts/setup-deps.sh

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(VMLINUX_DIR):
	$(Q)mkdir -p $@

# ---- libbpf (static) ------------------------------------------------------
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		CC="$(CC)" \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

# ---- bpftool (host bootstrap build) ---------------------------------------
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= CC="$(HOSTCC)" \
		OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# ---- vmlinux.h ------------------------------------------------------------
$(VMLINUX): | $(VMLINUX_DIR) $(BPFTOOL)
	$(call msg,VMLINUX,$@ ($(ARCH)))
	$(Q)if [ -n "$(VMLINUX_BTF)" ]; then \
		$(BPFTOOL) btf dump file "$(VMLINUX_BTF)" format c > $@; \
	elif [ -f bpf/vmlinux/$(ARCH)/vmlinux.h ]; then \
		cp bpf/vmlinux/$(ARCH)/vmlinux.h $@; \
	elif [ -r /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "ERROR: no BTF source. Set VMLINUX_BTF=/path/to/target/vmlinux or commit bpf/vmlinux/$(ARCH)/vmlinux.h" >&2; \
		exit 1; \
	fi

# ---- BPF objects ----------------------------------------------------------
$(OUTPUT)/%.bpf.o: src/%.bpf.c $(LIBBPF_OBJ) $(VMLINUX) $(EVENTS_STAMP) | $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CLANG) $(BPF_CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(EVENTS_CPPFLAGS) \
		-I$(dir $<) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $(@:.bpf.o=.tmp.bpf.o)
	$(Q)$(BPFTOOL) gen object $@ $(@:.bpf.o=.tmp.bpf.o)
	$(Q)rm -f $(@:.bpf.o=.tmp.bpf.o)

# ---- BPF skeletons --------------------------------------------------------
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(BPFTOOL)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# ---- user-space objects ---------------------------------------------------
$(OUTPUT)/%.o: src/%.c $(SKELS) $(LIBBPF_OBJ) $(EVENTS_STAMP)
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(INCLUDES) $(SKEL_INCLUDES) -I$(dir $<) -c $< -o $@

# ---- diag: embed default rules.yaml ---------------------------------------
# Bakes the default knowledge base into the binary (works standalone), while
# `diag --rules <file>` still overrides at runtime.
DIAG_RULES_YAML := src/modules/diag/rules.yaml
ifneq ($(wildcard $(DIAG_RULES_YAML)),)
DIAG_RULES_HDR := $(OUTPUT)/modules/diag/rules_default.h
$(DIAG_RULES_HDR): $(DIAG_RULES_YAML) scripts/embed-file.sh
	$(call msg,EMBED,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)scripts/embed-file.sh $< rules_default_yaml > $@
$(OUTPUT)/modules/diag/rules.o: $(DIAG_RULES_HDR)
endif

# ---- final binary ---------------------------------------------------------
$(BIN): $(USER_OBJS) $(LIBBPF_OBJ) $(LINK_STAMP)
	$(call msg,BIN,$@ ($(USBTRACE_LINK)))
	$(Q)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) $(LINK_MODE_FLAGS) \
		$(USER_OBJS) $(LIBBPF_OBJ) $(USBTRACE_LIBS) -o $@

.DELETE_ON_ERROR:
# Keep the generated BPF objects/skeletons (they are intermediates of the
# .bpf.c -> .bpf.o -> .skel.h chain). Scoped on purpose: a bare `.SECONDARY:`
# marks *every* target intermediate, and make then ignores a missing
# prerequisite instead of rebuilding — which silently broke the events stamp.
.SECONDARY: $(BPF_OBJS) $(SKELS)

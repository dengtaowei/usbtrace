# SPDX-License-Identifier: GPL-2.0
#
# usbtrace - eBPF USB subsystem tracer & diagnostic tool.
#
# Build (native):      make
# Verbose:             make V=1
# Cross (arm64):       make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
#                           VMLINUX_BTF=/path/to/target/vmlinux
#
# Supported ARCH values: x86 (x86_64/i686), arm (armv7), arm64 (aarch64).

OUTPUT := build

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

INCLUDES := -I$(OUTPUT) -Iinclude -I$(LIBBPF_UAPI) -I$(VMLINUX_DIR)
CFLAGS := -g -O2 -Wall -DUSBTRACE_VERSION='"$(VERSION)"'
BIN := $(OUTPUT)/usbtrace

# Clang's system include dirs, needed when compiling with -target bpf.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

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
	$(call msg,DONE,$(BIN) (arch=$(ARCH)))

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
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

# ---- bpftool (host bootstrap build) ---------------------------------------
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

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
		echo "ERROR: no BTF source. Set VMLINUX_BTF=/path/to/vmlinux or commit bpf/vmlinux/$(ARCH)/vmlinux.h" >&2; \
		exit 1; \
	fi

# ---- BPF objects ----------------------------------------------------------
$(OUTPUT)/%.bpf.o: src/%.bpf.c $(LIBBPF_OBJ) $(VMLINUX) | $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(dir $<) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $(@:.bpf.o=.tmp.bpf.o)
	$(Q)$(BPFTOOL) gen object $@ $(@:.bpf.o=.tmp.bpf.o)
	$(Q)rm -f $(@:.bpf.o=.tmp.bpf.o)

# ---- BPF skeletons --------------------------------------------------------
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(BPFTOOL)
	$(call msg,SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# ---- user-space objects ---------------------------------------------------
$(OUTPUT)/%.o: src/%.c $(SKELS) $(LIBBPF_OBJ)
	$(call msg,CC,$@)
	$(Q)mkdir -p $(dir $@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $(SKEL_INCLUDES) -I$(dir $<) -c $< -o $@

# ---- final binary ---------------------------------------------------------
$(BIN): $(USER_OBJS) $(LIBBPF_OBJ)
	$(call msg,BIN,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

.DELETE_ON_ERROR:
.SECONDARY:

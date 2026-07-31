# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# blitmus build
#   litmus_tests/*.litmus --(litmus2bpf.py)--> .output/gen/*.{c,bpf.c} --> bin/<test>
# All generated/build artifacts live under .output/ and bin/ (both gitignored);
# nothing generated is committed.
#
# Usage:
#   make            regenerate sources and build every test into bin/
#   make regen      (re)generate .output/gen from litmus_tests/
#   make build      build all discovered tests into bin/ (no regen)
#   make clean      remove .output/ and bin/
#   make run        build, then run every test (via ./run.sh)

OUTPUT         := .output
GEN            := $(OUTPUT)/gen
BIN            := bin
CLANG          ?= clang
LIBBPF_SRC     := $(abspath src/libbpf/src)
BPFTOOL_SRC    := $(abspath src/bpftool/src)
LIBBPF_OBJ     := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL        ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
VMLINUX := src/vmlinux/$(ARCH)/vmlinux.h

# Our own libbpf/UAPI headers, template/ (reusable bpf_header etc.), and the
# build dir (for the generated *.skel.h).
INCLUDES := -I$(OUTPUT) -Itemplate -Isrc/libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
# Tuning knobs applied to BOTH the BPF and userspace compile so they agree,
# e.g.: make BLITMUS_DEFS="-DARENA_PAGES=8192 -DBLITMUS_SLOTS=2048" bin/mp_recycle
BLITMUS_DEFS ?=
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS) -lrt -ldl -lpthread -lm

vpath %.bpf.c $(GEN)
vpath %.c     $(GEN)

# A test is any userspace .c (excluding the *.bpf.c programs) in $(GEN).
APPS := $(sort $(patsubst %.c,%,$(notdir $(filter-out %.bpf.c,$(wildcard $(GEN)/*.c)))))

# Clang's default includes, added for -target bpf (some asm/* headers otherwise
# missing on some arches).  -idirafter so we don't disturb normal include order.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

# Default: regenerate sources, then build.  Two phases (recursive make) so the
# APPS wildcard sees the freshly generated .output/gen files.
.PHONY: all
all:
	$(Q)$(MAKE) regen
	$(Q)$(MAKE) build

.PHONY: build
build: $(addprefix $(BIN)/,$(APPS))

.PHONY: regen
regen: | $(GEN)
	$(call msg,REGEN,litmus_tests/*.litmus)
	$(Q)for f in litmus_tests/*.litmus; do ./litmus2bpf.py "$$f" >/dev/null || exit 1; done

.PHONY: run
run: all
	$(Q)./run.sh

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(BIN)

$(OUTPUT) $(GEN) $(BIN) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool (bootstrap)
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF object
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -mcpu=v4 -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)	      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) $(BLITMUS_DEFS)	      \
		     -c $(filter %.bpf.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Each app's userspace object needs its skeleton first
$(addprefix $(OUTPUT)/,$(addsuffix .o,$(APPS))): $(OUTPUT)/%.o: $(OUTPUT)/%.skel.h

# Build userspace object
$(OUTPUT)/%.o: %.c | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $(BLITMUS_DEFS) -c $(filter %.c,$^) -o $@

# Link the test binary into bin/
$(BIN)/%: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(BIN)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, .o) targets
.SECONDARY:

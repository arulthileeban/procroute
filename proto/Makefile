# ProcRoute prototype -- build targets
# Prerequisites: clang, llvm, libbpf-dev, golang (1.22+)

CLANG      ?= clang
GO         ?= go
BPF_SRC    := bpf/procroute.c
BPF_OBJ    := bpf/procroute.o
UNAME_M    := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
  BPF_TARGET_ARCH := -D__TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
  BPF_TARGET_ARCH := -D__TARGET_ARCH_arm64
else
  BPF_TARGET_ARCH := -D__TARGET_ARCH_x86
endif
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf $(BPF_TARGET_ARCH)

BIN        := bin/procroute

.PHONY: all bpf build clean fmt generate

all: bpf build

# BPF object
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/headers/*.h
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

# Go binary
build: $(BIN)

GOFLAGS ?= $(shell [ -d vendor ] && echo -mod=vendor || true)

$(BIN): $(BPF_OBJ) daemon/*.go cmd/procroute/main.go
	mkdir -p bin
	$(GO) build $(GOFLAGS) -o $@ ./cmd/procroute

# bpf2go generate (alternative to manual clang)
generate:
	$(GO) generate ./daemon/

# Cleanup
clean:
	rm -f $(BPF_OBJ) $(BIN)
	rm -f daemon/procroute_bpf*.go daemon/procroute_bpf*.o
	rm -rf bin/

# Format
fmt:
	@command -v clang-format >/dev/null 2>&1 && \
		clang-format -i bpf/procroute.c bpf/headers/*.h || \
		echo "clang-format not found, skipping C formatting"
	$(GO) fmt ./...

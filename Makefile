CLANG ?= clang
GO ?= go
PREFIX ?= /usr/local
DESTDIR ?=
BPF_ENDIAN ?= bpfel

.PHONY: all test test-kernel install clean
all: build/ebpfw build/firewall.o

build/ebpfw: $(shell find cmd internal -name '*.go') go.mod go.sum
	mkdir -p build
	CGO_ENABLED=0 $(GO) build -trimpath -o $@ ./cmd/ebpfw

# No kernel headers or generated vmlinux.h: only the stable XDP/map ABI is used.
build/firewall.o: bpf/firewall.c bpf/packet.h
	mkdir -p build
	$(CLANG) -O2 -g -target $(BPF_ENDIAN) -Wall -Werror -c bpf/firewall.c -o $@

test:
	$(GO) test -race ./...
	$(GO) vet ./...

# Run only on a disposable Linux test host; needs BPF privileges.
build/kernel.test: $(shell find internal -name '*.go') go.mod go.sum
	mkdir -p build
	$(GO) test -c -o $@ ./internal/runtime

test-kernel: all build/kernel.test
	EBPFW_KERNEL_TEST=1 EBPFW_LIVE_TEST=1 EBPFW_BINARY=$(CURDIR)/build/ebpfw EBPFW_OBJECT=$(CURDIR)/build/firewall.o ./build/kernel.test -test.v

build/ebpfw-bench: $(shell find cmd internal -name '*.go') go.mod go.sum
	mkdir -p build
	CGO_ENABLED=0 $(GO) build -trimpath -o $@ ./cmd/ebpfw-bench

install: all
	install -d $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/lib/ebpfw $(DESTDIR)/etc/ebpfw $(DESTDIR)/usr/lib/systemd/system
	install -m 0755 build/ebpfw $(DESTDIR)$(PREFIX)/sbin/ebpfw
	install -m 0644 build/firewall.o $(DESTDIR)$(PREFIX)/lib/ebpfw/firewall.o
	sed 's|/usr/local|$(PREFIX)|g' packaging/ebpfw@.service > $(DESTDIR)/usr/lib/systemd/system/ebpfw@.service
	@echo 'Installation complete. Configure rules before enabling a service.'

clean:
	rm -rf build

CLANG ?= clang
GO ?= go
PREFIX ?= /usr/local
DESTDIR ?=
BPF_ENDIAN ?= bpfel
# The stateful datapath uses 32-bit atomics; older Clang defaults target v1.
BPF_CPU ?= v3
ARCH ?= $(shell $(GO) env GOARCH)
# Private network/mount namespaces protect the test host and its pinned BPF state.
ISOLATE = unshare --net --mount sh -ec 'mount --make-rprivate /; mount -t bpf bpf /sys/fs/bpf; mount -t tmpfs -o mode=0755 tmpfs /run; exec "$$@"' sh

.PHONY: all test test-kernel benchmark install deb clean
all: build/ebpfw build/stateful.o

build/ebpfw: main.go $(shell find internal/config internal/firewall -name '*.go') go.mod go.sum
	mkdir -p build
	CGO_ENABLED=0 $(GO) build -trimpath -o $@ .

build/stateful.o: bpf/stateful.c Makefile
	mkdir -p build
	$(CLANG) -O2 -g -target $(BPF_ENDIAN) -mcpu=$(BPF_CPU) -Wall -Werror -c $< -o $@

build/full.test: $(shell find internal -name '*.go') go.mod go.sum
	mkdir -p build
	CGO_ENABLED=0 $(GO) test -c -o $@ ./internal/firewall

test:
	$(GO) test -race ./...
	$(GO) vet ./...

# Run as root on a disposable Linux host; each command creates private namespaces.
test-kernel: all build/full.test
	$(ISOLATE) env EBPFW_FULL_TEST=1 EBPFW_OBJECT=$(CURDIR)/build/stateful.o EBPFW_BINARY=$(CURDIR)/build/ebpfw ./build/full.test -test.v -test.timeout=10m

benchmark: all build/full.test
	$(ISOLATE) env EBPFW_FULL_TEST=1 EBPFW_UFW_TEST=1 EBPFW_UFW_BENCH=1 EBPFW_OBJECT=$(CURDIR)/build/stateful.o EBPFW_BINARY=$(CURDIR)/build/ebpfw ./build/full.test -test.v -test.run='^TestDirectUFWBenchmark$$' -test.timeout=20m

install: all
	install -d $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/lib/ebpfw $(DESTDIR)/etc/ebpfw $(DESTDIR)/usr/lib/systemd/system
	install -m 0755 build/ebpfw $(DESTDIR)$(PREFIX)/sbin/ebpfw
	install -m 0644 build/stateful.o $(DESTDIR)$(PREFIX)/lib/ebpfw/stateful.o
	sed 's|/usr/local|$(PREFIX)|g' ebpfw.service > $(DESTDIR)/usr/lib/systemd/system/ebpfw.service
	@echo 'Installed files only. Mount bpffs, configure rules, then enable explicitly.'

# Build a Linux binary and matching BPF object without installing or enabling.
deb:
	@test -n "$(VERSION)" || { echo 'Set VERSION, e.g. make deb VERSION=0.2.0 ARCH=amd64'; exit 1; }
	python3 packaging/build.py --version "$(VERSION)" --arch "$(ARCH)"

clean:
	rm -rf build

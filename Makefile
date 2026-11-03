CLANG ?= clang
GO ?= go
PREFIX ?= /usr/local
DESTDIR ?=
BPF_ENDIAN ?= bpfel
# The stateful datapath uses 32-bit atomics; older Clang defaults target v1.
BPF_CPU ?= v3

.PHONY: all test test-kernel benchmark install clean
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
	python3 -m unittest discover -s tests -p 'test_*.py'

# Invoke inside a private network namespace on a disposable Linux test host.
# Tests refuse namespaces containing existing interfaces other than loopback.
test-kernel: all build/full.test
	EBPFW_FULL_TEST=1 EBPFW_OBJECT=$(CURDIR)/build/stateful.o EBPFW_BINARY=$(CURDIR)/build/ebpfw ./build/full.test -test.v -test.timeout=10m

benchmark: all build/full.test
	EBPFW_FULL_TEST=1 EBPFW_UFW_TEST=1 EBPFW_UFW_BENCH=1 EBPFW_OBJECT=$(CURDIR)/build/stateful.o EBPFW_BINARY=$(CURDIR)/build/ebpfw ./build/full.test -test.v -test.run='^TestDirectUFWBenchmark$$' -test.timeout=20m

install: all
	install -d $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/lib/ebpfw $(DESTDIR)/etc/ebpfw $(DESTDIR)/usr/lib/systemd/system
	install -m 0755 build/ebpfw $(DESTDIR)$(PREFIX)/sbin/ebpfw
	install -m 0644 build/stateful.o $(DESTDIR)$(PREFIX)/lib/ebpfw/stateful.o
	sed 's|/usr/local|$(PREFIX)|g' ebpfw.service > $(DESTDIR)/usr/lib/systemd/system/ebpfw.service
	@echo 'Installed files only. Mount bpffs, configure rules, then enable explicitly.'

clean:
	rm -rf build

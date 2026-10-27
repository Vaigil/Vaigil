# Whatever go is on PATH.
GO ?= go
VERSION ?= dev

# The platforms a release carries. Windows carries a .exe suffix or it is not
# a program anybody can run.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64


all: fmt test

fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

# Two binaries: the server and the endpoint recorder (cmd/vaigil-collector).
# Both stamp the version the same way, because a collector heartbeat that
# cannot say which build it is is a fleet nobody can reason about.
build:
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/vaigil ./cmd/vaigil
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/vaigil-collector ./cmd/vaigil-collector
	@echo "binary: $$(du -h bin/vaigil | cut -f1)"
	@echo "binary: $$(du -h bin/vaigil-collector | cut -f1)"

# One binary per platform, named so a person downloading can tell which is
# which. CGO is off so these are genuinely static and genuinely
# cross-compiled — with it on, every target but the host needs a toolchain.
build-all:
	@mkdir -p bin
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath \
			-ldflags="-s -w -X main.version=$(VERSION)" \
			-o bin/vaigil-$$os-$$arch$$ext ./cmd/vaigil || exit 1; \
		echo "  vaigil  $$os/$$arch  $$(du -h bin/vaigil-$$os-$$arch$$ext | cut -f1)"; \
	done
# The collector's MVP substrate is Linux; Windows and macOS are phase 2
# (docs/research/12-xdr-ndr-tip-iam.md §8.3), so the release carries it for
# Linux only rather than shipping a binary that cannot read anything.
	@for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath \
			-ldflags="-s -w -X main.version=$(VERSION)" \
			-o bin/vaigil-collector-linux-$$arch ./cmd/vaigil-collector || exit 1; \
		echo "  vaigil-collector  linux/$$arch  $$(du -h bin/vaigil-collector-linux-$$arch | cut -f1)"; \
	done

# The GNU Coding Standards ask for these targets by name, and the reason is
# packaging: a distribution's build recipe runs `make && make check && make
# install DESTDIR=...` and does not read this file first. Missing one means a
# packager writes a bespoke recipe, and a bespoke recipe is one that breaks.
#
# prefix, DESTDIR and the exec/bin split are the standard variables. There is no
# ./configure to set them, because there is nothing to detect: no optional
# libraries, no feature switches, and go.mod has no require block.
prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
DESTDIR ?=
INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 0755

install: build
	$(INSTALL) -d "$(DESTDIR)$(bindir)"
	$(INSTALL_PROGRAM) bin/vaigil "$(DESTDIR)$(bindir)/vaigil"
	$(INSTALL_PROGRAM) bin/vaigil-collector "$(DESTDIR)$(bindir)/vaigil-collector"
	@echo "installed $(DESTDIR)$(bindir)/vaigil and vaigil-collector"

uninstall:
	rm -f "$(DESTDIR)$(bindir)/vaigil" "$(DESTDIR)$(bindir)/vaigil-collector"

# check is the standard name for what this project already spelled `test`.
# Both, because the muscle memory here is `make test` and a packager's is
# `make check`, and one of them being wrong is a build that looks broken.
check: test

# A source archive, from the committed tree rather than the working one — so a
# release tarball cannot carry somebody's local store or an editor backup.
dist:
	@git archive --format=tar.gz --prefix=vaigil-$(VERSION)/ \
		-o vaigil-$(VERSION).tar.gz HEAD
	@echo "vaigil-$(VERSION).tar.gz  $$(du -h vaigil-$(VERSION).tar.gz | cut -f1)"

distclean: clean
	rm -f vaigil-*.tar.gz

image:
	docker build --build-arg VERSION=$(VERSION) -t vaigil:$(VERSION) .

release: test build-all
	@cd bin && sha256sum vaigil-* > SHA256SUMS
	@echo
	@echo "release $(VERSION)"
	@sed 's/^/  /' bin/SHA256SUMS

clean:
	rm -rf bin

.PHONY: all fmt test check build build-all image release \
	install uninstall dist clean distclean

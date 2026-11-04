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

# Two binaries: the server and the endpoint recorder (cmd/aeroprove-collector).
# Both stamp the version the same way, because a collector heartbeat that
# cannot say which build it is is a fleet nobody can reason about.
build:
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/aeroprove ./cmd/aeroprove
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/aeroprove-collector ./cmd/aeroprove-collector
	@echo "binary: $$(du -h bin/aeroprove | cut -f1)"
	@echo "binary: $$(du -h bin/aeroprove-collector | cut -f1)"

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
			-o bin/aeroprove-$$os-$$arch$$ext ./cmd/aeroprove || exit 1; \
		echo "  aeroprove  $$os/$$arch  $$(du -h bin/aeroprove-$$os-$$arch$$ext | cut -f1)"; \
	done
# The collector's MVP substrate is Linux; Windows and macOS are phase 2
# (docs/research/12-xdr-ndr-tip-iam.md §8.3), so the release carries it for
# Linux only rather than shipping a binary that cannot read anything.
	@for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath \
			-ldflags="-s -w -X main.version=$(VERSION)" \
			-o bin/aeroprove-collector-linux-$$arch ./cmd/aeroprove-collector || exit 1; \
		echo "  aeroprove-collector  linux/$$arch  $$(du -h bin/aeroprove-collector-linux-$$arch | cut -f1)"; \
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
	$(INSTALL_PROGRAM) bin/aeroprove "$(DESTDIR)$(bindir)/aeroprove"
	$(INSTALL_PROGRAM) bin/aeroprove-collector "$(DESTDIR)$(bindir)/aeroprove-collector"
	# apv is the short form: the same bytes, a second name for the fingers.
	ln -f "$(DESTDIR)$(bindir)/aeroprove" "$(DESTDIR)$(bindir)/apv"
	@echo "installed $(DESTDIR)$(bindir)/aeroprove, apv and aeroprove-collector"

uninstall:
	rm -f "$(DESTDIR)$(bindir)/aeroprove" "$(DESTDIR)$(bindir)/apv" "$(DESTDIR)$(bindir)/aeroprove-collector"

# check is the standard name for what this project already spelled `test`.
# Both, because the muscle memory here is `make test` and a packager's is
# `make check`, and one of them being wrong is a build that looks broken.
check: test

# A source archive, from the committed tree rather than the working one — so a
# release tarball cannot carry somebody's local store or an editor backup.
dist:
	@git archive --format=tar.gz --prefix=aeroprove-$(VERSION)/ \
		-o aeroprove-$(VERSION).tar.gz HEAD
	@echo "aeroprove-$(VERSION).tar.gz  $$(du -h aeroprove-$(VERSION).tar.gz | cut -f1)"

distclean: clean
	rm -f aeroprove-*.tar.gz

image:
	docker build --build-arg VERSION=$(VERSION) -t aeroprove:$(VERSION) .

release: test build-all
	@cd bin && sha256sum aeroprove-* > SHA256SUMS
	@echo
	@echo "release $(VERSION)"
	@sed 's/^/  /' bin/SHA256SUMS

clean:
	rm -rf bin

.PHONY: all fmt test check build build-all image release \
	install uninstall dist clean distclean

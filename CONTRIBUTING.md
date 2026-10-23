# Contributing to Vaigil

This project is looking for maintainers, not just patches. If you want commit
access, the path is written down in [GOVERNANCE.md](GOVERNANCE.md) and it is
short.

## Try it first, in about two minutes

You need Go 1.27 or later and nothing else. There are no dependencies to fetch.

```bash
git clone https://github.com/quilzo/vaigil   # or your fork
cd vaigil
go build -o vaigil ./cmd/vaigil

mkdir /tmp/try && cd /tmp/try
../vaigil init --admin you@example.com   # prints the link that adds your passkey
../vaigil serve                          # the console, on http://localhost:8080
```

Vaigil has no default password and creates no default account. Nothing is
`admin` until you say so, and there is no state where an unconfigured install
is reachable with a known credential.

For the command line, issue yourself a token. It is shown once:

```bash
../vaigil token issue laptop --principal you@example.com --role admin
mkdir -p ~/.vaigil && umask 077 && printf '%s\n' 'vg_…' > ~/.vaigil/token
```

`VAIGIL_TOKEN` in the environment works too, and is looked at after the file.
The file is preferred because every program you start inherits your
environment, including an agent you are letting drive the command line.

`--role` may be narrower than the principal (a token can carry less than the
person holding it, never more), `--read-only` refuses every write whatever the
role, `--ttl` sets expiry, and `vaigil token revoke ID` ends one immediately.
An administrator's token takes a second administrator's approval when another
administrator exists.

## Building and testing

```bash
make test                  # the whole suite
make build                 # one binary for this platform
make build-all             # linux, darwin and windows, each on amd64 and arm64
go run cmd/gofmt -l .      # must print nothing
go vet ./...               # must print nothing
```

`go run cmd/gofmt` is the gofmt of the toolchain go.mod names. An older gofmt
on your PATH can call a file clean that CI then rejects.

CI runs formatting and vet, a build for every released platform, govulncheck
against the toolchain, the full suite, and a container build. All of them must
pass, and code scanning (CodeQL) must find nothing new.

## The one rule that will surprise you

**No third-party dependencies.** `go.mod` has no `require` block, and a test
fails if one appears.

A security console is the highest-value place in an infrastructure to put
something, and every transitive dependency is somebody else's release process
running inside yours. The audit chain, the Merkle tree, the OIDC and SAML
clients, the HTTP message signatures and the Sigma reader are written here,
and each is smaller than the library it replaces because it does only what
this needs.

If you need something the standard library does not have, open an issue
before writing the code.

## How code is reviewed here

**Tests that assert structure, not just behaviour.** The suite walks the
source and fails on omissions: every command declares its privilege, every
command has a screen and an MCP operation or a written reason it has not,
every role reaches its own work and no more, every change through the console
is written to the audit log. If you add a capability, it needs to be reachable
from all three surfaces or carry a written reason.

**Comments that say why, not what.** The code says what. A comment earns its
place by recording the reasoning or the alternative that was rejected.

**Refusing rather than warning.** When the tool detects a problem it stops and
explains. A warning nobody reads is a feature nobody has.

## Signing off

Every commit in a pull request needs a `Signed-off-by` line:

```bash
git commit -s -m "your message"
```

That certifies the [Developer Certificate of Origin](https://developercertificate.org/):
you wrote it or have the right to submit it under the project's licence.

Contributions are licensed under the [Apache License 2.0](LICENSE), as its
section 5 provides. There is no contributor licence agreement and no copyright
assignment: your copyright stays yours.

## What this project is not looking for

- Dependencies, as above.
- A JavaScript build step. The console is server-rendered. Its one script is
  first-party, allowed per page by a nonce, and every screen works with it
  switched off.
- Anything that makes a control optional. Security here is not a setting.

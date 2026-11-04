# Running aertun on a server

This directory has a hardened systemd unit and a Caddyfile that puts the
console behind https with a certificate it renews itself. Anything with 512 MB
will do: this is one static binary and a directory.

## 1. A user and a place

```bash
sudo useradd --system --home /srv/aertun --shell /usr/sbin/nologin aertun
sudo install -d -o aertun -g aertun -m 0700 /srv/aertun /srv/aertun/store
```

## 2. The binary

```bash
make build
sudo install -m 0755 bin/aertun /usr/local/bin/aertun
```

## 3. The store and the first administrator

```bash
sudo -u aertun aertun --root /srv/aertun/store init --admin you@example.com
```

It prints a one-time link that adds your passkey. Open it once the console is
reachable.

## 4. The service and the proxy

```bash
sudo cp deploy/aertun.service /etc/systemd/system/
sudo systemctl enable --now aertun
caddy run --config deploy/Caddyfile
```

Then, as the Caddyfile says, tell aertun it is behind TLS and where it is
reached, so cookies are marked Secure and passkeys name the right host:

```bash
sudo -u aertun aertun --root /srv/aertun/store config set admin.behind_tls_proxy true
sudo -u aertun aertun --root /srv/aertun/store config set admin.base_url https://aertun.example.com
sudo -u aertun aertun --root /srv/aertun/store config set admin.trusted_proxy true
```

## 5. Credentials

Connector credentials and feed secrets are sealed under a keyring whose key is
kept outside the store:

```bash
sudo -u aertun aertun --root /srv/aertun/store vault enable
```

It prints the key once. Put it in a file only root reads, and point
`AERTUN_KEY_FILE` at it in `/etc/aertun/env`.

// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/config"
	"github.com/aertun/aertun/internal/ssf"
)

// The transmitter half of OpenID Shared Signals, at the command line:
// `aertun ssf receivers` says where the agent kill switch is announced,
// `aertun ssf key` prints what a receiver needs to check what arrives, and
// `aertun ssf send` re-announces a kill — the path a receiver that was down
// during the disable, or one added afterwards, is caught up by.
//
// The sending itself is not here: internal/ssf builds and signs the token,
// and agentcmd's disable hook pushes it, best-effort, so the kill switch and
// its outward half are one act and not a menu.

// ssfReceiver is one configured listener: where it hears the kill switch,
// and the name of the stored secret holding its bearer token when the
// receiver asked for one (the same sealed store `connect secret` writes).
type ssfReceiver struct {
	URL    string `json:"url"`
	Secret string `json:"secret,omitempty"`
}

// ssfReceiverList reads the setting. An entry is URL or URL|SECRET; the
// configuration validated the shape when it was set, so this reads without
// re-judging and a hand-edited file is refused at load, not here.
func ssfReceiverList(cfg *config.Config) []ssfReceiver {
	var out []ssfReceiver
	for _, entry := range cfg.Strings("ssf.transmit.receivers") {
		where, secret, _ := strings.Cut(entry, "|")
		out = append(out, ssfReceiver{URL: where, Secret: secret})
	}
	return out
}

func ssfUsage() error {
	return fmt.Errorf("usage: aertun ssf receivers | key | send NAME --why \"…\" | help")
}

func cmdSSF(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"receivers"}
	}
	switch args[0] {
	case "help":
		return ssfHelp()
	case "receivers":
		return ssfReceiversList(root)
	case "key":
		return ssfShowKey(root)
	case "send":
		return ssfSend(root, args[1:])
	}
	return ssfUsage()
}

// ssfKeyPath is the transmitter's signing key, kept with the store's other
// signing keys and with their permissions: this account only, because
// whoever holds it can say this deployment killed an agent when it did not.
func ssfKeyPath(root string) string { return filepath.Join(auditDir(root), "ssf.key") }

// ssfPubPath is the public half, meant to be handed to receivers. Published
// as a file for the same reason the head keys are: a verifier outside this
// deployment needs it and nothing else — the receiver's configuration, this
// file, and the events.
func ssfPubPath(root string) string { return filepath.Join(auditDir(root), "ssf.pub.json") }

// ssfKey loads the transmitter's ES256 key, making it on first use, in the
// shape `aertun token keygen` writes (a P-256 JWK, read back by readKey).
// Made rather than demanded for the same reason the head keys are: a
// transmitter that needed a setup command first would stay silent for every
// store whose operator had not read about it.
func ssfKey(root string) (*ecdsa.PrivateKey, error) {
	if _, err := os.Stat(ssfKeyPath(root)); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		key, gerr := ssf.GenerateKey()
		if gerr != nil {
			return nil, gerr
		}
		enc := func(n *big.Int) string {
			return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32)))
		}
		priv, merr := json.Marshal(privateJWK{Kty: "EC", Crv: "P-256",
			X: enc(key.X), Y: enc(key.Y), D: enc(key.D)})
		if merr != nil {
			return nil, merr
		}
		if derr := os.MkdirAll(auditDir(root), 0o700); derr != nil {
			return nil, derr
		}
		// 0600: this is the key that signs events in this deployment's name.
		if werr := os.WriteFile(ssfKeyPath(root), append(priv, '\n'), 0o600); werr != nil {
			return nil, fmt.Errorf("cannot keep the transmitter's key: %w", werr)
		}
	}
	return readKey(ssfKeyPath(root))
}

// publishedSSFKey is ssfPubPath's document.
type publishedSSFKey struct {
	Issuer string          `json:"issuer"`
	KeyID  string          `json:"key_id"`
	JWKS   json.RawMessage `json:"jwks"`
	Note   string          `json:"note"`
}

// publishSSFKey rewrites the public half whenever the key is loaded, so it
// cannot drift from the key that is actually signing — the head keys'
// discipline, for the same reason: a published key that names a retired one
// makes every genuine event look forged.
func publishSSFKey(root string, e *ssf.Emitter) error {
	out, err := json.MarshalIndent(publishedSSFKey{
		Issuer: e.Issuer, KeyID: e.KeyID, JWKS: e.JWKS(),
		Note: "The transmitter half of this deployment's Shared Signals: the " +
			"key its security event tokens are signed with (ES256). Nothing in " +
			"this file is secret; give it to whatever receives its events.",
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(auditDir(root), 0o700); err != nil {
		return err
	}
	return os.WriteFile(ssfPubPath(root), append(out, '\n'), 0o644)
}

// ssfEmitter is the transmitter as configured: the key, the issuer this
// deployment is known by, and — only when somebody is listening — the will
// to send. Nil means transmitting is off, which is the default and not an
// error: the kill switch works without it, it just says nothing.
func ssfEmitter(root string) (*ssf.Emitter, error) {
	cfg := mustConfig(root)
	if len(ssfReceiverList(cfg)) == 0 {
		return nil, nil
	}
	key, err := ssfKey(root)
	if err != nil {
		return nil, err
	}
	e, err := ssf.NewEmitter(key, cfg.Raw("admin.base_url"))
	if err != nil {
		return nil, fmt.Errorf("kill-switch events cannot be signed: %w", err)
	}
	if err := publishSSFKey(root, e); err != nil {
		return nil, err
	}
	return e, nil
}

// ssfReceiversList is `aertun ssf receivers`: where a disable goes, and
// what signs it — the screen an operator reads before trusting that the
// outward half is wired.
func ssfReceiversList(root string) error {
	cfg := mustConfig(root)
	receivers := ssfReceiverList(cfg)
	issuer := cfg.Raw("admin.base_url")
	if w.JSON(map[string]any{"receivers": receivers, "issuer": issuer}) {
		return nil
	}
	if len(receivers) == 0 {
		w.Human("  no receivers; the kill switch is local only — transmitting is off\n")
		w.Human("  %s%s%s\n", dim,
			"aertun config set ssf.transmit.receivers https://partner.example/caep", reset)
		return nil
	}
	w.Human("kill-switch events (session-revoked) are pushed to:\n")
	for _, r := range receivers {
		line := "  " + r.URL
		if r.Secret != "" {
			line += "  with the token stored as " + r.Secret
		}
		w.Human("%s\n", line)
	}
	key, err := ssfKey(root)
	if err != nil {
		return err
	}
	if issuer == "" {
		w.Human("\n  %sno issuer is set, so nothing can be signed yet: admin.base_url%s\n", yellow, reset)
		return nil
	}
	w.Human("\n  %ssigned by %s (ES256), issued as %s%s\n", dim,
		ssf.KeyID(&key.PublicKey), issuer, reset)
	w.Human("  %sthe receiving side configures this issuer, its own address as the "+
		"audience, and the key from aertun ssf key%s\n", dim, reset)
	return nil
}

// ssfShowKey is `aertun ssf key`: what a receiver's verifier is configured
// with — the issuer it must demand, the key id in each token's header, and
// the key set itself.
func ssfShowKey(root string) error {
	key, err := ssfKey(root)
	if err != nil {
		return err
	}
	cfg := mustConfig(root)
	kid := ssf.KeyID(&key.PublicKey)
	e := &ssf.Emitter{Key: key, KeyID: kid, Issuer: cfg.Raw("admin.base_url")}
	jwks := e.JWKS()
	if w.JSON(map[string]any{"key_id": kid, "alg": "ES256",
		"issuer": e.Issuer, "jwks": json.RawMessage(jwks)}) {
		return nil
	}
	w.Human("give the receiving side these, to check what it is pushed:\n")
	w.Human("  issuer   %s\n", e.Issuer)
	w.Human("  key id   %s  (ES256)\n", kid)
	w.Human("  key set  %s\n", jwks)
	if e.Issuer == "" {
		w.Human("\n  %sno issuer is set; set admin.base_url before the first "+
			"event can be signed%s\n", yellow, reset)
	}
	return nil
}

// ssfSend is `aertun ssf send NAME --why "…"`: re-announce one kill. Only a
// disabled agent, because a session-revoked event for a live agent would
// tell every partner to end sessions this deployment has not ended — the
// event is a statement about this store, and it has to stay true.
func ssfSend(root string, args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	why := fs.String("why", "", "the reason, kept for the receiving administrators")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return ssfUsage()
	}
	a, ok, err := agentStore(root).Get(pos[0])
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("there is no agent %q (aertun agent list)", pos[0])
	}
	if a.Status != agentreg.Disabled {
		return fmt.Errorf("%s is active; session-revoked is said when an agent "+
			"is killed (aertun agent disable %s --why \"…\")", pos[0], pos[0])
	}
	if strings.TrimSpace(*why) == "" {
		return fmt.Errorf("sending needs --why: the receiving administrators " +
			"read it, and a kill re-announced with no word from anybody is " +
			"indistinguishable from a fault")
	}
	caller := resolveCaller(root, "")
	transmitAgentRevocation(root, caller, pos[0], strings.TrimSpace(*why))
	return nil
}

func ssfHelp() error {
	w.Human(`  Where the agent kill switch is announced: OpenID Shared Signals.

  When an agent is disabled, a session-revoked event (CAEP, in a signed
  security event token) is pushed to every configured receiver, so the
  platforms that trusted the agent kill its sessions too. The push is
  best-effort by contract: the local kill — the registry row and the
  revoked tokens — has already happened, and a receiver that is down is
  recorded as not hearing it, never allowed to fail the kill.

  aertun ssf receivers                  who hears the kill switch
  aertun ssf key                        what a receiver checks tokens against
  aertun ssf send watcher --why "…"     re-announce a kill (a receiver was down)

  Receivers are a setting, each entry the address a receiver listens on and
  optionally the name of its stored bearer token:

  aertun config set ssf.transmit.receivers https://partner.example/caep|partner

  The subject is the agent's registry name, in the clear: an SSF receiver
  can only act on an event it can resolve, and registry names are clear
  identifiers by design — unlike the pseudonyms this program keeps people
  behind in its own log. No person is named; the reason travels as the
  administrator-facing field CAEP defines for exactly that.

  Empty means transmitting is off. The kill switch needs none of this to
  work; this is how neighbours learn at once.
`)
	return nil
}

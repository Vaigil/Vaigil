// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/quilzo/vaigil/internal/throttle"
	"net/http"
	"strconv"
	"strings"

	"github.com/quilzo/vaigil/internal/auth"
)

// humanBytes writes a file size the way somebody choosing a picture reads it.
//
// Not because the exact number is wrong, but because "2411954" and "2.4 MB"
// answer different questions, and the one being asked on this screen is
// whether the photograph is too heavy for the page it is going on.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	case n >= 1<<10:
		return strconv.FormatInt(n/(1<<10), 10) + " kB"
	default:
		return strconv.FormatInt(n, 10) + " bytes"
	}
}

// nonce returns a fresh per-response value.
//
// Per response, never per process. A nonce reused across responses is a nonce
// an attacker can read from one page and use in an injection into another,
// which is the same as not having one.
// brandName is what this console is called: on every page, and to a
// passkey's authenticator as the party it is for.
const brandName = "Vaigil"

func nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(b), nil
}

// securityCan admits somebody who may do act in security operations: a
// role on the whole console, or one on the security area alone.
func (s *Server) securityCan(w http.ResponseWriter, r *http.Request, act auth.Action) (principal, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, act, auth.AreaSecurity) {
		return principal{}, false
	}
	return p, true
}

// areaAdmin admits an administrator of an area: of the whole console, which
// covers every area, or of that area alone.
func (s *Server) areaAdmin(w http.ResponseWriter, r *http.Request, area string) (principal, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, auth.ActGrant, area) {
		return principal{}, false
	}
	return p, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func sentenceCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func plural2(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// auditPub records what a person did, under their name.
func (s *Server) auditPub(p principal, action, resource string, detail map[string]string) {
	if s.Audit == nil {
		return
	}
	if detail == nil {
		detail = map[string]string{}
	}
	detail["by"] = p.Name
	s.Audit(action, resource, detail)
}

// ownOrigin is the scheme and host this request reached.
func (s *Server) ownOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || s.behindTLSProxy() {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// throttled is the sign-in limiter's state, for the Sign-ins screen.
//
// The subjects are opaque by construction — the limiter holds HMACs — so
// this reports counts and timings and cannot say who: the list of people
// currently being attacked is itself worth protecting.
func (s *Server) throttled() []throttle.Snapshot {
	if s.Throttle == nil {
		return nil
	}
	return s.Throttle.State()
}

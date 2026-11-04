// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"path/filepath"

	"github.com/aertun/aertun/internal/admin"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/config"
	"github.com/aertun/aertun/internal/oauthas"
)

// The authorization server, mounted beside the console (internal/oauthas).
//
// Its endpoints answer the agent interface's 401: a client that follows the
// resource's RFC 9728 document to its OAuth conclusion now finds a real
// issuer — /oauth/authorize asks the person signed in to the console whether
// the agent may act for them, /oauth/token mints a /mcp-bound credential
// under PKCE and a DPoP key, and /token/exchange composes that credential
// with the agent's own into an on-behalf-of token. Every hook below is a
// thing that already existed somewhere in this store; the server owns a
// protocol and no state of its own beyond minutes-short codes.

// consentsPath is the consent register, beside the registry it is consulted
// with and with its permissions: like agents.json it names who may act.
func consentsPath(root string) string {
	return filepath.Join(root, "consents.json")
}

func consentStore(root string) oauthas.Store {
	return oauthas.Store{Path: consentsPath(root)}
}

// mountOAuthAS puts the authorization server on the console's mux.
//
// The issuer is the origin the operator chose (mountMCP names the same one
// in the resource document), and the resource is the agent interface — the
// one audience this server issues for, so a token taken from it opens /mcp
// and nothing else.
func mountOAuthAS(mux *http.ServeMux, root string, cfg *config.Config, addr string, srv *admin.Server) {
	scheme := "http"
	if cfg.Bool("admin.behind_tls_proxy") {
		scheme = "https"
	}
	origin := scheme + "://" + addr

	as := &oauthas.Server{
		Issuer:   origin,
		Resource: origin + "/mcp",
		Consents: consentStore(root),
		Agents:   agentStore(root),
		// The person approving is the person signed in to the console: the
		// session, two factors, held to the same rules requireAuth holds —
		// decided by the console's own machinery (admin.Server.Session),
		// because a second implementation of "who is signed in" would be a
		// second thing to get wrong.
		Identity: srv.Session,
		// The policy, loaded fresh: a consent delegates what a person
		// holds, and what they hold is what the policy says now, not what
		// it said when this process started.
		Can: func(person string, act auth.Action, resource string) bool {
			pol, err := loadPolicy(root)
			if err != nil {
				// Unreadable is refused, the same line the command line
				// and the console hold: a consent recorded against a
				// policy nobody could read would be authority minted in
				// the dark.
				return false
			}
			return pol.Evaluate(person, act, resource).Allowed
		},
		Tokens: func() (*auth.TokenStore, func(*auth.TokenStore) error, error) {
			ts, err := loadTokens(root)
			if err != nil {
				return nil, nil, err
			}
			return ts, func(t *auth.TokenStore) error { return saveTokens(root, t) }, nil
		},
		Audit: func(action, resource string, detail map[string]string) {
			record(root, audit.Record{
				Action: action, Resource: resource, Outcome: audit.Success,
				Principal: detail["by"], Kind: audit.KindHuman, Verified: true,
				Detail: detail,
			})
		},
		SameOrigin: func(o string) bool { return mcpOrigins(cfg, addr)[o] },
	}
	mux.Handle(oauthas.MetadataPath, as)
	mux.Handle("/oauth/", as)
}

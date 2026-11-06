// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/aertun/aertun/internal/config"
)

// The origin the OAuth server names is the one the operator chose, not the
// one the process listens on. The authorization-server metadata, the
// protected-resource metadata and the audience the exchange accepts all
// derive from the same function, so behind a proxy they cannot disagree.
func TestTheOAuthOriginFollowsTheOperatorNotTheListener(t *testing.T) {
	cases := []struct {
		name     string
		baseURL  string
		tlsProxy bool
		addr     string
		want     string
	}{
		{"laptop", "", false, "localhost:8080", "http://localhost:8080"},
		{"behind proxy", "", true, "127.0.0.1:8080", "https://127.0.0.1:8080"},
		{"named origin", "https://aertun.example.com", false, "127.0.0.1:8080",
			"https://aertun.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.New()
			if tc.baseURL != "" {
				cfg.Set("admin.base_url", tc.baseURL, "test", "test")
			}
			if tc.tlsProxy {
				cfg.Set("admin.behind_tls_proxy", "true", "test", "test")
			}
			got := oauthOrigin(cfg, tc.addr)
			if got != tc.want {
				t.Errorf("oauthOrigin = %q, want %q", got, tc.want)
			}
		})
	}
}

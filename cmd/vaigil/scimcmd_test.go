// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
	"github.com/quilzo/vaigil/internal/scim"
)

type scimClient struct {
	t     *testing.T
	h     *scim.Handler
	token string
}

func (c scimClient) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func sessionFor(t *testing.T, root, who string) string {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue("laptop", who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	return secret
}

func works(root, secret string) bool {
	ts, _ := loadTokens(root)
	_, err := ts.Authenticate(secret, time.Now())
	return err == nil
}

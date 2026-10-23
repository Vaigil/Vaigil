// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package model is the one way this program asks a language model
// anything: an OpenAI-compatible chat completions endpoint, reached through
// the SSRF-hardened client, behind a privacy guard (Guarded).
//
// What a model returns is untrusted input. Nothing here acts on it; the
// callers parse it strictly and treat it as a suggestion a person decides.
package model

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quilzo/vaigil/internal/fetch"
)

// RequestTimeout bounds one completion.
const RequestTimeout = 120 * time.Second

// Model is anything that can answer a prompt. An interface so the tests can
// drive hostile responses through the same path a real model uses.
type Model interface {
	Complete(ctx context.Context, system, user string) (string, error)
	Name() string
}

// HTTPModel talks to any OpenAI-compatible chat completions endpoint, which
// covers Ollama Cloud, Bedrock behind a gateway, and most self-hosted servers.
// One shape rather than a provider per vendor.
type HTTPModel struct {
	BaseURL string
	APIKey  string
	Model   string
	Client  *http.Client
}

// StatusError is what a provider answered when it did not answer 200,
// kept with its status so a caller can tell a route that is unavailable
// from a request every route would refuse.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("model returned %d: %s", e.Code, e.Body) }

func (h *HTTPModel) Name() string { return h.Model }

// isLocalEndpoint reports whether a model endpoint is on this machine or this
// network, and says why when it is not.
//
// Resolved rather than pattern-matched on the hostname. "localhost" is a name
// somebody can point anywhere, and a check that trusts the spelling is a check
// that trusts DNS — so the address is looked up and judged, which is the same
// reasoning internal/fetch applies in the other direction.
//
// Unresolvable is not local. An endpoint nobody can reach is a misconfiguration
// either way, and guessing in the permissive direction would let a typo become
// a keyless call to whatever the name eventually resolves to.
func isLocalEndpoint(raw string) (bool, string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false, "it is not a URL this can read"
	}
	host := u.Hostname()
	if host == "" {
		return false, "it names no host"
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false, "its address could not be resolved"
	}
	// Every address, not the first. A name that resolves to both a loopback
	// address and a public one is not a local endpoint, and taking the first
	// answer would make the decision depend on resolver ordering.
	//
	// This is the message rather than the boundary. The same rule runs again
	// in Control, on the address actually being dialled, because a resolver
	// that answers differently the second time is how a checked address stops
	// being the connected one — see fetch.Speaking.
	for _, ip := range ips {
		if why := fetch.OnThisNetwork(ip); why != "" {
			// The reason already names the address, so it is not prefixed
			// with one: "it resolves to 169.254.169.254 is link-local" is
			// what that produces, and a message nobody can read is a message
			// people route around.
			return false, why
		}
	}
	return true, ""
}

// NewHTTPModel reads configuration from the environment.
func NewHTTPModel() (*HTTPModel, error) {
	base := os.Getenv("VAIGIL_MODEL_URL")
	if base == "" {
		base = "https://ollama.com/v1"
	}
	key := os.Getenv("VAIGIL_MODEL_KEY")
	if key == "" {
		key = os.Getenv("OLLAMA_API_KEY")
	}
	model := os.Getenv("VAIGIL_MODEL")
	if model == "" {
		model = "gpt-oss:20b"
	}
	return NewHTTPModelAt(base, key, model)
}

// NewHTTPModelAt is a model at a given endpoint, under the same rule as the
// configured one: a keyless endpoint must resolve to this network, because a
// public endpoint that answers without a key is one anybody's traffic can
// reach and nobody is accountable for.
func NewHTTPModelAt(base, key, model string) (*HTTPModel, error) {
	if key == "" {
		local, why := isLocalEndpoint(base)
		if !local {
			return nil, fmt.Errorf(
				"no model key, and %s is not a model on this machine (%s).\n"+
					"  Set VAIGIL_MODEL_KEY for a hosted endpoint, or point "+
					"VAIGIL_MODEL_URL at a local one — Ollama, llama.cpp, LM "+
					"Studio and vLLM all serve this protocol and need no key",
				base, why)
		}
	}
	// A key over plain http is a key anybody on the path can read: sent
	// only over https, or to a model on this machine.
	if key != "" && strings.HasPrefix(strings.ToLower(base), "http://") {
		if local, _ := isLocalEndpoint(base); !local {
			return nil, fmt.Errorf("%s is plain http and not on this machine, and a model's key is sent only over https", base)
		}
	}
	reach := fetch.Anywhere
	if key == "" {
		reach = fetch.OnThisNetwork
	}
	return &HTTPModel{
		BaseURL: strings.TrimSuffix(base, "/"),
		APIKey:  key,
		Model:   model,
		Client:  fetch.Speaking("model", reach, RequestTimeout),
	}, nil
}

// Usage is what one completion used, as the provider reported it.
type Usage struct {
	In, Out int
	// Reported is false when the provider said nothing, and the counts are
	// estimated from the length of the text.
	Reported bool
}

// Estimate is a usage worked out from text alone: about four characters to
// a token, rounded up, which is what providers' own guides give for
// English and an overstatement for most other text.
func Estimate(in, out string) Usage {
	return Usage{In: (len(in) + 3) / 4, Out: (len(out) + 3) / 4}
}

// Metered is a model that says what each completion used.
type Metered interface {
	CompleteMetered(ctx context.Context, system, user string) (string, Usage, error)
}

func (h *HTTPModel) Complete(ctx context.Context, system, user string) (string, error) {
	out, _, err := h.CompleteMetered(ctx, system, user)
	return out, err
}

// CompleteMetered is Complete, with what the provider says it used: the
// usage block every OpenAI-compatible server returns, or an estimate when
// it returns none.
func (h *HTTPModel) CompleteMetered(ctx context.Context, system, user string) (string, Usage, error) {
	payload := map[string]any{
		"model": h.Model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"stream": false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", Usage{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Omitted rather than sent empty. "Bearer " with nothing after it is a
	// credential that is present and blank, which some servers reject and
	// others log as a failed authentication — neither of which is what a
	// keyless local model meant to happen.
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		return "", Usage{}, fmt.Errorf("model request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		snippet := strings.TrimSpace(buf.String())
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return "", Usage{}, &StatusError{Code: resp.StatusCode, Body: snippet}
	}

	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage *struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", Usage{}, fmt.Errorf("cannot read the model's reply: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", Usage{}, fmt.Errorf("the model returned no choices")
	}
	text := out.Choices[0].Message.Content
	u := Estimate(system+user, text)
	if out.Usage != nil && out.Usage.Prompt >= 0 && out.Usage.Completion >= 0 &&
		(out.Usage.Prompt > 0 || out.Usage.Completion > 0) {
		u = Usage{In: out.Usage.Prompt, Out: out.Usage.Completion, Reported: true}
	}
	return text, u, nil
}

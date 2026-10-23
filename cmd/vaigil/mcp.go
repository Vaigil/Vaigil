// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vaigil/vaigil/internal/admin"
	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/find"
	"github.com/vaigil/vaigil/internal/mcp"
)

// The MCP surface is the third interface onto the same store, and every
// operation here goes through the same gates as the command line and the
// console. It reads, and proposes; it does not act. An agent reading events
// is reading text an attacker chose, so nothing on this surface changes who
// may do what, approves an act, or reaches another platform.

func cmdMCP(root string, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	list := fs.Bool("list", false, "print the operations and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	caller := resolveCaller(root, flagToken)
	srv := buildMCP(root, caller)

	if *list {
		for _, op := range srv.Operations() {
			kind := "read"
			if op.Writes {
				kind = "write"
			}
			fmt.Printf("  %-22s %-6s %s\n", op.Name, kind, op.Summary)
		}
		fmt.Printf("\n  %s%d operations behind 4 tools; an agent loads only what it "+
			"searches for%s\n", dim, len(srv.Operations()), reset)
		return nil
	}

	// stdio. A hosted deployment fronts this with streamable HTTP, and the
	// framing is the only difference — the routing and the gates are identical,
	// which is why they live in buildMCP rather than in a transport.
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := json.NewEncoder(os.Stdout)

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var req mcp.Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = out.Encode(mcp.Response{JSONRPC: "2.0",
				Error: &mcp.Error{Code: mcp.CodeParse, Message: err.Error()}})
			continue
		}
		resp := srv.Handle(req)
		// A notification has no id and expects no reply.
		if len(req.ID) == 0 {
			continue
		}
		if err := out.Encode(resp); err != nil {
			return err
		}
	}
	return in.Err()
}

func buildMCP(root string, caller *Caller) *mcp.Server {
	srv := mcp.NewServer("vaigil", version)

	// Every operation is authorised here, from the role it declares, and
	// each handler checks again: a second look costs nothing, and a new
	// operation does not need anybody to remember.
	srv.Authorise = func(op mcp.Operation) error {
		action, err := actionForRole(op.NeedsRole)
		if err != nil {
			// An operation with no role declared is refused rather than
			// allowed. The alternative is the behaviour being fixed: a new
			// operation is open until somebody notices.
			return fmt.Errorf("%q declares no role, so it cannot be "+
				"authorised: %v", op.Name, err)
		}
		// A change made through this interface is an agent's, and is
		// refused while its record could not be written (auditReady).
		// Reads go on, and their records are what tell this process the
		// log is back.
		if op.Writes {
			if err := auditReady(root); err != nil {
				return err
			}
		}
		if op.Area != "" {
			return authoriseUnder(root, caller, action, op.Area)
		}
		return authorise(root, caller, action, "/")
	}

	// Screens, by words. The settings are left out on this surface rather
	// than gated: a key's summary describes a control, and reconnaissance
	// over the controls is what an injected instruction would ask for first.
	srv.Register(mcp.Operation{
		Name: "find", NeedsRole: "viewer",
		Summary: "find a screen by words",
		Detail: "Words, not a query: there is no syntax, and a colon or a " +
			"quote is a character in a word.",
		Args: map[string]string{
			"query": "the words to look for",
			"limit": "optional, default 20",
		},
		Area:     "/",
		Keywords: []string{"find", "search", "where", "lookup", "locate", "screen"},
	}, func(a map[string]any) (any, error) {
		query, _ := a["query"].(string)
		if strings.TrimSpace(query) == "" {
			return nil, fmt.Errorf("find needs a query")
		}
		limit := 20
		if n, ok := a["limit"].(float64); ok && n > 0 {
			limit = int(n)
		}
		hits := find.Search(query, find.Sources{Screens: admin.Screens()}, limit)
		if len(hits) == 0 {
			return "nothing matched", nil
		}
		var b strings.Builder
		for _, h := range hits {
			fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", h.Kind, h.Title, h.Path, h.Why)
		}
		return strings.TrimSpace(b.String()), nil
	})

	registerSecurityOps(srv, root, caller)
	registerEstateOps(srv, root, caller)

	return srv
}

// actionForRole maps the role an operation declares to the action checked.
//
// Roles rather than actions on the Operation because that is what an agent is
// shown, and a surface that tells a caller "needs analyst" and then checks
// something else would be lying to it.
func actionForRole(role string) (auth.Action, error) {
	switch role {
	case "viewer":
		return auth.ActView, nil
	case "analyst":
		return auth.ActTriage, nil
	case "responder":
		return auth.ActRespond, nil
	case "admin":
		// The workforce summary is an administrator's: a person's score is
		// a file on an employee.
		return auth.ActGrant, nil
	}
	return "", fmt.Errorf("%q is not a role this program has", role)
}

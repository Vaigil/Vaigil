// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package inbound

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vaigil/vaigil/internal/telemetry"
)

// Quilzo's audit log, pushed as it is written.
//
// Quilzo keeps what defends it and hands its audit log to whoever watches,
// with siem.stream.url: batches of OCSF records, each with the chain
// envelope, every record's Merkle leaf and a tree head signed with Ed25519
// and ML-DSA, the request signed as an HTTP message (RFC 9421). A feed of
// this kind pins the keys Quilzo publishes for that (`quilzo siem stream
// key --json`), takes a batch only when internal/auditstream's Receiver
// says it follows the last one exactly and rebuilds the signed head, and
// stores each record as an event under its own source, quilzo/audit, where
// the quilzo.* rules read it.
//
// What is copied is what the record says and nothing more: the action, its
// outcome and resource, the kind of actor and the few details a rule needs.
// The principal is the pseudonym Quilzo sends unless it was told to reveal
// people, and is stored as it came.

// AuditStream is the kind of feed that receives Quilzo's audit log.
const AuditStream = "quilzo"

// StreamSource is the source its records are stored under.
const StreamSource = "quilzo/audit"

// StreamHeadContext is the context Quilzo signs its audit tree heads in.
const StreamHeadContext = "quilzo/audit-head/v1"

// StreamKeys are the keys a sender publishes for its receiver, as
// `quilzo siem stream key --json` writes them.
type StreamKeys struct {
	KeyID       string `json:"key_id"`
	Alg         string `json:"alg"`
	PublicKey   string `json:"public_key"`
	HeadKeyID   string `json:"head_key_id"`
	HeadEd25519 string `json:"head_ed25519"`
	HeadMLDSA   string `json:"head_mldsa"`
}

// ParseStreamKeys reads and checks published stream keys.
func ParseStreamKeys(b []byte) (*StreamKeys, error) {
	var k StreamKeys
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&k); err != nil {
		return nil, fmt.Errorf("these are not the keys `quilzo siem stream key --json` writes: %w", err)
	}
	if _, _, _, err := k.Decode(); err != nil {
		return nil, err
	}
	return &k, nil
}

// Decode returns the batch key and the two head keys.
func (k StreamKeys) Decode() (batch ed25519.PublicKey, headEd, headML []byte, err error) {
	if k.Alg != "ed25519" {
		return nil, nil, nil, fmt.Errorf("batches signed with %q; a stream signs them with ed25519", k.Alg)
	}
	if k.KeyID == "" || len(k.KeyID) > 100 || strings.ContainsAny(k.KeyID, "\" \t\r\n") {
		return nil, nil, nil, errors.New("the stream key has no usable key_id")
	}
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, nil, nil, errors.New("public_key is not an Ed25519 public key in base64")
	}
	if headEd, err = base64.StdEncoding.DecodeString(k.HeadEd25519); err != nil || len(headEd) != ed25519.PublicKeySize {
		return nil, nil, nil, errors.New("head_ed25519 is not an Ed25519 public key in base64")
	}
	if headML, err = base64.StdEncoding.DecodeString(k.HeadMLDSA); err != nil || len(headML) == 0 {
		return nil, nil, nil, errors.New("head_mldsa is not an ML-DSA public key in base64")
	}
	return ed25519.PublicKey(pub), headEd, headML, nil
}

// streamDetail are the details a rule about Quilzo may read. The rest are
// free text somebody typed, or not needed. "kind" is the kind of a request
// for a second administrator, kept as request_kind so it does not overwrite
// the kind of actor.
var streamDetail = map[string]string{
	"role": "role", "alone": "alone", "bootstrap": "bootstrap", "kind": "request_kind",
	"severity": "severity", "signal": "signal", "playbook": "playbook", "rule": "rule",
	"failures": "failures", "surface": "surface", "setting": "setting", "risk": "risk",
	"agent": "agent", "autonomy": "autonomy", "tool": "tool", "operation": "operation",
}

// StreamEvents maps a batch's OCSF records into events, in order. A line
// that is not a record is an error: the batch was verified, so a line that
// does not parse is the sender's bug and not something to skip quietly.
func StreamEvents(ocsf string, received time.Time) ([]telemetry.Event, error) {
	var out []telemetry.Event
	for n, line := range strings.Split(ocsf, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, err := streamEvent([]byte(line), received)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", n+1, err)
		}
		out = append(out, e)
	}
	return out, nil
}

type streamRecord struct {
	ClassUID     int    `json:"class_uid"`
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name"`
	Time         int64  `json:"time"`
	Status       string `json:"status"`
	API          struct {
		Operation string `json:"operation"`
	} `json:"api"`
	Actor struct {
		User struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"user"`
		AppName string `json:"app_name"`
	} `json:"actor"`
	Resources []struct {
		UID string `json:"uid"`
	} `json:"resources"`
	Unmapped map[string]any `json:"unmapped"`
}

func streamEvent(line []byte, received time.Time) (telemetry.Event, error) {
	var r streamRecord
	if err := json.Unmarshal(line, &r); err != nil {
		return telemetry.Event{}, err
	}
	if r.ActivityName == "" || r.Time == 0 {
		return telemetry.Event{}, errors.New("no action or no time")
	}
	class := telemetry.ClassAPIActivity
	if r.ClassUID == int(telemetry.ClassAuthentication) {
		class = telemetry.ClassAuthentication
	}
	disposition := telemetry.DispositionAllowed
	switch r.Status {
	case "denied":
		disposition = telemetry.DispositionBlocked
	case "failure":
		disposition = telemetry.DispositionFailed
	}
	kind := "human"
	switch r.Actor.User.Type {
	case "Service":
		kind = "service"
	case "AI":
		kind = "ai"
	}
	raw := map[string]string{"action": r.ActivityName, "outcome": r.Status, "kind": kind}
	if r.API.Operation != "" && r.API.Operation != r.ActivityName {
		raw["operation"] = r.API.Operation
	}
	if len(r.Resources) > 0 {
		raw["resource"] = r.Resources[0].UID
	}
	if r.Actor.AppName != "" {
		raw["model"] = r.Actor.AppName
	}
	for k, v := range r.Unmapped {
		switch k {
		case "seq", "hash":
			raw[k] = scalar(v)
			continue
		}
		name, ok := strings.CutPrefix(k, "detail_")
		if !ok {
			continue
		}
		if as, keep := streamDetail[name]; keep {
			raw[as] = scalar(v)
		}
	}
	activity := uint8(0)
	if r.ActivityID > 0 && r.ActivityID < 256 {
		activity = uint8(r.ActivityID)
	}
	return telemetry.Event{
		Time: time.UnixMilli(r.Time).UTC(), Received: received,
		Class: class, Activity: activity, Disposition: disposition,
		Source: StreamSource, Message: r.ActivityName,
		Actor: telemetry.ID{Issuer: "quilzo", Value: r.Actor.User.Name},
		Raw:   raw,
	}, nil
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package policy is the policy enforcement point's client to the policy
// decision point (OPA). The gateway never interprets policy itself; it builds
// an input document, asks OPA, and enforces the returned decision object.
//
// OPA runs as a sidecar on localhost (or is embedded via the rego package in
// a build that may take that dependency). Calls are fail-closed: any error
// talking to OPA is a deny.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Decision is the verdict: what OPA returns for one call. It mirrors
// valkyrie.tool_authz.decision and is never a bare boolean.
type Decision struct {
	Allow         bool           `json:"allow"`
	DenyReason    []string       `json:"deny_reason"`
	Obligations   map[string]any `json:"obligations"`
	PolicyVersion string         `json:"policy_version"`
	DecisionID    string         `json:"decision_id"`
	EvalMS        float64        `json:"eval_ms"`
}

func (d Decision) ApprovalRequired() bool {
	for _, r := range d.DenyReason {
		if r == "approval_required" {
			return true
		}
	}
	return false
}

func (d Decision) RedactFields() []string {
	v, ok := d.Obligations["redact_fields"]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (d Decision) MaxRows() int {
	if v, ok := d.Obligations["max_rows"].(float64); ok {
		return int(v)
	}
	return 0
}

type PDP interface {
	Decide(ctx context.Context, rule string, input map[string]any) (Decision, error)
}

// OPAClient speaks OPA's Data API: POST /v1/data/<path> {"input": ...}.
type OPAClient struct {
	BaseURL string
	HTTP    *http.Client
}

func NewOPA(baseURL string) *OPAClient {
	return &OPAClient{BaseURL: baseURL, HTTP: &http.Client{Timeout: 2 * time.Second}}
}

func (c *OPAClient) Decide(ctx context.Context, rule string, input map[string]any) (Decision, error) {
	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		return Decision{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/data/"+rule, bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("opa: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Decision{}, fmt.Errorf("opa: status %d", resp.StatusCode)
	}
	var env struct {
		Result     *Decision `json:"result"`
		DecisionID string    `json:"decision_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return Decision{}, fmt.Errorf("opa: decode: %w", err)
	}
	if env.Result == nil {
		// Undefined result == policy did not evaluate == deny.
		return Decision{Allow: false, DenyReason: []string{"policy_undefined"}}, nil
	}
	d := *env.Result
	d.DecisionID = env.DecisionID
	d.EvalMS = float64(time.Since(start).Microseconds()) / 1000
	if d.Obligations == nil {
		d.Obligations = map[string]any{}
	}
	return d, nil
}

// Static is an in-memory PDP for tests.
type Static struct {
	Fn func(rule string, input map[string]any) Decision
}

func (s Static) Decide(_ context.Context, rule string, input map[string]any) (Decision, error) {
	return s.Fn(rule, input), nil
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package pipeline

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"valkyrie/gateway/internal/audit"
	"valkyrie/gateway/internal/authn"
	"valkyrie/gateway/internal/credentials"
	"valkyrie/gateway/internal/mcpjson"
	"valkyrie/gateway/internal/policy"
	"valkyrie/gateway/internal/registry"
	"valkyrie/gateway/internal/upstream"
)

func newP(t *testing.T, pdp policy.PDP, broker credentials.Broker, sink audit.Sink, ups map[string]Executor) *Pipeline {
	t.Helper()
	p := New(Options{Registry: reg(t), PDP: pdp, Broker: broker, Audit: sink})
	for k, v := range ups {
		p.SetUpstream(k, v)
	}
	return p
}

type fakeUpstream struct {
	calls  int
	delay  time.Duration
	result mcpjson.CallToolResult
	seen   string
}

func (f *fakeUpstream) CallTool(ctx context.Context, cred upstream.Credential, name string, args map[string]any) (mcpjson.CallToolResult, error) {
	f.calls++
	f.seen = cred.Token
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return mcpjson.CallToolResult{}, ctx.Err()
		}
	}
	return f.result, nil
}

func reg(t *testing.T) *registry.Registry {
	t.Helper()
	r, err := registry.FromFile(registry.File{
		Servers: map[string]registry.Server{"orders": {URL: "http://x"}, "profile": {URL: "http://y"}},
		Tools: []registry.Manifest{
			{Name: "orders.create_cart", Server: "orders", Version: "2.0.0", RiskTier: 2, DataClassification: "confidential",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"items":{"type":"array","items":{"type":"string"}}},"required":["items"],"additionalProperties":false}`),
				Credentials: registry.Credentials{VaultRole: "w", Scope: "orders:write", TTLSeconds: 60},
				Limits:      registry.Limits{TimeoutMS: 50, MaxResultKB: 1, RatePerMinute: 5}, Idempotent: true},
			{Name: "profile.get_preferences", Server: "profile", Version: "1.0.0", RiskTier: 1, DataClassification: "pii",
				InputSchema: json.RawMessage(`{"type":"object"}`),
				Credentials: registry.Credentials{VaultRole: "r", Scope: "profile:read", TTLSeconds: 60},
				Limits:      registry.Limits{TimeoutMS: 500, MaxResultKB: 64}, Idempotent: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var caller = authn.Caller{AgentID: "ordering-01", AgentRole: "ordering", Subject: "jane", TenantID: "acme"}

func TestDenyPathNeverTouchesUpstreamOrLeases(t *testing.T) {
	up := &fakeUpstream{}
	broker := credentials.NewSigned([]byte("k"), "test")
	mem := &audit.Memory{}
	pdp := policy.Static{Fn: func(_ string, in map[string]any) policy.Decision {
		return policy.Decision{Allow: false, DenyReason: []string{"allergen_conflict: Pesto Pasta contains tree_nuts"}, PolicyVersion: "v1"}
	}}
	p := newP(t, pdp, broker, mem, map[string]Executor{"orders": up})
	res := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"Pesto Pasta"}}, Context{TraceID: "t1"})
	if res.Status != StatusDenied || res.Reason[0] != "allergen_conflict: Pesto Pasta contains tree_nuts" {
		t.Fatalf("got %+v", res)
	}
	if up.calls != 0 || broker.Active() != 0 {
		t.Fatalf("deny must not execute or lease: calls=%d leases=%d", up.calls, broker.Active())
	}
	ev := mem.Snapshot()
	if len(ev) != 1 || ev[0].Outcome != "denied" || ev[0].ArgsHash == "" {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestAllowPathLeasesExecutesRevokes(t *testing.T) {
	up := &fakeUpstream{result: mcpjson.CallToolResult{Content: []mcpjson.Content{{Type: "text", Text: `{"cart_id":"c1"}`}}}}
	broker := credentials.NewSigned([]byte("k"), "test")
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision {
		return policy.Decision{Allow: true, Obligations: map[string]any{}}
	}}
	p := newP(t, pdp, broker, &audit.Memory{}, map[string]Executor{"orders": up})
	res := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"Margherita Pizza"}}, Context{IdempotencyKey: "k1"})
	if res.Status != StatusOK || up.calls != 1 {
		t.Fatalf("got %+v", res)
	}
	if up.seen == "" || broker.Active() != 0 {
		t.Fatalf("bearer must be set and lease revoked: bearer=%q active=%d", up.seen, broker.Active())
	}
	// idempotent replay
	res2 := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"Margherita Pizza"}}, Context{IdempotencyKey: "k1"})
	if res2.Status != StatusOK || up.calls != 1 {
		t.Fatalf("replay must not re-execute: calls=%d", up.calls)
	}
}

func TestSchemaRejectsBeforePolicy(t *testing.T) {
	asked := false
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision { asked = true; return policy.Decision{Allow: true} }}
	p := newP(t, pdp, credentials.NewSigned([]byte("k"), "test"), &audit.Memory{}, map[string]Executor{"orders": &fakeUpstream{}})
	res := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": "not-an-array", "sql": "DROP TABLE"}, Context{})
	if res.Status != StatusInvalid || len(res.Violations) != 2 || asked {
		t.Fatalf("got %+v asked=%v", res, asked)
	}
}

func TestApprovalRequiredIsDistinct(t *testing.T) {
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision {
		return policy.Decision{Allow: false, DenyReason: []string{"approval_required"}}
	}}
	p := newP(t, pdp, credentials.NewSigned([]byte("k"), "test"), &audit.Memory{}, map[string]Executor{"orders": &fakeUpstream{}})
	res := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"x"}}, Context{})
	if res.Status != StatusApprovalRequired {
		t.Fatalf("got %+v", res)
	}
}

func TestRedactionObligation(t *testing.T) {
	up := &fakeUpstream{result: mcpjson.CallToolResult{
		Content:           []mcpjson.Content{{Type: "text", Text: `{"name":"Jane","phone":"555-0100","address":{"email":"j@x.io","city":"Pleasanton"}}`}},
		StructuredContent: json.RawMessage(`{"phone":"555-0100","email":"j@x.io"}`)}}
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision {
		return policy.Decision{Allow: true, Obligations: map[string]any{"redact_fields": []any{"phone", "email"}}}
	}}
	p := newP(t, pdp, credentials.NewSigned([]byte("k"), "test"), &audit.Memory{}, map[string]Executor{"profile": up})
	res := p.Invoke(context.Background(), caller, "profile.get_preferences", map[string]any{}, Context{})
	if res.Status != StatusOK {
		t.Fatalf("got %+v", res)
	}
	var out map[string]any
	json.Unmarshal([]byte(res.Content.Content[0].Text), &out)
	if out["phone"] != "[REDACTED]" || out["address"].(map[string]any)["email"] != "[REDACTED]" || out["name"] != "Jane" {
		t.Fatalf("redaction wrong: %v", out)
	}
	if len(res.Redacted) != 2 {
		t.Fatalf("redacted list: %v", res.Redacted)
	}
}

func TestTimeoutFromManifest(t *testing.T) {
	up := &fakeUpstream{delay: 300 * time.Millisecond}
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision { return policy.Decision{Allow: true} }}
	broker := credentials.NewSigned([]byte("k"), "test")
	p := newP(t, pdp, broker, &audit.Memory{}, map[string]Executor{"orders": up})
	res := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"x"}}, Context{})
	if res.Status != StatusUpstreamError || res.Reason[0] != "timeout after 50ms" {
		t.Fatalf("got %+v", res)
	}
	if broker.Active() != 0 {
		t.Fatal("lease must be revoked on timeout")
	}
}

func TestPolicyUnavailableFailsClosed(t *testing.T) {
	type failing struct{ policy.PDP }
	f := failingPDP{}
	p := newP(t, f, credentials.NewSigned([]byte("k"), "test"), &audit.Memory{}, map[string]Executor{"orders": &fakeUpstream{}})
	res := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"x"}}, Context{})
	if res.Status != StatusDenied || res.Reason[0] != "policy_unavailable" {
		t.Fatalf("got %+v", res)
	}
	_ = failing{}
}

type failingPDP struct{}

func (failingPDP) Decide(context.Context, string, map[string]any) (policy.Decision, error) {
	return policy.Decision{}, errors.New("opa down")
}

func TestUnknownTool(t *testing.T) {
	p := newP(t, policy.Static{Fn: func(string, map[string]any) policy.Decision { return policy.Decision{Allow: true} }}, credentials.NewSigned([]byte("k"), "test"), &audit.Memory{}, nil)
	if res := p.Invoke(context.Background(), caller, "nope.tool", nil, Context{}); res.Status != StatusUnknownTool {
		t.Fatalf("got %+v", res)
	}
}

func TestRateLimitPerTenant(t *testing.T) {
	up := &fakeUpstream{result: mcpjson.CallToolResult{Content: []mcpjson.Content{{Type: "text", Text: "ok"}}}}
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision { return policy.Decision{Allow: true} }}
	p := newP(t, pdp, credentials.NewSigned([]byte("k"), "test"), &audit.Memory{}, map[string]Executor{"orders": up})
	for i := 0; i < 5; i++ {
		if r := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"x"}}, Context{}); r.Status != StatusOK {
			t.Fatalf("call %d: %+v", i, r)
		}
	}
	r := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"x"}}, Context{})
	if r.Status != StatusRateLimited {
		t.Fatalf("6th call must be rate limited: %+v", r)
	}
	other := caller
	other.TenantID = "globex"
	if r := p.Invoke(context.Background(), other, "orders.create_cart", map[string]any{"items": []string{"x"}}, Context{}); r.Status != StatusOK {
		t.Fatalf("other tenant has its own budget: %+v", r)
	}
}

type panicky struct{}

func (panicky) CallTool(context.Context, upstream.Credential, string, map[string]any) (mcpjson.CallToolResult, error) {
	panic("boom")
}

func TestPanicIsContainedAndLeaseRevoked(t *testing.T) {
	broker := credentials.NewSigned([]byte("k"), "test")
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision { return policy.Decision{Allow: true} }}
	p := newP(t, pdp, broker, &audit.Memory{}, map[string]Executor{"orders": panicky{}})
	r := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"x"}}, Context{})
	if r.Status != StatusUpstreamError || r.Reason[0] != "internal error" {
		t.Fatalf("panic must become an error result: %+v", r)
	}
	if broker.Active() != 0 {
		t.Fatal("lease must be revoked even on panic")
	}
}

func TestHTTPAdapterTool(t *testing.T) {
	var gotPath, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotKey = r.URL.Path+"?"+r.URL.RawQuery, r.Header.Get("X-API-Key")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"city":"Pleasanton","temp_c":21,"phone":"555"}`))
	}))
	defer srv.Close()
	r, _ := registry.FromFile(registry.File{Servers: map[string]registry.Server{}, Tools: []registry.Manifest{{
		Name: "weather.forecast", Server: "weather", Version: "1.0.0", RiskTier: 0, DataClassification: "public",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"city":{"type":"string"},"units":{"type":"string"}},"required":["city"]}`),
		Credentials: registry.Credentials{Type: "static", SecretRef: "WEATHER_KEY", Scope: "weather:read", Header: "X-API-Key", TTLSeconds: 60},
		Limits:      registry.Limits{TimeoutMS: 1000, MaxResultKB: 16},
		Adapter:     &registry.Adapter{Type: "http", Method: "GET", URL: srv.URL + "/v1/forecast/{city}", Query: []string{"units"}},
	}}})
	broker := credentials.Router{Signed: credentials.NewSigned([]byte("k"), "t"), Static: &credentials.StaticBroker{Lookup: func(string) string { return "sk-weather" }}, None: credentials.NoneBroker{}}
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision {
		return policy.Decision{Allow: true, Obligations: map[string]any{"redact_fields": []any{"phone"}}}
	}}
	p := New(Options{Registry: r, PDP: pdp, Broker: broker, Audit: &audit.Memory{}})
	res := p.Invoke(context.Background(), caller, "weather.forecast", map[string]any{"city": "Pleasanton", "units": "c"}, Context{})
	if res.Status != StatusOK {
		t.Fatalf("got %+v", res)
	}
	if gotPath != "/v1/forecast/Pleasanton?units=c" || gotKey != "sk-weather" {
		t.Fatalf("adapter request wrong: %s key=%s", gotPath, gotKey)
	}
	if !strings.Contains(res.Content.Content[0].Text, "[REDACTED]") || strings.Contains(string(res.Content.StructuredContent), "555") {
		t.Fatalf("redaction must apply to adapter results: %s %s", res.Content.Content[0].Text, res.Content.StructuredContent)
	}
}

// ---------------------------------------------------------------- delegated authorization

func leaseClaims(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a jwt: %q", tok)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLeaseCarriesCallerSubjectAndTenant(t *testing.T) {
	up := &fakeUpstream{result: mcpjson.CallToolResult{Content: []mcpjson.Content{{Type: "text", Text: `{}`}}}}
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision { return policy.Decision{Allow: true} }}
	p := newP(t, pdp, credentials.NewSigned([]byte("k"), "test"), &audit.Memory{}, map[string]Executor{"orders": up})
	res := p.Invoke(context.Background(), caller, "orders.create_cart", map[string]any{"items": []string{"x"}}, Context{})
	if res.Status != StatusOK {
		t.Fatalf("got %+v", res)
	}
	c := leaseClaims(t, up.seen)
	if c["sub"] != caller.Subject || c["tenant_id"] != caller.TenantID {
		t.Fatalf("upstream lease must identify the end user the call is for: %v", c)
	}
}

type errPDP struct{}

func (errPDP) Decide(context.Context, string, map[string]any) (policy.Decision, error) {
	return policy.Decision{}, errors.New("opa down")
}

var supervisor = authn.Caller{AgentID: "concierge-01", AgentRole: "concierge", Subject: "jane", TenantID: "acme", Chain: []string{"root-01"}}

func TestDelegateUsesVerifiedCallerAndChain(t *testing.T) {
	var gotRule string
	var gotInput map[string]any
	pdp := policy.Static{Fn: func(rule string, in map[string]any) policy.Decision {
		gotRule, gotInput = rule, in
		return policy.Decision{Allow: true, PolicyVersion: "v1"}
	}}
	mem := &audit.Memory{}
	p := newP(t, pdp, credentials.NewSigned([]byte("k"), "test"), mem, nil)
	res := p.Delegate(context.Background(), supervisor, DelegationRequest{
		Target:  map[string]any{"id": "menu-01", "tenant_id": "acme", "trust_level": 2},
		Task:    map[string]any{"required_trust": 1, "est_tokens": 2000},
		Budget:  map[string]any{"tokens_used": 10, "token_limit": 100},
		Chain:   []string{"forged-by-caller"}, // must be ignored: the chain comes from the verified token
		TraceID: "t9",
	})
	if !res.Allow || res.PolicyVersion != "v1" || res.TraceID != "t9" {
		t.Fatalf("got %+v", res)
	}
	if gotRule != "valkyrie/delegation/decision" {
		t.Fatalf("rule: %s", gotRule)
	}
	c := gotInput["caller"].(map[string]any)
	if c["id"] != "concierge-01" || c["tenant_id"] != "acme" {
		t.Fatalf("caller must come from the token: %v", c)
	}
	chain, _ := gotInput["chain"].([]string)
	if len(chain) != 1 || chain[0] != "root-01" {
		t.Fatalf("chain must come from the token, not the request: %v", gotInput["chain"])
	}
	if gotInput["target"].(map[string]any)["id"] != "menu-01" || gotInput["task"] == nil || gotInput["budget"] == nil {
		t.Fatalf("target/task/budget must be passed through: %v", gotInput)
	}
	ev := mem.Snapshot()
	if len(ev) != 1 || ev[0].Outcome != "ok" || ev[0].AgentID != "concierge-01" || ev[0].Tool != "delegate:menu-01" {
		t.Fatalf("delegation must be audited: %+v", ev)
	}
}

func TestDelegateDenyCarriesReasons(t *testing.T) {
	pdp := policy.Static{Fn: func(string, map[string]any) policy.Decision {
		return policy.Decision{Allow: false, DenyReason: []string{"delegation_loop"}, PolicyVersion: "v1"}
	}}
	mem := &audit.Memory{}
	p := newP(t, pdp, credentials.NewSigned([]byte("k"), "test"), mem, nil)
	res := p.Delegate(context.Background(), supervisor, DelegationRequest{Target: map[string]any{"id": "root-01"}})
	if res.Allow || len(res.Reason) != 1 || res.Reason[0] != "delegation_loop" {
		t.Fatalf("got %+v", res)
	}
	if ev := mem.Snapshot(); len(ev) != 1 || ev[0].Outcome != "denied" || ev[0].DenyReason[0] != "delegation_loop" {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestDelegateFailsClosedWhenPDPUnavailable(t *testing.T) {
	p := newP(t, errPDP{}, credentials.NewSigned([]byte("k"), "test"), &audit.Memory{}, nil)
	res := p.Delegate(context.Background(), supervisor, DelegationRequest{Target: map[string]any{"id": "menu-01"}})
	if res.Allow || len(res.Reason) != 1 || res.Reason[0] != "policy_unavailable" {
		t.Fatalf("PDP error must deny: %+v", res)
	}
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"valkyrie/gateway/internal/audit"
	"valkyrie/gateway/internal/authn"
	"valkyrie/gateway/internal/credentials"
	"valkyrie/gateway/internal/mcpjson"
	"valkyrie/gateway/internal/metrics"
	"valkyrie/gateway/internal/pipeline"
	"valkyrie/gateway/internal/policy"
	"valkyrie/gateway/internal/registry"
	"valkyrie/gateway/internal/upstream"
)

type okUpstream struct{}

func (okUpstream) CallTool(context.Context, upstream.Credential, string, map[string]any) (mcpjson.CallToolResult, error) {
	return mcpjson.CallToolResult{Content: []mcpjson.Content{{Type: "text", Text: `{"ok":true}`}}}, nil
}

func testServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	reg, _ := registry.FromFile(registry.File{Servers: map[string]registry.Server{"orders": {URL: "x"}}, Tools: []registry.Manifest{
		{Name: "orders.create_cart", Server: "orders", Version: "1", RiskTier: 2, DataClassification: "confidential",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"items":{"type":"array"}},"required":["items"]}`),
			Credentials: registry.Credentials{Scope: "orders:write", TTLSeconds: 60}, Limits: registry.Limits{TimeoutMS: 1000}, Idempotent: true},
		{Name: "menu.search_menu", Server: "orders", Version: "1", RiskTier: 0, DataClassification: "public",
			InputSchema: json.RawMessage(`{"type":"object"}`), Credentials: registry.Credentials{Scope: "menu:read", TTLSeconds: 60}, Limits: registry.Limits{TimeoutMS: 1000}},
	}})
	pdp := policy.Static{Fn: func(_ string, in map[string]any) policy.Decision {
		role := in["agent"].(map[string]any)["role"].(string)
		tool := in["tool"].(map[string]any)["name"].(string)
		if role == "menu" && tool != "menu.search_menu" {
			return policy.Decision{Allow: false, DenyReason: []string{"tool_not_bound_to_role"}}
		}
		if items, ok := in["tool"].(map[string]any)["args"].(map[string]any)["items"].([]any); ok && len(items) > 0 && items[0] == "Pesto Pasta" {
			return policy.Decision{Allow: false, DenyReason: []string{"allergen_conflict: Pesto Pasta contains tree_nuts"}, PolicyVersion: "v1"}
		}
		return policy.Decision{Allow: true, PolicyVersion: "v1"}
	}}
	p := pipeline.New(pipeline.Options{Registry: reg, PDP: pdp, Broker: credentials.NewSigned([]byte("k"), "t"), Audit: &audit.Memory{}, Metrics: metrics.New()})
	p.SetUpstream("orders", okUpstream{})
	s := &Server{Verifier: authn.HMACVerifier{Secret: []byte("s")}, Pipeline: p, Log: slog.New(slog.NewTextHandler(discard{}, nil)),
		Metrics: p.Metrics.Handler(), Ready: func(context.Context) error { return nil }}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	tok, _ := authn.Sign([]byte("s"), map[string]any{"sub": "jane", "tenant_id": "acme", "agent_id": "o1", "agent_role": "ordering", "exp": time.Now().Add(time.Hour).Unix()})
	return srv, tok
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func do(t *testing.T, srv *httptest.Server, tok, method, path, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return resp, out
}

func TestRESTFace(t *testing.T) {
	srv, tok := testServer(t)
	resp, _ := do(t, srv, "bad", "POST", "/v1/tools/invoke", `{"tool":"menu.search_menu"}`)
	if resp.StatusCode != 401 {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	resp, out := do(t, srv, tok, "POST", "/v1/tools/invoke", `{"tool":"orders.create_cart","args":{"items":["Pesto Pasta"]}}`)
	if resp.StatusCode != 403 || out["status"] != "denied" {
		t.Fatalf("deny: %d %v", resp.StatusCode, out)
	}
	if resp.Header.Get("X-Trace-Id") == "" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("trace id and no-store headers expected")
	}
	resp, out = do(t, srv, tok, "POST", "/v1/tools/invoke", `{"tool":"orders.create_cart","args":{"items":["Margherita"]},"idempotency_key":"k1"}`)
	if resp.StatusCode != 200 || out["status"] != "ok" {
		t.Fatalf("allow: %d %v", resp.StatusCode, out)
	}
	_, out = do(t, srv, tok, "POST", "/v1/tools/invoke", `{"tool":"orders.create_cart","args":{"items":["Margherita"]},"idempotency_key":"k1"}`)
	if out["replayed"] != true {
		t.Fatalf("second call with same key must replay: %v", out)
	}
	resp, _ = do(t, srv, tok, "POST", "/v1/tools/invoke", `{"tool":"orders.create_cart","args":{"items":"nope"}}`)
	if resp.StatusCode != 422 {
		t.Fatalf("invalid args: %d", resp.StatusCode)
	}
	resp, _ = do(t, srv, tok, "POST", "/v1/tools/invoke", `{"tool":"ghost.tool"}`)
	if resp.StatusCode != 404 {
		t.Fatalf("unknown tool: %d", resp.StatusCode)
	}
	resp, out = do(t, srv, tok, "GET", "/v1/tools", "")
	if resp.StatusCode != 200 || len(out["tools"].([]any)) != 2 {
		t.Fatalf("list: %d %v", resp.StatusCode, out)
	}
	mreq, _ := http.NewRequest("GET", srv.URL+"/metrics", nil)
	mresp, _ := http.DefaultClient.Do(mreq)
	b := make([]byte, 4096)
	n, _ := mresp.Body.Read(b)
	if !strings.Contains(string(b[:n]), `valkyrie_tool_calls_total{tool="orders.create_cart",outcome="denied"} 1`) {
		t.Fatalf("metrics missing deny counter:\n%s", b[:n])
	}
}

func TestMCPFace(t *testing.T) {
	srv, tok := testServer(t)
	rpc := func(body string) map[string]any {
		_, out := do(t, srv, tok, "POST", "/mcp", body)
		return out
	}
	init := rpc(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if init["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "valkyrie" {
		t.Fatalf("initialize: %v", init)
	}
	list := rpc(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if len(list["result"].(map[string]any)["tools"].([]any)) != 2 {
		t.Fatalf("tools/list: %v", list)
	}
	den := rpc(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"orders.create_cart","arguments":{"items":["Pesto Pasta"]}}}`)
	res := den["result"].(map[string]any)
	if res["isError"] != true || !strings.Contains(res["content"].([]any)[0].(map[string]any)["text"].(string), "allergen_conflict") {
		t.Fatalf("deny must be an isError tool result: %v", den)
	}
	unk := rpc(`{"jsonrpc":"2.0","id":4,"method":"resources/list"}`)
	if unk["error"].(map[string]any)["code"].(float64) != mcpjson.CodeMethodNotFound {
		t.Fatalf("unsupported method: %v", unk)
	}
	// menu role sees one tool
	mtok, _ := authn.Sign([]byte("s"), map[string]any{"sub": "x", "tenant_id": "acme", "agent_id": "m1", "agent_role": "menu", "exp": time.Now().Add(time.Hour).Unix()})
	_, out := do(t, srv, mtok, "POST", "/mcp", `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	if len(out["result"].(map[string]any)["tools"].([]any)) != 1 {
		t.Fatalf("menu role must see one tool: %v", out)
	}
}

func TestReadyzReflectsDependencies(t *testing.T) {
	s := &Server{Verifier: authn.HMACVerifier{Secret: []byte("s")}, Log: slog.Default(),
		Ready: func(context.Context) error { return errors.New("opa unreachable") }}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/readyz")
	if resp.StatusCode != 503 {
		t.Fatalf("readyz should be 503 when a dependency is down, got %d", resp.StatusCode)
	}
}

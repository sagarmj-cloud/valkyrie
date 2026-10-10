// SPDX-License-Identifier: LicenseRef-Valkyrie-Enterprise
// Copyright (c) 2026 Sagar Jadhav

package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"valkyrie/controlplane/internal/bundle"
	"valkyrie/controlplane/internal/store"
)

// fake MCP server exposing one tool "add" so contract tests can pass.
func fakeMCP(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		switch req["method"] {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "s1")
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"protocolVersion": "2025-06-18"}})
		case "notifications/initialized":
			w.WriteHeader(202)
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req["id"], "result": map[string]any{"tools": []map[string]any{{
				"name": "add", "description": "Adds two numbers",
				"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "number"}, "b": map[string]any{"type": "number"}}, "required": []string{"a", "b"}}}}}})
		}
	}))
}

func newServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "data.json"), []byte(`{"policy_version":"test","limits":{"tip_rate":0.1}}`), 0o644)
	os.WriteFile(filepath.Join(dir, "x.rego"), []byte("package x\n"), 0o644)
	st, _ := store.Open(filepath.Join(dir, "state.json"))
	s := &Server{Store: st, AdminToken: "admin", Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Bundle: &bundle.Builder{PolicyDir: dir, SigningKey: []byte("k"), KeyID: "test"}}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st
}

func req(t *testing.T, srv *httptest.Server, method, path string, body any, hdr map[string]string) (int, map[string]any, http.Header) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, srv.URL+path, rdr)
	r.Header.Set("Authorization", "Bearer admin")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &out)
	return resp.StatusCode, out, resp.Header
}

func manifest(server string) map[string]any {
	return map[string]any{"owner": "team-x", "server": server, "version": "1.0.0", "description": "Adds two numbers together",
		"risk_tier": 0, "data_classification": "public", "input_schema": map[string]any{"type": "object",
			"properties": map[string]any{"a": map[string]any{"type": "number"}, "b": map[string]any{"type": "number"}}, "required": []string{"a", "b"}},
		"credentials": map[string]any{"type": "none", "scope": "calc:read", "ttl_seconds": 60},
		"limits":      map[string]any{"timeout_ms": 1000, "rate_per_minute": 60, "max_result_kb": 16}, "idempotent": true, "upstream_name": "add"}
}

func TestPublishFlowWithContractTest(t *testing.T) {
	srv, st := newServer(t)
	mcp := fakeMCP(t)
	defer mcp.Close()

	// unauthenticated write refused
	if code, _, _ := req(t, srv, "PUT", "/v1/servers/calc", map[string]any{"url": mcp.URL}, map[string]string{"Authorization": "Bearer nope"}); code != 401 {
		t.Fatalf("expected 401, got %d", code)
	}
	// publishing before the server exists fails
	if code, out, _ := req(t, srv, "PUT", "/v1/tools/calc.add", manifest("calc"), nil); code != 422 {
		t.Fatalf("expected 422 unknown server, got %d %v", code, out)
	}
	if code, _, _ := req(t, srv, "PUT", "/v1/servers/calc", map[string]any{"url": mcp.URL, "runtime": "node"}, nil); code != 200 {
		t.Fatal("server add")
	}
	// contract test: wrong upstream tool name is rejected
	bad := manifest("calc")
	bad["upstream_name"] = "subtract"
	if code, out, _ := req(t, srv, "PUT", "/v1/tools/calc.add", bad, nil); code != 422 || !strings.Contains(out["error"].(string), "contract") {
		t.Fatalf("expected contract failure, got %d %v", code, out)
	}
	// manifest declaring an argument the server lacks is rejected
	bad = manifest("calc")
	bad["input_schema"].(map[string]any)["properties"].(map[string]any)["c"] = map[string]any{"type": "number"}
	if code, _, _ := req(t, srv, "PUT", "/v1/tools/calc.add", bad, nil); code != 422 {
		t.Fatal("schema incompatibility must be rejected")
	}
	// good publish
	code, out, _ := req(t, srv, "PUT", "/v1/tools/calc.add", manifest("calc"), nil)
	if code != 200 || out["revision"].(float64) != 2 {
		t.Fatalf("publish: %d %v changes=%+v", code, out, st.Changes(10))
	}
	// version must not go backwards
	old := manifest("calc")
	old["version"] = "0.9.0"
	if code, _, _ := req(t, srv, "PUT", "/v1/tools/calc.add", old, nil); code != 409 {
		t.Fatal("downgrade must conflict")
	}
	// optimistic concurrency
	if code, _, _ := req(t, srv, "PUT", "/v1/tools/calc.add", manifest("calc"), map[string]string{"If-Match-Version": "0.0.1"}); code != 409 {
		t.Fatal("If-Match-Version mismatch must conflict")
	}
	// invalid manifest: tier 3 without approval
	bad = manifest("calc")
	bad["risk_tier"] = 3
	if code, out, _ := req(t, srv, "PUT", "/v1/tools/calc.add", bad, nil); code != 422 || out["problems"] == nil {
		t.Fatalf("validation: %d %v", code, out)
	}
	// role bind to unknown tool fails; to known tool succeeds
	if code, _, _ := req(t, srv, "PUT", "/v1/roles/analyst", map[string]any{"tools": []string{"ghost.tool"}, "max_tier": 1}, nil); code != 422 {
		t.Fatal("binding unknown tool must fail")
	}
	if code, _, _ := req(t, srv, "PUT", "/v1/roles/analyst", map[string]any{"tools": []string{"calc.add"}, "max_tier": 1}, nil); code != 200 {
		t.Fatal("role bind")
	}
	// snapshot + ETag
	_, snap, hdr := req(t, srv, "GET", "/v1/registry", nil, nil)
	if len(snap["tools"].([]any)) != 1 || hdr.Get("ETag") == "" {
		t.Fatalf("snapshot: %v", snap)
	}
	if code, _, _ := req(t, srv, "GET", "/v1/registry", nil, map[string]string{"If-None-Match": hdr.Get("ETag")}); code != 304 {
		t.Fatal("ETag must yield 304")
	}
	// deprecate removes from snapshot but keeps in ?state=all
	req(t, srv, "DELETE", "/v1/tools/calc.add", nil, nil)
	_, snap, _ = req(t, srv, "GET", "/v1/registry", nil, nil)
	if snap["tools"] != nil && len(snap["tools"].([]any)) != 0 {
		t.Fatal("deprecated tool must leave the snapshot")
	}
	_, all, _ := req(t, srv, "GET", "/v1/tools?state=all", nil, nil)
	if len(all["tools"].([]any)) != 1 {
		t.Fatal("deprecated tool must remain listed with state=all")
	}
	// change log
	if ch := st.Changes(10); len(ch) < 4 || ch[0].Action != "deprecate" {
		t.Fatalf("changes: %+v", ch)
	}
}

func TestBundleIsSignedAndCarriesRoles(t *testing.T) {
	srv, st := newServer(t)
	st.PutServer("t", store.Server{Name: "calc", URL: "http://x"})
	st.PutTool("t", store.Manifest{Name: "calc.add", Server: "calc", Version: "1.0.0", RiskTier: 2}, "")
	st.PutRole("t", store.Role{Name: "analyst", Tools: []string{"calc.add"}, MaxTier: 2})
	r, _ := http.NewRequest("GET", srv.URL+"/v1/bundle.tar.gz", nil)
	r.Header.Set("Authorization", "Bearer admin")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = b
	}
	for _, want := range []string{"/.signatures.json", "/.manifest", "/data.json", "/x.rego"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("bundle missing %s (has %v)", want, keys(files))
		}
	}
	var data map[string]any
	json.Unmarshal(files["/data.json"], &data)
	if data["roles"].(map[string]any)["analyst"].(map[string]any)["max_tier"].(float64) != 2 || data["tool_tiers"].(map[string]any)["calc.add"].(float64) != 2 {
		t.Fatalf("data.json must carry roles and tiers: %s", files["/data.json"])
	}
	if data["policy_version"] != "test" {
		t.Fatal("static data must be preserved")
	}
	var sig map[string][]string
	json.Unmarshal(files["/.signatures.json"], &sig)
	if len(sig["signatures"]) != 1 || strings.Count(sig["signatures"][0], ".") != 2 {
		t.Fatal("expected one JWT signature")
	}
	if resp.Header.Get("ETag") == "" {
		t.Fatal("bundle ETag")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

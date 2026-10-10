// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"valkyrie/gateway/internal/mcpjson"
)

// fake MCP server: answers initialize as JSON and tools/call as SSE.
func fakeServer(t *testing.T, fail *bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *fail {
			http.Error(w, "boom", 500)
			return
		}
		var req mcpjson.Request
		json.NewDecoder(r.Body).Decode(&req)
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "no bearer", 401)
			return
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			json.NewEncoder(w).Encode(mcpjson.NewResponse(req.ID, map[string]any{"protocolVersion": "2025-06-18"}))
		case "notifications/initialized":
			w.WriteHeader(202)
		case "tools/call":
			if r.Header.Get("Mcp-Session-Id") != "sess-1" {
				http.Error(w, "no session", 404)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n")
			res := mcpjson.NewResponse(req.ID, mcpjson.CallToolResult{Content: []mcpjson.Content{{Type: "text", Text: "hello"}}})
			b, _ := json.Marshal(res)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
		}
	}))
}

func TestCallToolOverSSEWithSession(t *testing.T) {
	fail := false
	srv := fakeServer(t, &fail)
	defer srv.Close()
	c := New("orders", srv.URL, Options{MaxInFlight: 2, MaxFailures: 2, Cooldown: 200 * time.Millisecond})
	out, err := c.CallTool(context.Background(), Credential{Token: "tok"}, "orders.create_cart", map[string]any{"items": []string{"x"}})
	if err != nil || out.Content[0].Text != "hello" {
		t.Fatalf("err=%v out=%+v", err, out)
	}
}

func TestCircuitBreaker(t *testing.T) {
	fail := false
	srv := fakeServer(t, &fail)
	defer srv.Close()
	c := New("orders", srv.URL, Options{MaxInFlight: 2, MaxFailures: 2, Cooldown: 200 * time.Millisecond})
	fail = true
	for i := 0; i < 2; i++ {
		if _, err := c.CallTool(context.Background(), Credential{Token: "tok"}, "t", nil); err == nil {
			t.Fatal("expected failure")
		}
	}
	if _, err := c.CallTool(context.Background(), Credential{Token: "tok"}, "t", nil); err != ErrCircuitOpen {
		t.Fatalf("expected open circuit, got %v", err)
	}
	fail = false
	time.Sleep(250 * time.Millisecond)
	if _, err := c.CallTool(context.Background(), Credential{Token: "tok"}, "t", nil); err != nil {
		t.Fatalf("expected recovery, got %v", err)
	}
}

func TestBackpressure(t *testing.T) {
	c := New("slow", "http://127.0.0.1:1", Options{MaxInFlight: 1})
	c.sem <- struct{}{} // occupy the only slot
	if _, err := c.CallTool(context.Background(), Credential{Token: "tok"}, "t", nil); err != ErrBusy {
		t.Fatalf("expected ErrBusy, got %v", err)
	}
}

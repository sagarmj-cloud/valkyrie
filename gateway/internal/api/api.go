// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package api exposes the gateway's two faces over the same pipeline:
//
//	POST /v1/tools/invoke   plain JSON for the agent SDK
//	GET  /v1/tools          policy-filtered catalogue
//	POST /mcp               MCP Streamable HTTP (initialize, tools/list, tools/call)
//	GET  /healthz, /readyz
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"valkyrie/gateway/internal/authn"
	"valkyrie/gateway/internal/mcpjson"
	"valkyrie/gateway/internal/pipeline"
)

type Server struct {
	Verifier authn.Verifier
	Pipeline *pipeline.Pipeline
	Log      *slog.Logger
	MaxBody  int64
	Metrics  http.Handler
	// Ready reports whether dependencies (OPA, store, registry) are usable.
	Ready func(ctx context.Context) error
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.Ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := s.Ready(ctx); err != nil {
				http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.Write([]byte("ok"))
	})
	if s.Metrics != nil {
		mux.Handle("GET /metrics", s.Metrics)
	}
	mux.HandleFunc("GET /v1/tools", s.withAuth(s.listTools))
	mux.HandleFunc("POST /v1/tools/invoke", s.withAuth(s.invoke))
	mux.HandleFunc("POST /mcp", s.withAuth(s.mcp))
	mux.HandleFunc("GET /mcp", s.withAuth(func(w http.ResponseWriter, r *http.Request, _ authn.Caller) {
		// Server-initiated stream: not used by the gateway (it has nothing to push).
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	mux.HandleFunc("DELETE /mcp", s.withAuth(func(w http.ResponseWriter, r *http.Request, _ authn.Caller) {
		w.WriteHeader(http.StatusNoContent)
	}))
	return s.trace(s.recover(mux))
}

// recover converts a handler panic into a 500 instead of killing the connection
// (the pipeline has its own recover; this covers the API layer itself).
func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Log.Error("handler panic", "path", r.URL.Path, "panic", fmt.Sprint(rec))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type handler func(http.ResponseWriter, *http.Request, authn.Caller)

func (s *Server) withAuth(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.Verifier.Verify(r)
		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/mcp") {
				writeJSON(w, http.StatusUnauthorized, mcpjson.NewError(nil, mcpjson.CodeUnauthenticated, err.Error(), nil))
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
			return
		}
		h(w, r, c)
	}
}

func (s *Server) trace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid := r.Header.Get("X-Trace-Id")
		if tid == "" {
			b := make([]byte, 8)
			rand.Read(b)
			tid = hex.EncodeToString(b)
		}
		w.Header().Set("X-Trace-Id", tid)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.Header.Set("X-Trace-Id", tid)
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if s.Log != nil && r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && r.URL.Path != "/metrics" {
			s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status, "trace_id", tid,
				"ms", float64(time.Since(start).Microseconds())/1000)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---------------------------------------------------------------- REST face

type invokeRequest struct {
	Tool           string         `json:"tool"`
	Args           map[string]any `json:"args"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	Customer       map[string]any `json:"customer,omitempty"`
	Approval       map[string]any `json:"approval,omitempty"`
	Budget         map[string]any `json:"budget,omitempty"`
}

func (s *Server) invoke(w http.ResponseWriter, r *http.Request, c authn.Caller) {
	var req invokeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, s.maxBody())).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json: " + err.Error()})
		return
	}
	if req.Tool == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "tool is required"})
		return
	}
	res := s.Pipeline.Invoke(r.Context(), c, req.Tool, req.Args, pipeline.Context{
		TraceID: r.Header.Get("X-Trace-Id"), IdempotencyKey: req.IdempotencyKey,
		Customer: req.Customer, Approval: req.Approval, Budget: req.Budget,
	})
	writeJSON(w, statusFor(res.Status), res)
}

func (s *Server) listTools(w http.ResponseWriter, r *http.Request, c authn.Caller) {
	tools := s.Pipeline.ToolsFor(r.Context(), c)
	out := make([]mcpjson.Tool, 0, len(tools))
	for _, m := range tools {
		out = append(out, mcpjson.Tool{Name: m.Name, Description: m.Description, InputSchema: m.InputSchema})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tools": out})
}

func statusFor(st pipeline.Status) int {
	switch st {
	case pipeline.StatusOK:
		return http.StatusOK
	case pipeline.StatusDenied:
		return http.StatusForbidden
	case pipeline.StatusApprovalRequired:
		return http.StatusAccepted
	case pipeline.StatusInvalid:
		return http.StatusUnprocessableEntity
	case pipeline.StatusUnknownTool:
		return http.StatusNotFound
	case pipeline.StatusRateLimited:
		return http.StatusTooManyRequests
	default:
		return http.StatusBadGateway
	}
}

// ---------------------------------------------------------------- MCP face

func (s *Server) mcp(w http.ResponseWriter, r *http.Request, c authn.Caller) {
	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody()))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, mcpjson.NewError(nil, mcpjson.CodeParse, "read error", nil))
		return
	}
	var req mcpjson.Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, mcpjson.NewError(nil, mcpjson.CodeParse, "parse error", nil))
		return
	}
	if req.ID == nil || string(req.ID) == "null" {
		// Notification (e.g. notifications/initialized): accept, no body.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		writeJSON(w, http.StatusOK, mcpjson.NewResponse(req.ID, map[string]any{
			"protocolVersion": mcpjson.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "valkyrie", "version": "0.1.0"},
			"instructions":    "Every tool call is authorized by policy. A denied call returns an error with the reason; choose another action.",
		}))
	case "ping":
		writeJSON(w, http.StatusOK, mcpjson.NewResponse(req.ID, map[string]any{}))
	case "tools/list":
		tools := s.Pipeline.ToolsFor(r.Context(), c)
		out := mcpjson.ToolsListResult{Tools: []mcpjson.Tool{}}
		for _, m := range tools {
			out.Tools = append(out.Tools, mcpjson.Tool{Name: m.Name, Description: m.Description, InputSchema: m.InputSchema})
		}
		writeJSON(w, http.StatusOK, mcpjson.NewResponse(req.ID, out))
	case "tools/call":
		var p mcpjson.CallToolParams
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			writeJSON(w, http.StatusOK, mcpjson.NewError(req.ID, mcpjson.CodeInvalidParams, "name and arguments required", nil))
			return
		}
		// Context (customer, approval, budget) may ride in _meta for MCP clients.
		var meta struct {
			Meta struct {
				Customer map[string]any `json:"customer"`
				Approval map[string]any `json:"approval"`
				Budget   map[string]any `json:"budget"`
			} `json:"_meta"`
		}
		_ = json.Unmarshal(req.Params, &meta)
		res := s.Pipeline.Invoke(r.Context(), c, p.Name, p.Arguments, pipeline.Context{
			TraceID: r.Header.Get("X-Trace-Id"), Customer: meta.Meta.Customer, Approval: meta.Meta.Approval, Budget: meta.Meta.Budget,
		})
		switch res.Status {
		case pipeline.StatusOK:
			writeJSON(w, http.StatusOK, mcpjson.NewResponse(req.ID, res.Content))
		case pipeline.StatusUnknownTool:
			writeJSON(w, http.StatusOK, mcpjson.NewError(req.ID, mcpjson.CodeMethodNotFound, "unknown tool", res))
		default:
			// Policy denies, approval holds, invalid arguments and upstream
			// failures are tool-level outcomes: the model must see the reason
			// and re-plan, so they are returned as isError results, not as
			// JSON-RPC protocol errors (MCP spec: tool execution errors).
			writeJSON(w, http.StatusOK, mcpjson.NewResponse(req.ID, toolError(res)))
		}
	default:
		writeJSON(w, http.StatusOK, mcpjson.NewError(req.ID, mcpjson.CodeMethodNotFound, "method not supported by gateway: "+req.Method, nil))
	}
}

// toolError renders a non-OK pipeline result as an MCP tool error.
func toolError(res pipeline.Result) mcpjson.CallToolResult {
	var msg string
	switch res.Status {
	case pipeline.StatusDenied:
		msg = "DENIED by policy: " + strings.Join(res.Reason, "; ") + ". Choose a different action."
	case pipeline.StatusApprovalRequired:
		msg = "APPROVAL REQUIRED: a human must approve this action before it can run."
	case pipeline.StatusInvalid:
		msg = "INVALID ARGUMENTS: " + strings.Join(res.Violations, "; ")
	case pipeline.StatusRateLimited:
		msg = "RATE LIMITED: " + strings.Join(res.Reason, "; ") + ". Retry later."
	default:
		msg = "ERROR (" + string(res.Status) + "): " + strings.Join(res.Reason, "; ")
	}
	sc, _ := json.Marshal(map[string]any{"status": res.Status, "reason": res.Reason, "violations": res.Violations,
		"decision_id": res.DecisionID, "policy_version": res.PolicyVersion, "trace_id": res.TraceID})
	return mcpjson.CallToolResult{Content: []mcpjson.Content{{Type: "text", Text: msg}}, StructuredContent: sc, IsError: true}
}

func (s *Server) maxBody() int64 {
	if s.MaxBody > 0 {
		return s.MaxBody
	}
	return 1 << 20
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var _ = errors.New

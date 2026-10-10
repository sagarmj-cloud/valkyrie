// SPDX-License-Identifier: LicenseRef-Valkyrie-Enterprise
// Copyright (c) 2026 Sagar Jadhav

// Package api is registryd's HTTP surface.
//
//	GET    /v1/registry            snapshot for gateways (ETag, 304)
//	GET    /v1/bundle.tar.gz       signed OPA bundle (ETag, 304) — OPA polls this
//	GET    /v1/tools               list manifests (?state=active|deprecated|all)
//	GET    /v1/tools/{name}        one manifest
//	PUT    /v1/tools/{name}        publish (validates + contract-tests; ?skip_contract=1 for offline servers)
//	DELETE /v1/tools/{name}        deprecate
//	GET    /v1/servers · PUT /v1/servers/{name}
//	GET    /v1/roles   · PUT /v1/roles/{name}
//	GET    /v1/changes             change log, newest first
//	GET    /healthz /readyz
//
// Writes require a bearer token (VALKYRIE_REGISTRY_ADMIN_TOKEN); reads
// require the reader token if one is configured. In production both are
// OIDC-verified identities with roles; the shape of the handlers is the same.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"valkyrie/controlplane/internal/bundle"
	"valkyrie/controlplane/internal/contract"
	"valkyrie/controlplane/internal/store"
)

type Server struct {
	Store        *store.Store
	Bundle       *bundle.Builder
	Log          *slog.Logger
	AdminToken   string
	ReaderToken  string
	ContractAuth contract.Auth // credentials registryd presents to servers during contract tests

	mu        sync.Mutex
	cached    bundle.Built
	cachedRev int64
	snapCache []byte
	snapETag  string
	snapRev   int64
}

var toolName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
var serverName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var semver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /v1/registry", s.read(s.registry))
	mux.HandleFunc("GET /v1/bundle.tar.gz", s.read(s.bundleHandler))
	mux.HandleFunc("GET /v1/tools", s.read(s.listTools))
	mux.HandleFunc("GET /v1/tools/{name}", s.read(s.getTool))
	mux.HandleFunc("PUT /v1/tools/{name}", s.admin(s.putTool))
	mux.HandleFunc("DELETE /v1/tools/{name}", s.admin(s.deprecateTool))
	mux.HandleFunc("GET /v1/servers", s.read(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.Store.Servers()) }))
	mux.HandleFunc("PUT /v1/servers/{name}", s.admin(s.putServer))
	mux.HandleFunc("GET /v1/roles", s.read(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.Store.Roles()) }))
	mux.HandleFunc("PUT /v1/roles/{name}", s.admin(s.putRole))
	mux.HandleFunc("GET /v1/changes", s.read(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.Store.Changes(200)) }))
	return s.logging(mux)
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if s.Log != nil && !strings.HasSuffix(r.URL.Path, "z") {
			s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "ms", float64(time.Since(start).Microseconds())/1000)
		}
	})
}

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (s *Server) read(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.ReaderToken != "" && bearer(r) != s.ReaderToken && bearer(r) != s.AdminToken {
			writeJSON(w, 401, map[string]string{"error": "reader token required"})
			return
		}
		h(w, r)
	}
}

func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AdminToken == "" || bearer(r) != s.AdminToken {
			writeJSON(w, 401, map[string]string{"error": "admin token required"})
			return
		}
		h(w, r)
	}
}

func actor(r *http.Request) string {
	if a := r.Header.Get("X-Actor"); a != "" {
		return a
	}
	return "admin"
}

// ---------------------------------------------------------------- gateway + OPA faces

func (s *Server) registry(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.snapCache == nil || s.snapRev != s.Store.Revision() {
		snap := s.Store.Snapshot()
		s.snapCache, _ = json.Marshal(snap)
		s.snapETag = fmt.Sprintf(`"r%d"`, snap.Revision)
		s.snapRev = snap.Revision
	}
	body, etag := s.snapCache, s.snapETag
	s.mu.Unlock()
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (s *Server) bundleHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.cached.Bytes == nil || s.cachedRev != s.Store.Revision() {
		b, err := s.Bundle.Build(s.Store)
		if err != nil {
			s.mu.Unlock()
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		s.cached, s.cachedRev = b, s.Store.Revision()
	}
	b := s.cached
	s.mu.Unlock()
	if r.Header.Get("If-None-Match") == b.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", b.ETag)
	w.Header().Set("Content-Type", "application/gzip")
	w.Write(b.Bytes)
}

// ---------------------------------------------------------------- tools

func (s *Server) listTools(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "active"
	}
	var out []store.Manifest
	for _, m := range s.Store.Tools() {
		if state == "all" || m.State == state {
			out = append(out, m)
		}
	}
	if out == nil {
		out = []store.Manifest{}
	}
	writeJSON(w, 200, map[string]any{"revision": s.Store.Revision(), "tools": out})
}

func (s *Server) getTool(w http.ResponseWriter, r *http.Request) {
	m, ok := s.Store.Tool(r.PathValue("name"))
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, 200, m)
}

func (s *Server) putTool(w http.ResponseWriter, r *http.Request) {
	var m store.Manifest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&m); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json: " + err.Error()})
		return
	}
	m.Name = r.PathValue("name")
	if problems := validate(m); len(problems) > 0 {
		writeJSON(w, 422, map[string]any{"error": "manifest invalid", "problems": problems})
		return
	}
	var ct contract.Result
	if r.URL.Query().Get("skip_contract") != "1" {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		ct = contract.Check(ctx, m, s.Store.Servers(), s.ContractAuth)
		if !ct.OK {
			writeJSON(w, 422, map[string]any{"error": "contract test failed", "contract": ct})
			return
		}
	}
	rev, err := s.Store.PutTool(actor(r), m, r.Header.Get("If-Match-Version"))
	if err != nil {
		code := 500
		if errors.Is(err, store.ErrConflict) {
			code = 409
		} else if errors.Is(err, store.ErrNotFound) {
			code = 422
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"name": m.Name, "version": m.Version, "revision": rev, "contract": ct})
}

func (s *Server) deprecateTool(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.DeprecateTool(actor(r), r.PathValue("name")); err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"name": r.PathValue("name"), "state": "deprecated", "revision": s.Store.Revision()})
}

func (s *Server) putServer(w http.ResponseWriter, r *http.Request) {
	var sv store.Server
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&sv); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	sv.Name = r.PathValue("name")
	if !serverName.MatchString(sv.Name) || (!strings.HasPrefix(sv.URL, "http://") && !strings.HasPrefix(sv.URL, "https://")) {
		writeJSON(w, 422, map[string]string{"error": "name must be [a-z][a-z0-9-]* and url must be http(s)"})
		return
	}
	if err := s.Store.PutServer(actor(r), sv); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"name": sv.Name, "revision": s.Store.Revision()})
}

func (s *Server) putRole(w http.ResponseWriter, r *http.Request) {
	var role store.Role
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&role); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	role.Name = r.PathValue("name")
	if role.MaxTier < 0 || role.MaxTier > 3 {
		writeJSON(w, 422, map[string]string{"error": "max_tier must be 0..3"})
		return
	}
	if err := s.Store.PutRole(actor(r), role); err != nil {
		code := 500
		if errors.Is(err, store.ErrNotFound) {
			code = 422
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"name": role.Name, "revision": s.Store.Revision()})
}

func validate(m store.Manifest) []string {
	var p []string
	if !toolName.MatchString(m.Name) {
		p = append(p, "name must be <server>.<tool> in [a-z0-9_]")
	}
	if m.Owner == "" {
		p = append(p, "owner is required")
	}
	if !serverName.MatchString(m.Server) {
		p = append(p, "server must be [a-z][a-z0-9-]*")
	}
	if !semver.MatchString(m.Version) {
		p = append(p, "version must be semver x.y.z")
	}
	if len(m.Description) < 10 {
		p = append(p, "description must be at least 10 characters")
	}
	if m.RiskTier < 0 || m.RiskTier > 3 {
		p = append(p, "risk_tier must be 0..3")
	}
	switch m.DataClassification {
	case "public", "internal", "confidential", "pii":
	default:
		p = append(p, "data_classification must be public|internal|confidential|pii")
	}
	var sch map[string]any
	if len(m.InputSchema) == 0 || json.Unmarshal(m.InputSchema, &sch) != nil || sch["type"] != "object" {
		p = append(p, "input_schema must be a JSON Schema of type object")
	}
	switch m.Credentials.Type {
	case "", "lease", "vault", "static", "none":
	default:
		p = append(p, "credentials.type must be lease|vault|static|none")
	}
	if m.Credentials.Type == "static" && m.Credentials.SecretRef == "" {
		p = append(p, "credentials.secret_ref is required for static credentials")
	}
	if m.Credentials.Type == "vault" && m.Credentials.VaultRole == "" {
		p = append(p, "credentials.vault_role is required for vault credentials")
	}
	if m.Credentials.TTLSeconds < 30 || m.Credentials.TTLSeconds > 300 {
		p = append(p, "credentials.ttl_seconds must be 30..300")
	}
	if m.Limits.TimeoutMS < 100 || m.Limits.TimeoutMS > 60000 {
		p = append(p, "limits.timeout_ms must be 100..60000")
	}
	if m.Limits.RatePerMinute < 1 {
		p = append(p, "limits.rate_per_minute must be >= 1")
	}
	if m.Limits.MaxResultKB < 1 || m.Limits.MaxResultKB > 4096 {
		p = append(p, "limits.max_result_kb must be 1..4096")
	}
	if m.RiskTier >= 3 && m.Approval == nil {
		p = append(p, "tier 3 tools must declare an approval block")
	}
	if m.Adapter != nil && m.Adapter.Type != "http" {
		p = append(p, "adapter.type must be http")
	}
	return p
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

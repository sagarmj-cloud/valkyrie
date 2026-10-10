// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package registry loads tool manifests and the server map. Manifests are the
// source of truth: a tool that is not here cannot be called.
//
// Manifests are YAML on disk in the repo; to keep the gateway free of
// third-party dependencies they are converted to JSON by `make registry`
// (scripts/build_registry.py) and the gateway loads registry.json.
package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

type Credentials struct {
	Type       string `json:"type,omitempty"` // lease (default) | vault | static | none
	VaultRole  string `json:"vault_role,omitempty"`
	Scope      string `json:"scope"`
	SecretRef  string `json:"secret_ref,omitempty"` // static: env var holding the secret
	Header     string `json:"header,omitempty"`     // how to send it upstream: "Authorization: Bearer" (default) or e.g. "X-API-Key"
	TTLSeconds int    `json:"ttl_seconds"`
}

// Adapter describes a non-MCP tool: a plain HTTP/REST endpoint the gateway
// calls directly. When present, Server is the logical name only; no MCP
// session is opened.
type Adapter struct {
	Type   string            `json:"type"`             // "http"
	Method string            `json:"method"`           // GET | POST | PUT | DELETE
	URL    string            `json:"url"`              // may contain {arg} placeholders, substituted from args
	Query  []string          `json:"query,omitempty"`  // args sent as query parameters
	Body   bool              `json:"body,omitempty"`   // remaining args sent as JSON body
	Header map[string]string `json:"header,omitempty"` // static headers
}

type Limits struct {
	TimeoutMS     int `json:"timeout_ms"`
	RatePerMinute int `json:"rate_per_minute"`
	MaxResultKB   int `json:"max_result_kb"`
}

type Approval struct {
	RequiredAboveUSD float64 `json:"required_above_usd"`
}

type Manifest struct {
	Name               string          `json:"name"`
	Owner              string          `json:"owner"`
	Server             string          `json:"server"`
	Version            string          `json:"version"`
	Description        string          `json:"description"`
	RiskTier           int             `json:"risk_tier"`
	DataClassification string          `json:"data_classification"`
	InputSchema        json.RawMessage `json:"input_schema"`
	OutputSchema       json.RawMessage `json:"output_schema,omitempty"`
	Credentials        Credentials     `json:"credentials"`
	Limits             Limits          `json:"limits"`
	Idempotent         bool            `json:"idempotent"`
	Approval           *Approval       `json:"approval,omitempty"`
	Adapter            *Adapter        `json:"adapter,omitempty"`
	// Upstream (MCP only): the tool name on the upstream server when it
	// differs from the registry name (e.g. registry "everything.add" ->
	// upstream "add"). Namespacing keeps third-party tool names from
	// colliding across servers.
	UpstreamName string `json:"upstream_name,omitempty"`
}

type Server struct {
	URL     string `json:"url"`
	Runtime string `json:"runtime"`
}

type File struct {
	Revision int64             `json:"revision,omitempty"`
	Tools    []Manifest        `json:"tools"`
	Servers  map[string]Server `json:"servers"`
}

// Registry is an in-memory, read-mostly view of the manifests. In production
// it is refreshed from the control plane on a TTL and keeps serving the last
// good copy if the control plane is unreachable (stale-but-valid).
type Registry struct {
	mu       sync.RWMutex
	tools    map[string]Manifest
	servers  map[string]Server
	revision int64
	etag     string
}

func Load(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}
	return FromFile(f)
}

func FromFile(f File) (*Registry, error) {
	r := &Registry{tools: map[string]Manifest{}, servers: f.Servers, revision: f.Revision}
	if r.servers == nil {
		r.servers = map[string]Server{}
	}
	for _, m := range f.Tools {
		if m.Name == "" || m.Server == "" {
			return nil, fmt.Errorf("registry: manifest missing name or server: %+v", m)
		}
		if _, ok := f.Servers[m.Server]; !ok && m.Adapter == nil {
			return nil, fmt.Errorf("registry: tool %s references unknown server %q", m.Name, m.Server)
		}
		if m.Adapter != nil && m.Adapter.Type != "http" {
			return nil, fmt.Errorf("registry: tool %s: unsupported adapter type %q", m.Name, m.Adapter.Type)
		}
		if _, dup := r.tools[m.Name]; dup {
			return nil, fmt.Errorf("registry: duplicate tool %s", m.Name)
		}
		r.tools[m.Name] = m
	}
	return r, nil
}

func (r *Registry) Tool(name string) (Manifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.tools[name]
	return m, ok
}

func (r *Registry) Server(name string) (Server, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.servers[name]
	return s, ok
}

// All returns manifests sorted by name (stable tools/list output).
func (r *Registry) All() []Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Manifest, 0, len(r.tools))
	for _, m := range r.tools {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Replace swaps in a freshly loaded registry atomically (hot reload).
func (r *Registry) Replace(n *Registry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools, r.servers, r.revision, r.etag = n.tools, n.servers, n.revision, n.etag
}

func (r *Registry) Revision() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revision
}

// Servers returns a copy of the server map (used to build upstream clients).
func (r *Registry) Servers() map[string]Server {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]Server, len(r.servers))
	for k, v := range r.servers {
		out[k] = v
	}
	return out
}

// SPDX-License-Identifier: LicenseRef-Valkyrie-Enterprise
// Copyright (c) 2026 Sagar Jadhav

// Package store is registryd's persistence: tool manifests, servers and role
// bindings, each change producing a new monotonic revision and a change-log
// entry. Storage is a single JSON document written atomically (write temp,
// fsync, rename), which is correct for one registryd replica with a
// persistent volume; the Store interface is what a Postgres implementation
// would satisfy for an HA deployment.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

// Manifest mirrors the gateway's registry.Manifest; the control plane owns
// the authoritative shape and the gateway consumes the snapshot.
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
	UpstreamName       string          `json:"upstream_name,omitempty"`
	// Control-plane metadata
	State       string    `json:"state,omitempty"` // active | deprecated
	PublishedAt time.Time `json:"published_at,omitempty"`
	PublishedBy string    `json:"published_by,omitempty"`
}

type Credentials struct {
	Type       string `json:"type,omitempty"`
	VaultRole  string `json:"vault_role,omitempty"`
	Scope      string `json:"scope"`
	SecretRef  string `json:"secret_ref,omitempty"`
	Header     string `json:"header,omitempty"`
	TTLSeconds int    `json:"ttl_seconds"`
}
type Limits struct {
	TimeoutMS     int `json:"timeout_ms"`
	RatePerMinute int `json:"rate_per_minute"`
	MaxResultKB   int `json:"max_result_kb"`
}
type Approval struct {
	RequiredAboveUSD float64 `json:"required_above_usd"`
}
type Adapter struct {
	Type   string            `json:"type"`
	Method string            `json:"method"`
	URL    string            `json:"url"`
	Query  []string          `json:"query,omitempty"`
	Body   bool              `json:"body,omitempty"`
	Header map[string]string `json:"header,omitempty"`
}

type Server struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Runtime string `json:"runtime"`
	Owner   string `json:"owner,omitempty"`
	// Auth the gateway must present to this server when a manifest uses
	// credentials.type=static: the env var holding the key lives on the gateway.
	Notes string `json:"notes,omitempty"`
}

type Role struct {
	Name    string   `json:"name"`
	Tools   []string `json:"tools"`
	MaxTier int      `json:"max_tier"`
	// CanDelegate grants PEP 2: the role may hand tasks to other agents via
	// the gateway's /v1/delegate. Carried into the bundle as roles[<role>].can_delegate.
	CanDelegate bool `json:"can_delegate"`
}

type Change struct {
	Revision int64     `json:"revision"`
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`
	Kind     string    `json:"kind"` // tool | server | role
	Name     string    `json:"name"`
	Action   string    `json:"action"` // publish | deprecate | delete | bind
	Summary  string    `json:"summary"`
}

type State struct {
	Revision int64               `json:"revision"`
	Tools    map[string]Manifest `json:"tools"`
	Servers  map[string]Server   `json:"servers"`
	Roles    map[string]Role     `json:"roles"`
	Changes  []Change            `json:"changes"`
}

// Snapshot is what the gateway downloads: active tools + servers.
type Snapshot struct {
	Revision int64             `json:"revision"`
	Tools    []Manifest        `json:"tools"`
	Servers  map[string]Server `json:"servers"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	st   State
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, st: State{Tools: map[string]Manifest{}, Servers: map[string]Server{}, Roles: map[string]Role{}}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("store: %s: %w", path, err)
	}
	for _, m := range map[string]any{} {
		_ = m
	}
	if s.st.Tools == nil {
		s.st.Tools = map[string]Manifest{}
	}
	if s.st.Servers == nil {
		s.st.Servers = map[string]Server{}
	}
	if s.st.Roles == nil {
		s.st.Roles = map[string]Role{}
	}
	return s, nil
}

func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

func (s *Store) commit(actor, kind, name, action, summary string) error {
	s.st.Revision++
	s.st.Changes = append(s.st.Changes, Change{Revision: s.st.Revision, Time: time.Now().UTC(), Actor: actor, Kind: kind, Name: name, Action: action, Summary: summary})
	if len(s.st.Changes) > 10_000 {
		s.st.Changes = s.st.Changes[len(s.st.Changes)-10_000:]
	}
	return s.persist()
}

// ---------------------------------------------------------------- tools

func (s *Store) PutTool(actor string, m Manifest, ifVersion string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.st.Servers[m.Server]; !ok && m.Adapter == nil {
		return 0, fmt.Errorf("%w: server %q is not registered", ErrNotFound, m.Server)
	}
	prev, exists := s.st.Tools[m.Name]
	if exists && ifVersion != "" && prev.Version != ifVersion {
		return 0, fmt.Errorf("%w: tool %s is at %s, not %s", ErrConflict, m.Name, prev.Version, ifVersion)
	}
	if exists && !versionGreaterOrEqual(m.Version, prev.Version) {
		return 0, fmt.Errorf("%w: version %s must be >= current %s", ErrConflict, m.Version, prev.Version)
	}
	m.State, m.PublishedAt, m.PublishedBy = "active", time.Now().UTC(), actor
	s.st.Tools[m.Name] = m
	action := "publish"
	if exists {
		action = "update"
	}
	if err := s.commit(actor, "tool", m.Name, action, fmt.Sprintf("%s@%s tier=%d owner=%s", m.Name, m.Version, m.RiskTier, m.Owner)); err != nil {
		return 0, err
	}
	return s.st.Revision, nil
}

func (s *Store) DeprecateTool(actor, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.st.Tools[name]
	if !ok {
		return ErrNotFound
	}
	m.State = "deprecated"
	s.st.Tools[name] = m
	return s.commit(actor, "tool", name, "deprecate", name+" deprecated; removed from snapshot")
}

func (s *Store) Tool(name string) (Manifest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.st.Tools[name]
	return m, ok
}

func (s *Store) Tools() []Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Manifest, 0, len(s.st.Tools))
	for _, m := range s.st.Tools {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---------------------------------------------------------------- servers

func (s *Store) PutServer(actor string, sv Server) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Servers[sv.Name] = sv
	return s.commit(actor, "server", sv.Name, "publish", sv.Name+" -> "+sv.URL)
}

func (s *Store) Servers() map[string]Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Server, len(s.st.Servers))
	for k, v := range s.st.Servers {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------- roles

func (s *Store) PutRole(actor string, r Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range r.Tools {
		if _, ok := s.st.Tools[t]; !ok {
			return fmt.Errorf("%w: tool %q is not registered", ErrNotFound, t)
		}
	}
	sort.Strings(r.Tools)
	s.st.Roles[r.Name] = r
	return s.commit(actor, "role", r.Name, "bind", fmt.Sprintf("%s -> %d tools, max_tier=%d, can_delegate=%v", r.Name, len(r.Tools), r.MaxTier, r.CanDelegate))
}

func (s *Store) Roles() map[string]Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Role, len(s.st.Roles))
	for k, v := range s.st.Roles {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------- views

func (s *Store) Revision() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.Revision
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{Revision: s.st.Revision, Servers: map[string]Server{}}
	for _, m := range s.st.Tools {
		if m.State == "active" {
			snap.Tools = append(snap.Tools, m)
		}
	}
	sort.Slice(snap.Tools, func(i, j int) bool { return snap.Tools[i].Name < snap.Tools[j].Name })
	for k, v := range s.st.Servers {
		snap.Servers[k] = v
	}
	return snap
}

func (s *Store) Changes(limit int) []Change {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.st.Changes)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Change, limit)
	copy(out, s.st.Changes[n-limit:])
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func versionGreaterOrEqual(a, b string) bool {
	var a1, a2, a3, b1, b2, b3 int
	fmt.Sscanf(a, "%d.%d.%d", &a1, &a2, &a3)
	fmt.Sscanf(b, "%d.%d.%d", &b1, &b2, &b3)
	if a1 != b1 {
		return a1 > b1
	}
	if a2 != b2 {
		return a2 > b2
	}
	return a3 >= b3
}

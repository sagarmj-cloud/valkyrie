// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package credentials brokers short-lived, scoped credentials for a single
// tool call. The agent never sees them; the gateway attaches them to the
// upstream request and revokes them when the call ends.
//
// Three brokers:
//
//   - SignedBroker: mints HS256 lease tokens {scope, lease_id, exp, iss}
//     signed with a key shared with the MCP servers. Servers verify the
//     signature, scope and expiry (see sdk/python/valkyrie/server.py). This
//     is the default for first-party servers: no network hop, no Vault
//     dependency, cryptographic rather than string-prefix verification.
//   - VaultBroker: leases dynamic credentials from HashiCorp Vault's HTTP API
//     (any secrets engine that exposes /creds/<role>) and revokes the lease
//     when the call ends. For target systems that need real credentials
//     (databases, cloud APIs).
//   - StaticBroker: resolves a secret reference from the environment for
//     third-party MCP servers that only accept a fixed API key. The agent
//     still never sees it; the gateway attaches it per call.
//
// The manifest's credentials.type selects the broker: "lease" (default),
// "vault", "static", or "none".
package credentials

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Lease struct {
	ID        string
	Token     string // attached as Authorization: Bearer (or the scheme the manifest names)
	Scope     string
	ExpiresAt time.Time
}

type Request struct {
	Type      string // lease | vault | static | none
	VaultRole string
	Scope     string
	SecretRef string // static: environment variable name holding the secret
	TTL       time.Duration
}

type Broker interface {
	Lease(ctx context.Context, req Request) (Lease, error)
	Revoke(ctx context.Context, leaseID string) error
}

// ---------------------------------------------------------------- signed lease broker

type SignedBroker struct {
	key    []byte
	issuer string
	mu     sync.Mutex
	active map[string]time.Time
	now    func() time.Time
}

func NewSigned(key []byte, issuer string) *SignedBroker {
	return &SignedBroker{key: key, issuer: issuer, active: map[string]time.Time{}, now: time.Now}
}

func (s *SignedBroker) Lease(_ context.Context, req Request) (Lease, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return Lease{}, err
	}
	id := "lease-" + hex.EncodeToString(b)
	exp := s.now().Add(req.TTL)
	claims := map[string]any{"iss": s.issuer, "scope": req.Scope, "lease_id": id, "iat": s.now().Unix(), "exp": exp.Unix()}
	tok, err := signHS256(s.key, claims)
	if err != nil {
		return Lease{}, err
	}
	s.mu.Lock()
	s.active[id] = exp
	// opportunistic cleanup of expired leases so the map stays bounded
	for k, e := range s.active {
		if s.now().After(e) {
			delete(s.active, k)
		}
	}
	s.mu.Unlock()
	return Lease{ID: id, Token: tok, Scope: req.Scope, ExpiresAt: exp}, nil
}

func (s *SignedBroker) Revoke(_ context.Context, leaseID string) error {
	s.mu.Lock()
	delete(s.active, leaseID)
	s.mu.Unlock()
	return nil
}

func (s *SignedBroker) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active)
}

func signHS256(key []byte, claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hdr)
	p := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// ---------------------------------------------------------------- Vault broker

// VaultBroker speaks Vault's HTTP API. Lease: GET /v1/<mount>/creds/<role>
// returns {lease_id, lease_duration, data:{...}}; the broker picks the
// credential field named by TokenField (default "token"; "password" for
// database engines). Revoke: PUT /v1/sys/leases/revoke {lease_id}.
type VaultBroker struct {
	Addr       string
	Token      string // Vault token for the gateway's own identity (AppRole/K8s auth in prod)
	Mount      string // e.g. "database", "aws", "valkyrie-tools"
	TokenField string
	Namespace  string
	HTTP       *http.Client
}

func NewVault(addr, token, mount string) *VaultBroker {
	return &VaultBroker{Addr: strings.TrimRight(addr, "/"), Token: token, Mount: mount, TokenField: "token",
		HTTP: &http.Client{Timeout: 5 * time.Second}}
}

func (v *VaultBroker) Lease(ctx context.Context, req Request) (Lease, error) {
	u := fmt.Sprintf("%s/v1/%s/creds/%s", v.Addr, v.Mount, req.VaultRole)
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Lease{}, err
	}
	v.headers(r)
	resp, err := v.HTTP.Do(r)
	if err != nil {
		return Lease{}, fmt.Errorf("vault: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Lease{}, fmt.Errorf("vault: creds/%s: http %d", req.VaultRole, resp.StatusCode)
	}
	var out struct {
		LeaseID       string         `json:"lease_id"`
		LeaseDuration int            `json:"lease_duration"`
		Data          map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Lease{}, fmt.Errorf("vault: decode: %w", err)
	}
	tok, _ := out.Data[v.TokenField].(string)
	if tok == "" {
		return Lease{}, fmt.Errorf("vault: creds/%s: no %q field in data", req.VaultRole, v.TokenField)
	}
	ttl := time.Duration(out.LeaseDuration) * time.Second
	if ttl == 0 || ttl > req.TTL {
		ttl = req.TTL
	}
	return Lease{ID: out.LeaseID, Token: tok, Scope: req.Scope, ExpiresAt: time.Now().Add(ttl)}, nil
}

func (v *VaultBroker) Revoke(ctx context.Context, leaseID string) error {
	body, _ := json.Marshal(map[string]string{"lease_id": leaseID})
	r, err := http.NewRequestWithContext(ctx, http.MethodPut, v.Addr+"/v1/sys/leases/revoke", bytes.NewReader(body))
	if err != nil {
		return err
	}
	v.headers(r)
	resp, err := v.HTTP.Do(r)
	if err != nil {
		return fmt.Errorf("vault: revoke: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("vault: revoke: http %d", resp.StatusCode)
	}
	return nil
}

func (v *VaultBroker) headers(r *http.Request) {
	r.Header.Set("X-Vault-Token", v.Token)
	if v.Namespace != "" {
		r.Header.Set("X-Vault-Namespace", v.Namespace)
	}
}

// ---------------------------------------------------------------- static + none

// StaticBroker resolves a secret from an environment variable named by the
// manifest (credentials.secret_ref). The lease id is synthetic; revoke is a
// no-op because the secret is long-lived — which is exactly why this broker
// is only for third-party servers that offer nothing better.
type StaticBroker struct{ Lookup func(string) string }

func NewStatic() *StaticBroker { return &StaticBroker{Lookup: os.Getenv} }

func (s *StaticBroker) Lease(_ context.Context, req Request) (Lease, error) {
	if req.SecretRef == "" {
		return Lease{}, errors.New("static credentials: secret_ref is required")
	}
	v := s.Lookup(req.SecretRef)
	if v == "" {
		return Lease{}, fmt.Errorf("static credentials: %s is not set", req.SecretRef)
	}
	return Lease{ID: "static-" + req.SecretRef, Token: v, Scope: req.Scope, ExpiresAt: time.Now().Add(req.TTL)}, nil
}

func (s *StaticBroker) Revoke(context.Context, string) error { return nil }

// NoneBroker is for servers with no authentication (local dev tools, public
// read-only servers). The audit event still records a lease id.
type NoneBroker struct{}

func (NoneBroker) Lease(_ context.Context, req Request) (Lease, error) {
	return Lease{ID: "none", Scope: req.Scope, ExpiresAt: time.Now().Add(req.TTL)}, nil
}
func (NoneBroker) Revoke(context.Context, string) error { return nil }

// ---------------------------------------------------------------- router

// Router picks a broker by the manifest's credentials.type.
type Router struct {
	Signed, Vault, Static, None Broker
}

func (r Router) Lease(ctx context.Context, req Request) (Lease, error) {
	b, err := r.pick(req.Type)
	if err != nil {
		return Lease{}, err
	}
	return b.Lease(ctx, req)
}

func (r Router) Revoke(ctx context.Context, leaseID string) error {
	switch {
	case strings.HasPrefix(leaseID, "lease-"):
		return r.Signed.Revoke(ctx, leaseID)
	case strings.HasPrefix(leaseID, "static-"), leaseID == "none", leaseID == "":
		return nil
	default:
		if r.Vault == nil {
			return nil
		}
		return r.Vault.Revoke(ctx, leaseID)
	}
}

func (r Router) pick(t string) (Broker, error) {
	switch t {
	case "", "lease":
		return r.Signed, nil
	case "vault":
		if r.Vault == nil {
			return nil, errors.New("credentials: vault broker not configured (VALKYRIE_VAULT_ADDR)")
		}
		return r.Vault, nil
	case "static":
		return r.Static, nil
	case "none":
		return r.None, nil
	}
	return nil, fmt.Errorf("credentials: unknown type %q", t)
}

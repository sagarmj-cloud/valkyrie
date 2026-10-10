// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package credentials

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignedLeaseIsVerifiableAndRevocable(t *testing.T) {
	b := NewSigned([]byte("k"), "valkyrie")
	l, err := b.Lease(context.Background(), Request{Scope: "orders:write", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(l.Token, ".")
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != parts[2] {
		t.Fatal("signature mismatch")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	json.Unmarshal(payload, &c)
	if c["scope"] != "orders:write" || c["lease_id"] != l.ID || c["iss"] != "valkyrie" {
		t.Fatalf("claims: %v", c)
	}
	if b.Active() != 1 {
		t.Fatal("lease should be active")
	}
	b.Revoke(context.Background(), l.ID)
	if b.Active() != 0 {
		t.Fatal("lease should be revoked")
	}
}

func TestVaultBrokerLeaseAndRevoke(t *testing.T) {
	var revoked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "s.root" {
			http.Error(w, "forbidden", 403)
			return
		}
		switch r.URL.Path {
		case "/v1/valkyrie-tools/creds/orders-writer":
			json.NewEncoder(w).Encode(map[string]any{"lease_id": "valkyrie-tools/creds/orders-writer/abc", "lease_duration": 120,
				"data": map[string]any{"token": "vlt-token-1"}})
		case "/v1/sys/leases/revoke":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			revoked = b["lease_id"]
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	v := NewVault(srv.URL, "s.root", "valkyrie-tools")
	l, err := v.Lease(context.Background(), Request{Type: "vault", VaultRole: "orders-writer", Scope: "orders:write", TTL: 5 * time.Minute})
	if err != nil || l.Token != "vlt-token-1" || !strings.HasPrefix(l.ID, "valkyrie-tools/") {
		t.Fatalf("lease: %+v %v", l, err)
	}
	if ttl := time.Until(l.ExpiresAt); ttl > 121*time.Second {
		t.Fatalf("ttl should be capped by vault's lease_duration, got %v", ttl)
	}
	r := Router{Signed: NewSigned([]byte("k"), "v"), Vault: v, Static: NewStatic(), None: NoneBroker{}}
	if err := r.Revoke(context.Background(), l.ID); err != nil || revoked != l.ID {
		t.Fatalf("revoke: %v %q", err, revoked)
	}
}

func TestStaticAndNoneAndRouter(t *testing.T) {
	st := &StaticBroker{Lookup: func(k string) string { return map[string]string{"EVERYTHING_API_KEY": "sk-123"}[k] }}
	r := Router{Signed: NewSigned([]byte("k"), "v"), Static: st, None: NoneBroker{}}
	l, err := r.Lease(context.Background(), Request{Type: "static", SecretRef: "EVERYTHING_API_KEY", TTL: time.Minute})
	if err != nil || l.Token != "sk-123" {
		t.Fatalf("static: %+v %v", l, err)
	}
	if _, err := r.Lease(context.Background(), Request{Type: "static", SecretRef: "MISSING"}); err == nil {
		t.Fatal("missing secret must fail")
	}
	if l, err := r.Lease(context.Background(), Request{Type: "none"}); err != nil || l.Token != "" {
		t.Fatalf("none: %+v %v", l, err)
	}
	if _, err := r.Lease(context.Background(), Request{Type: "vault", VaultRole: "x"}); err == nil {
		t.Fatal("vault not configured must fail closed")
	}
	if _, err := r.Lease(context.Background(), Request{Type: "magic"}); err == nil {
		t.Fatal("unknown type must fail")
	}
}

func TestSignedLeaseCarriesSubjectAndTenant(t *testing.T) {
	b := NewSigned([]byte("k"), "valkyrie")
	l, err := b.Lease(context.Background(), Request{Scope: "orders:write", TTL: time.Minute, Subject: "jane", TenantID: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(l.Token, ".")[1])
	var c map[string]any
	json.Unmarshal(payload, &c)
	if c["sub"] != "jane" || c["tenant_id"] != "acme" {
		t.Fatalf("lease must carry the end user and tenant for downstream authz and audit: %v", c)
	}
}

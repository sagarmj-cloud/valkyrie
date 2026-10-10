// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package authn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func rs256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	p, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestJWKSVerifier(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	fetches := 0
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	defer jwks.Close()

	v := NewJWKS("https://idp.example.com", "valkyrie", jwks.URL)
	base := map[string]any{"iss": "https://idp.example.com", "aud": []string{"valkyrie", "other"}, "sub": "jane",
		"tenant_id": "acme", "agent_id": "ordering-01", "agent_role": "ordering", "exp": time.Now().Add(time.Hour).Unix()}
	req := func(tok string) *http.Request {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}

	c, err := v.Verify(req(rs256(t, key, "k1", base)))
	if err != nil || c.AgentRole != "ordering" || c.TenantID != "acme" {
		t.Fatalf("valid token rejected: %v %+v", err, c)
	}
	if _, err := v.Verify(req(rs256(t, other, "k1", base))); err == nil {
		t.Fatal("wrong key must fail")
	}
	bad := func(mut func(m map[string]any)) {
		m := map[string]any{}
		for k, val := range base {
			m[k] = val
		}
		mut(m)
		if _, err := v.Verify(req(rs256(t, key, "k1", m))); err == nil {
			t.Fatalf("expected rejection for %v", m)
		}
	}
	bad(func(m map[string]any) { m["iss"] = "https://evil" })
	bad(func(m map[string]any) { m["aud"] = "someone-else" })
	bad(func(m map[string]any) { m["exp"] = time.Now().Add(-time.Minute).Unix() })
	bad(func(m map[string]any) { delete(m, "agent_role") })
	// unknown kid: one refresh (clock moved past the refresh floor), then rate-limited
	v.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	before := fetches
	v.Verify(req(rs256(t, key, "k9", base)))
	v.Verify(req(rs256(t, key, "k9", base)))
	if fetches-before != 1 {
		t.Fatalf("expected exactly one JWKS refresh for unknown kid, got %d", fetches-before)
	}
	// chain: HMAC dev token still accepted alongside JWKS
	hm, _ := Sign([]byte("dev"), map[string]any{"sub": "dev", "tenant_id": "acme", "agent_id": "cli", "agent_role": "menu", "exp": time.Now().Add(time.Hour).Unix()})
	ch := Chain{v, HMACVerifier{Secret: []byte("dev")}}
	if c, err := ch.Verify(req(hm)); err != nil || c.AgentRole != "menu" {
		t.Fatalf("chain: %v", err)
	}
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package authn

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDelegatedTokenRoundTripExtendsChain(t *testing.T) {
	iss := Issuer{Key: []byte("delegation-key"), TTL: 10 * time.Minute}
	parent := Caller{AgentID: "concierge-01", AgentRole: "concierge", Subject: "jane", TenantID: "acme", Chain: []string{"root-01"}}
	tok, exp, err := iss.Issue(parent, "menu-01", "menu", "dec-123")
	if err != nil || tok == "" || time.Until(exp) < 9*time.Minute {
		t.Fatalf("issue: %v tok=%q exp=%v", err, tok, exp)
	}
	r := httptest.NewRequest("POST", "/v1/tools/invoke", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c, err := iss.Verify(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.AgentID != "menu-01" || c.AgentRole != "menu" || c.Subject != "jane" || c.TenantID != "acme" {
		t.Fatalf("identity: %+v", c)
	}
	if len(c.Chain) != 2 || c.Chain[0] != "root-01" || c.Chain[1] != "concierge-01" {
		t.Fatalf("chain must be the parent's chain plus the parent: %v", c.Chain)
	}
}

func TestDelegatedTokenRejectsTamperingAndForeignIssuer(t *testing.T) {
	iss := Issuer{Key: []byte("delegation-key"), TTL: time.Minute}
	parent := Caller{AgentID: "c", AgentRole: "concierge", Subject: "jane", TenantID: "acme"}
	tok, _, _ := iss.Issue(parent, "m", "menu", "d")
	r := httptest.NewRequest("POST", "/", nil)

	// tampered payload (chain shortened) fails the signature
	parts := strings.Split(tok, ".")
	r.Header.Set("Authorization", "Bearer "+parts[0]+"."+parts[1]+"x."+parts[2])
	if _, err := iss.Verify(r); err == nil {
		t.Fatal("tampered token accepted")
	}
	// a dev-secret HMAC token with the same shape is not a delegated token: issuer differs
	dev, _ := Sign([]byte("delegation-key"), map[string]any{"sub": "jane", "tenant_id": "acme", "agent_id": "m", "agent_role": "menu",
		"chain": []string{"forged"}, "exp": time.Now().Add(time.Hour).Unix()})
	r.Header.Set("Authorization", "Bearer "+dev)
	if _, err := iss.Verify(r); err == nil {
		t.Fatal("token without the gateway issuer claim accepted")
	}
	// and the dev HMAC verifier must not accept a delegated token either (separate trust domains)
	r.Header.Set("Authorization", "Bearer "+tok)
	if _, err := (HMACVerifier{Secret: []byte("delegation-key")}).Verify(r); err == nil {
		t.Fatal("HMAC verifier accepted a gateway-issued delegated token")
	}
}

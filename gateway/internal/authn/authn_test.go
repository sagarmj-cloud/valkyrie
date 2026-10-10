// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package authn

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestHMACRoundTrip(t *testing.T) {
	secret := []byte("s3cret")
	tok, err := Sign(secret, map[string]any{"sub": "jane", "tenant_id": "acme", "agent_id": "ordering-01", "agent_role": "ordering", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/tools/invoke", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c, err := HMACVerifier{Secret: secret}.Verify(r)
	if err != nil || c.AgentRole != "ordering" || c.TenantID != "acme" {
		t.Fatalf("verify: %v %+v", err, c)
	}
	// wrong secret
	if _, err := (HMACVerifier{Secret: []byte("other")}).Verify(r); err == nil {
		t.Fatal("expected signature failure")
	}
	// expired
	exp, _ := Sign(secret, map[string]any{"sub": "jane", "tenant_id": "acme", "agent_id": "a", "agent_role": "r", "exp": time.Now().Add(-time.Minute).Unix()})
	r.Header.Set("Authorization", "Bearer "+exp)
	if _, err := (HMACVerifier{Secret: secret}).Verify(r); err == nil {
		t.Fatal("expected expiry failure")
	}
}

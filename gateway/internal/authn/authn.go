// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package authn establishes who is calling: which agent (service identity)
// and on whose behalf (end-user context).
//
// Production: the agent identity comes from the mTLS peer certificate (SPIFFE
// ID) and the end-user context from an OIDC-issued JWT verified against the
// IdP's JWKS. This package keeps the interface and ships two verifiers:
//
//   - HMACVerifier: HS256 JWTs signed with a shared secret (dev / CI).
//   - the mTLS path is a TODO hook (see PeerIdentity) so the pipeline is
//     unchanged when it lands.
package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Caller is the authenticated context attached to every tool call.
type Caller struct {
	AgentID   string   `json:"agent_id"`
	AgentRole string   `json:"agent_role"`
	Subject   string   `json:"sub"`
	TenantID  string   `json:"tenant_id"`
	Chain     []string `json:"chain,omitempty"`
}

type Verifier interface {
	Verify(r *http.Request) (Caller, error)
}

var ErrUnauthenticated = errors.New("unauthenticated")

// HMACVerifier verifies HS256 JWTs. Claims used: sub, tenant_id, agent_id,
// agent_role, chain, exp.
type HMACVerifier struct {
	Secret []byte
	Now    func() time.Time
}

func (h HMACVerifier) Verify(r *http.Request) (Caller, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return Caller{}, fmt.Errorf("%w: missing bearer token", ErrUnauthenticated)
	}
	parts := strings.Split(strings.TrimPrefix(auth, "Bearer "), ".")
	if len(parts) != 3 {
		return Caller{}, fmt.Errorf("%w: malformed token", ErrUnauthenticated)
	}
	mac := hmac.New(sha256.New, h.Secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return Caller{}, fmt.Errorf("%w: bad signature", ErrUnauthenticated)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Caller{}, fmt.Errorf("%w: bad payload", ErrUnauthenticated)
	}
	var claims struct {
		Sub       string   `json:"sub"`
		TenantID  string   `json:"tenant_id"`
		AgentID   string   `json:"agent_id"`
		AgentRole string   `json:"agent_role"`
		Chain     []string `json:"chain"`
		Exp       int64    `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Caller{}, fmt.Errorf("%w: bad claims", ErrUnauthenticated)
	}
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	if claims.Exp != 0 && now().Unix() > claims.Exp {
		return Caller{}, fmt.Errorf("%w: token expired", ErrUnauthenticated)
	}
	if claims.Sub == "" || claims.TenantID == "" || claims.AgentID == "" || claims.AgentRole == "" {
		return Caller{}, fmt.Errorf("%w: missing required claims", ErrUnauthenticated)
	}
	return Caller{AgentID: claims.AgentID, AgentRole: claims.AgentRole, Subject: claims.Sub, TenantID: claims.TenantID, Chain: claims.Chain}, nil
}

// Sign mints an HS256 token. Used by the dev SDK and tests only.
func Sign(secret []byte, claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hdr)
	p := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

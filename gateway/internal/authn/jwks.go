// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package authn

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKSVerifier verifies RS256 JWTs issued by an OIDC provider (Okta, Entra
// ID, Auth0, Keycloak…). Keys are fetched from the JWKS URL, cached, and
// refreshed on an unknown kid (bounded to once per minute so a flood of bad
// tokens cannot hammer the IdP).
//
// Expected claims: iss (must equal Issuer), aud (must contain Audience),
// exp, sub, plus the Valkyrie claims tenant_id, agent_id, agent_role and
// optional chain. In production the agent claims come from the agent
// service's own token-exchange step (on-behalf-of), not from the end user.
type JWKSVerifier struct {
	Issuer   string
	Audience string
	JWKSURL  string
	HTTP     *http.Client
	Now      func() time.Time

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	lastRefresh time.Time
}

func NewJWKS(issuer, audience, jwksURL string) *JWKSVerifier {
	return &JWKSVerifier{Issuer: issuer, Audience: audience, JWKSURL: jwksURL, HTTP: &http.Client{Timeout: 5 * time.Second},
		Now: time.Now, keys: map[string]*rsa.PublicKey{}}
}

func (j *JWKSVerifier) Verify(r *http.Request) (Caller, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return Caller{}, fmt.Errorf("%w: missing bearer token", ErrUnauthenticated)
	}
	return j.VerifyToken(r.Context(), strings.TrimPrefix(auth, "Bearer "))
}

func (j *JWKSVerifier) VerifyToken(ctx context.Context, tok string) (Caller, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Caller{}, fmt.Errorf("%w: malformed token", ErrUnauthenticated)
	}
	hdrB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Caller{}, fmt.Errorf("%w: bad header", ErrUnauthenticated)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hdrB, &hdr) != nil || hdr.Alg != "RS256" {
		return Caller{}, fmt.Errorf("%w: unsupported alg", ErrUnauthenticated)
	}
	key, err := j.key(ctx, hdr.Kid)
	if err != nil {
		return Caller{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Caller{}, fmt.Errorf("%w: bad signature encoding", ErrUnauthenticated)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return Caller{}, fmt.Errorf("%w: bad signature", ErrUnauthenticated)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Caller{}, fmt.Errorf("%w: bad payload", ErrUnauthenticated)
	}
	var c struct {
		Iss       string   `json:"iss"`
		Aud       audience `json:"aud"`
		Exp       int64    `json:"exp"`
		Nbf       int64    `json:"nbf"`
		Sub       string   `json:"sub"`
		TenantID  string   `json:"tenant_id"`
		AgentID   string   `json:"agent_id"`
		AgentRole string   `json:"agent_role"`
		Chain     []string `json:"chain"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return Caller{}, fmt.Errorf("%w: bad claims", ErrUnauthenticated)
	}
	now := j.Now().Unix()
	switch {
	case c.Iss != j.Issuer:
		return Caller{}, fmt.Errorf("%w: wrong issuer", ErrUnauthenticated)
	case j.Audience != "" && !c.Aud.contains(j.Audience):
		return Caller{}, fmt.Errorf("%w: wrong audience", ErrUnauthenticated)
	case c.Exp == 0 || now > c.Exp:
		return Caller{}, fmt.Errorf("%w: token expired", ErrUnauthenticated)
	case c.Nbf != 0 && now < c.Nbf-30:
		return Caller{}, fmt.Errorf("%w: token not yet valid", ErrUnauthenticated)
	case c.Sub == "" || c.TenantID == "" || c.AgentID == "" || c.AgentRole == "":
		return Caller{}, fmt.Errorf("%w: missing required claims", ErrUnauthenticated)
	}
	return Caller{AgentID: c.AgentID, AgentRole: c.AgentRole, Subject: c.Sub, TenantID: c.TenantID, Chain: c.Chain}, nil
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

func (a audience) contains(s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

func (j *JWKSVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	j.mu.RLock()
	k, ok := j.keys[kid]
	last := j.lastRefresh
	j.mu.RUnlock()
	if ok {
		return k, nil
	}
	if j.Now().Sub(last) < time.Minute && len(j.keys) > 0 {
		return nil, errors.New("unknown key id")
	}
	if err := j.Refresh(ctx); err != nil {
		return nil, err
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	if k, ok := j.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown key id")
}

// Refresh fetches the JWKS document. Called at startup and on unknown kid.
func (j *JWKSVerifier) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := j.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: http %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty, Kid, Use, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks: decode: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	}
	if len(keys) == 0 {
		return errors.New("jwks: no RSA signing keys")
	}
	j.mu.Lock()
	j.keys, j.lastRefresh = keys, j.Now()
	j.mu.Unlock()
	return nil
}

// Chain tries verifiers in order; the first success wins. Used to run the
// dev HMAC verifier alongside the production JWKS verifier during migration.
type Chain []Verifier

func (c Chain) Verify(r *http.Request) (Caller, error) {
	var last error
	for _, v := range c {
		caller, err := v.Verify(r)
		if err == nil {
			return caller, nil
		}
		last = err
	}
	if last == nil {
		last = ErrUnauthenticated
	}
	return Caller{}, last
}

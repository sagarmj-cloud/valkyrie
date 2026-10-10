// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package authn

import (
	"fmt"
	"net/http"
	"time"
)

// DelegatedIssuer is the iss claim of tokens the gateway mints for a
// specialist after an allowed handoff (PEP 2). They live in their own trust
// domain: a separate key, and neither the dev HMAC verifier nor the OIDC
// verifier will accept them, nor will this verifier accept theirs.
const DelegatedIssuer = "valkyrie-gateway"

// Issuer mints and verifies delegated tokens. The chain in a delegated token
// is the parent's chain plus the parent, so every hop is attested by the
// gateway's verdict rather than asserted by the agent service.
type Issuer struct {
	Key []byte
	TTL time.Duration
	Now func() time.Time
}

func (i *Issuer) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// Issue mints a token for target acting for the parent's end user.
func (i *Issuer) Issue(parent Caller, targetID, targetRole, decisionID string) (string, time.Time, error) {
	if targetID == "" || targetRole == "" {
		return "", time.Time{}, fmt.Errorf("delegated token: target id and role are required")
	}
	ttl := i.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	now := i.now()
	exp := now.Add(ttl)
	chain := make([]string, 0, len(parent.Chain)+1)
	chain = append(chain, parent.Chain...)
	chain = append(chain, parent.AgentID)
	tok, err := Sign(i.Key, map[string]any{
		"iss": DelegatedIssuer, "sub": parent.Subject, "tenant_id": parent.TenantID,
		"agent_id": targetID, "agent_role": targetRole, "chain": chain,
		"delegated_by": parent.AgentID, "decision_id": decisionID,
		"iat": now.Unix(), "exp": exp.Unix(),
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, exp, nil
}

// Verify accepts only tokens this gateway issued.
func (i *Issuer) Verify(r *http.Request) (Caller, error) {
	c, iss, err := verifyHS256(i.Key, r, i.now)
	if err != nil {
		return Caller{}, err
	}
	if iss != DelegatedIssuer {
		return Caller{}, fmt.Errorf("%w: not a delegated token", ErrUnauthenticated)
	}
	return c, nil
}

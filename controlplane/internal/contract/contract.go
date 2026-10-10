// SPDX-License-Identifier: LicenseRef-Valkyrie-Enterprise
// Copyright (c) 2026 Sagar Jadhav

// Package contract runs the publish-time contract test: before a manifest
// is accepted, registryd connects to the server it names and checks that the
// tool exists, that its advertised input schema is compatible with the
// manifest's, and (for HTTP adapters) that the URL resolves. A manifest that
// fails is rejected with the reason; nothing half-registered ever reaches the
// gateway.
package contract

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"valkyrie/controlplane/internal/mcpdiscover"
	"valkyrie/controlplane/internal/store"
)

type Result struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems,omitempty"`
	Checked  []string `json:"checked"`
}

// Auth is how the contract tester authenticates to a server, mirroring the
// gateway's credential brokers: a signed lease for first-party servers, a
// static secret from the environment for third-party ones, nothing for open
// servers. The control plane holds the lease key because it is as trusted as
// the gateway; a compromised registryd could publish anything anyway.
type Auth struct {
	LeaseKey []byte
	Lookup   func(string) string
}

func (a Auth) tokenFor(m store.Manifest) string {
	switch m.Credentials.Type {
	case "", "lease":
		if len(a.LeaseKey) == 0 {
			return ""
		}
		tok, _ := signHS256(a.LeaseKey, map[string]any{"iss": "valkyrie", "scope": m.Credentials.Scope, "lease_id": "contract-test",
			"iat": time.Now().Unix(), "exp": time.Now().Add(60 * time.Second).Unix()})
		return tok
	case "static":
		if a.Lookup != nil {
			return a.Lookup(m.Credentials.SecretRef)
		}
	}
	return ""
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

func Check(ctx context.Context, m store.Manifest, servers map[string]store.Server, auth Auth) Result {
	r := Result{OK: true}
	fail := func(f string, a ...any) { r.OK = false; r.Problems = append(r.Problems, fmt.Sprintf(f, a...)) }

	if m.Adapter != nil {
		u, err := url.Parse(m.Adapter.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			fail("adapter url %q is not an absolute http(s) URL", m.Adapter.URL)
		}
		r.Checked = append(r.Checked, "adapter url")
		var in struct {
			Properties map[string]any `json:"properties"`
		}
		_ = json.Unmarshal(m.InputSchema, &in)
		for _, ph := range placeholders(m.Adapter.URL) {
			if _, ok := in.Properties[ph]; !ok {
				fail("url placeholder {%s} is not an input_schema property", ph)
			}
		}
		r.Checked = append(r.Checked, "url placeholders match schema")
		return r
	}

	srv, ok := servers[m.Server]
	if !ok {
		fail("server %q is not registered", m.Server)
		return r
	}
	tools, err := mcpdiscover.ListTools(ctx, srv.URL, auth.tokenFor(m), m.Credentials.Header)
	if err != nil {
		fail("server %s unreachable or not MCP: %v", m.Server, err)
		return r
	}
	r.Checked = append(r.Checked, "server reachable (initialize + tools/list)")
	want := m.UpstreamName
	if want == "" {
		want = m.Name
	}
	var found *mcpdiscover.Tool
	for i := range tools {
		if tools[i].Name == want {
			found = &tools[i]
		}
	}
	if found == nil {
		names := make([]string, 0, len(tools))
		for _, t := range tools {
			names = append(names, t.Name)
		}
		fail("server %s does not expose tool %q (has: %s)", m.Server, want, strings.Join(names, ", "))
		return r
	}
	r.Checked = append(r.Checked, "tool exists on server")
	// Schema compatibility: every required property in the server's schema
	// must be a property in the manifest's schema (the manifest may be stricter).
	var srvSchema, manSchema struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
	}
	_ = json.Unmarshal(found.InputSchema, &srvSchema)
	_ = json.Unmarshal(m.InputSchema, &manSchema)
	for _, req := range srvSchema.Required {
		if _, ok := manSchema.Properties[req]; !ok {
			fail("server requires argument %q which the manifest's input_schema does not declare", req)
		}
	}
	for p := range manSchema.Properties {
		if _, ok := srvSchema.Properties[p]; !ok && len(srvSchema.Properties) > 0 {
			fail("manifest declares argument %q which the server does not accept", p)
		}
	}
	r.Checked = append(r.Checked, "input schema compatible")
	return r
}

func placeholders(u string) []string {
	var out []string
	for {
		i := strings.Index(u, "{")
		if i < 0 {
			return out
		}
		j := strings.Index(u[i:], "}")
		if j < 0 {
			return out
		}
		out = append(out, u[i+1:i+j])
		u = u[i+j+1:]
	}
}

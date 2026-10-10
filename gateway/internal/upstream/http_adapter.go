// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"valkyrie/gateway/internal/mcpjson"
	"valkyrie/gateway/internal/registry"
)

// HTTPAdapter turns a plain REST endpoint into a tool. The manifest's
// adapter block says how arguments map to the request:
//
//	adapter:
//	  type: http
//	  method: GET
//	  url: http://weather.internal/v1/forecast/{city}   # {city} taken from args
//	  query: [units]                                     # args sent as ?units=
//	  body: false                                        # remaining args as JSON body (POST/PUT)
//
// The credential (if any) is attached per the manifest's credentials.header.
// The response body is returned as a text content block (JSON passes
// through untouched, so PEP 4 redaction still applies).
type HTTPAdapter struct {
	HTTP        *http.Client
	MaxResult   int64
	SSRFAllowed func(host string) bool // production: allow-list of hosts/CIDRs
}

func NewHTTPAdapter() *HTTPAdapter {
	return &HTTPAdapter{HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // never follow redirects out of the allow-list
	}}, MaxResult: 4 << 20}
}

func (a *HTTPAdapter) Call(ctx context.Context, m registry.Manifest, cred Credential, args map[string]any) (mcpjson.CallToolResult, error) {
	ad := m.Adapter
	used := map[string]bool{}
	u := ad.URL
	for k, v := range args {
		ph := "{" + k + "}"
		if strings.Contains(u, ph) {
			u = strings.ReplaceAll(u, ph, url.PathEscape(fmt.Sprint(v)))
			used[k] = true
		}
	}
	if strings.Contains(u, "{") {
		return mcpjson.CallToolResult{}, fmt.Errorf("adapter: unresolved placeholder in %s", u)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return mcpjson.CallToolResult{}, fmt.Errorf("adapter: bad url: %w", err)
	}
	if a.SSRFAllowed != nil && !a.SSRFAllowed(parsed.Hostname()) {
		return mcpjson.CallToolResult{}, fmt.Errorf("adapter: host %s not in allow-list", parsed.Hostname())
	}
	q := parsed.Query()
	for _, k := range ad.Query {
		if v, ok := args[k]; ok {
			q.Set(k, fmt.Sprint(v))
			used[k] = true
		}
	}
	parsed.RawQuery = q.Encode()
	var body io.Reader
	if ad.Body {
		rest := map[string]any{}
		for k, v := range args {
			if !used[k] {
				rest[k] = v
			}
		}
		b, _ := json.Marshal(rest)
		body = bytes.NewReader(b)
	}
	method := ad.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), body)
	if err != nil {
		return mcpjson.CallToolResult{}, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range ad.Header {
		req.Header.Set(k, v)
	}
	cred.Apply(req)
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return mcpjson.CallToolResult{}, fmt.Errorf("adapter %s: %w", m.Server, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, a.MaxResult))
	if err != nil {
		return mcpjson.CallToolResult{}, err
	}
	out := mcpjson.CallToolResult{Content: []mcpjson.Content{{Type: "text", Text: string(b)}}}
	if resp.StatusCode/100 != 2 {
		out.IsError = true
		out.Content[0].Text = fmt.Sprintf("upstream http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
		return out, nil
	}
	if json.Valid(b) && bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		out.StructuredContent = json.RawMessage(b)
	}
	return out, nil
}

// Credential is how a leased token is attached to an upstream request.
// Scheme is "Authorization: Bearer" (default) or a header name such as
// "X-API-Key".
type Credential struct {
	Token  string
	Scheme string
}

func (c Credential) Apply(req *http.Request) {
	if c.Token == "" {
		return
	}
	switch {
	case c.Scheme == "" || strings.EqualFold(c.Scheme, "Authorization: Bearer"):
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case strings.Contains(c.Scheme, ":"):
		parts := strings.SplitN(c.Scheme, ":", 2)
		req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])+" "+c.Token)
	default:
		req.Header.Set(c.Scheme, c.Token)
	}
}

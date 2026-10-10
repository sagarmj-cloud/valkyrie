// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package pipeline is the seven-step path every tool call takes:
//
//  1. authenticate (done by the API layer; the Caller arrives here)
//  2. resolve the tool from the registry; enforce the per-tenant rate limit
//  3. validate arguments against the manifest schema
//  4. ask OPA (PEP 3) and enforce: deny / approval_required / allow + obligations
//  5. lease a credential (signed lease, Vault, static secret, or none)
//  6. execute upstream — MCP server or HTTP adapter — with a deadline from the manifest
//  7. post-process (PEP 4: redaction, size limit), audit, metrics, revoke the lease
//
// It is transport-agnostic: both /v1/tools/invoke and /mcp call Invoke.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"valkyrie/gateway/internal/audit"
	"valkyrie/gateway/internal/authn"
	"valkyrie/gateway/internal/credentials"
	"valkyrie/gateway/internal/mcpjson"
	"valkyrie/gateway/internal/metrics"
	"valkyrie/gateway/internal/policy"
	"valkyrie/gateway/internal/ratelimit"
	"valkyrie/gateway/internal/registry"
	"valkyrie/gateway/internal/schema"
	"valkyrie/gateway/internal/store"
	"valkyrie/gateway/internal/upstream"
)

type Status string

const (
	StatusOK               Status = "ok"
	StatusDenied           Status = "denied"
	StatusApprovalRequired Status = "approval_required"
	StatusInvalid          Status = "invalid_arguments"
	StatusUnknownTool      Status = "unknown_tool"
	StatusRateLimited      Status = "rate_limited"
	StatusUpstreamError    Status = "upstream_error"
)

// Context carries per-call facts the policy needs beyond the caller identity.
type Context struct {
	TraceID        string
	IdempotencyKey string
	Customer       map[string]any
	Approval       map[string]any
	Budget         map[string]any
}

type Result struct {
	Status        Status                 `json:"status"`
	Reason        []string               `json:"reason,omitempty"`
	Violations    []string               `json:"violations,omitempty"`
	Content       mcpjson.CallToolResult `json:"content,omitempty"`
	Redacted      []string               `json:"redacted,omitempty"`
	DecisionID    string                 `json:"decision_id,omitempty"`
	PolicyVersion string                 `json:"policy_version,omitempty"`
	TraceID       string                 `json:"trace_id"`
	Replayed      bool                   `json:"replayed,omitempty"`
}

// Executor is an MCP upstream (one per server).
type Executor interface {
	CallTool(ctx context.Context, cred upstream.Credential, name string, args map[string]any) (mcpjson.CallToolResult, error)
}

// Adapter executes non-MCP tools described by a manifest adapter block.
type Adapter interface {
	Call(ctx context.Context, m registry.Manifest, cred upstream.Credential, args map[string]any) (mcpjson.CallToolResult, error)
}

type Pipeline struct {
	Registry *registry.Registry
	PDP      policy.PDP
	Broker   credentials.Broker
	Audit    audit.Sink
	Store    store.Store
	Limiter  *ratelimit.Limiter
	Metrics  *metrics.Registry
	Adapter  Adapter
	Log      *slog.Logger
	// Issuer mints the specialist's token after an allowed handoff (PEP 2).
	// nil disables issuance: Delegate still gives a verdict, without a token.
	Issuer *authn.Issuer

	// Upstreams maps server name -> executor. UpstreamFactory builds one on
	// first use for servers that appear after startup (registry refresh).
	upMu            sync.RWMutex
	Upstreams       map[string]Executor
	UpstreamFactory func(name string, s registry.Server) Executor

	schemas sync.Map // tool@version -> *schema.Schema
}

type Options struct {
	Registry *registry.Registry
	PDP      policy.PDP
	Broker   credentials.Broker
	Audit    audit.Sink
	Store    store.Store
	Metrics  *metrics.Registry
	Adapter  Adapter
	Log      *slog.Logger
	Issuer   *authn.Issuer
	Factory  func(name string, s registry.Server) Executor
}

func New(o Options) *Pipeline {
	if o.Store == nil {
		o.Store = store.NewMemory(0)
	}
	if o.Metrics == nil {
		o.Metrics = metrics.New()
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Adapter == nil {
		o.Adapter = upstream.NewHTTPAdapter()
	}
	return &Pipeline{Registry: o.Registry, PDP: o.PDP, Broker: o.Broker, Audit: o.Audit, Store: o.Store,
		Limiter: ratelimit.New(o.Store), Metrics: o.Metrics, Adapter: o.Adapter, Log: o.Log, Issuer: o.Issuer,
		Upstreams: map[string]Executor{}, UpstreamFactory: o.Factory}
}

// SetUpstream registers an executor for a server name (tests, startup).
func (p *Pipeline) SetUpstream(name string, e Executor) {
	p.upMu.Lock()
	defer p.upMu.Unlock()
	p.Upstreams[name] = e
}

func (p *Pipeline) upstreamFor(name string) (Executor, bool) {
	p.upMu.RLock()
	e, ok := p.Upstreams[name]
	p.upMu.RUnlock()
	if ok {
		return e, true
	}
	srv, ok := p.Registry.Server(name)
	if !ok || p.UpstreamFactory == nil {
		return nil, false
	}
	p.upMu.Lock()
	defer p.upMu.Unlock()
	if e, ok := p.Upstreams[name]; ok {
		return e, true
	}
	e = p.UpstreamFactory(name, srv)
	p.Upstreams[name] = e
	return e, true
}

// ToolsFor lists the tools visible to a caller: those bound to its role.
func (p *Pipeline) ToolsFor(ctx context.Context, caller authn.Caller) []registry.Manifest {
	var out []registry.Manifest
	for _, m := range p.Registry.All() {
		d, err := p.PDP.Decide(ctx, "valkyrie/tool_authz/decision", p.policyInput(caller, m, map[string]any{}, Context{}))
		if err != nil {
			continue
		}
		if !contains(d.DenyReason, "tool_not_bound_to_role") && !contains(d.DenyReason, "risk_tier_exceeds_role") {
			out = append(out, m)
		}
	}
	return out
}

func (p *Pipeline) Invoke(ctx context.Context, caller authn.Caller, tool string, args map[string]any, cc Context) (res Result) {
	start := time.Now()
	res = Result{TraceID: cc.TraceID}
	ev := audit.Event{Time: start, TraceID: cc.TraceID, Tenant: caller.TenantID, Subject: caller.Subject,
		AgentID: caller.AgentID, AgentRole: caller.AgentRole, Tool: tool, ArgsHash: audit.HashArgs(args)}
	p.Metrics.InFlight.Add(1)
	defer func() {
		if r := recover(); r != nil {
			// A bug in one call must never take the replica down or leak a lease.
			p.Log.Error("pipeline panic", "tool", tool, "trace_id", cc.TraceID, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			res = Result{Status: StatusUpstreamError, Reason: []string{"internal error"}, TraceID: cc.TraceID}
			ev.Error = "panic"
		}
		p.Metrics.InFlight.Add(-1)
		ms := float64(time.Since(start).Microseconds()) / 1000
		ev.LatencyMS, ev.Outcome = ms, string(res.Status)
		if !res.Replayed {
			p.Metrics.Observe(tool, string(res.Status), ms, res.Reason)
			if p.Audit != nil {
				p.Audit.Emit(ev)
			}
		}
	}()

	// Idempotent replay: same tenant + key -> same result, no second execution.
	idemKey := ""
	if cc.IdempotencyKey != "" {
		idemKey = "idem:" + caller.TenantID + ":" + cc.IdempotencyKey
		if b, err := p.Store.Get(ctx, idemKey); err == nil {
			var cached Result
			if json.Unmarshal(b, &cached) == nil {
				cached.Replayed, cached.TraceID = true, cc.TraceID
				return cached
			}
		}
	}

	// 2. resolve + rate limit
	m, ok := p.Registry.Tool(tool)
	if !ok {
		res.Status, res.Reason = StatusUnknownTool, []string{"tool is not registered"}
		return res
	}
	ev.ToolVersion = m.Version
	if allowed, n, err := p.Limiter.Allow(ctx, caller.TenantID, m.Name, m.Limits.RatePerMinute); err != nil {
		p.Log.Warn("rate limiter store error; allowing", "err", err)
	} else if !allowed {
		res.Status = StatusRateLimited
		res.Reason = []string{fmt.Sprintf("rate limit %d/min exceeded for tenant (%d this minute)", m.Limits.RatePerMinute, n)}
		return res
	}

	// 3. validate
	sc, err := p.schemaFor(m)
	if err != nil {
		res.Status, res.Reason = StatusUpstreamError, []string{"manifest schema invalid: " + err.Error()}
		return res
	}
	args = normalize(args)
	if v := sc.Validate(args); len(v) > 0 {
		res.Status, res.Violations = StatusInvalid, v
		return res
	}

	// 4. policy (PEP 3) — fail closed
	d, err := p.PDP.Decide(ctx, "valkyrie/tool_authz/decision", p.policyInput(caller, m, args, cc))
	if err != nil {
		res.Status, res.Reason, ev.Error = StatusDenied, []string{"policy_unavailable"}, err.Error()
		return res
	}
	res.DecisionID, res.PolicyVersion = d.DecisionID, d.PolicyVersion
	ev.DecisionID, ev.PolicyVersion, ev.DenyReason = d.DecisionID, d.PolicyVersion, d.DenyReason
	if !d.Allow {
		if d.ApprovalRequired() && len(d.DenyReason) == 1 {
			res.Status = StatusApprovalRequired
		} else {
			res.Status = StatusDenied
		}
		res.Reason = d.DenyReason
		return res
	}

	// 5. credential
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(m.Limits.TimeoutMS)*time.Millisecond)
	defer cancel()
	lease, err := p.Broker.Lease(callCtx, credentials.Request{Type: m.Credentials.Type, VaultRole: m.Credentials.VaultRole,
		Scope: m.Credentials.Scope, SecretRef: m.Credentials.SecretRef, TTL: time.Duration(m.Credentials.TTLSeconds) * time.Second,
		Subject: caller.Subject, TenantID: caller.TenantID})
	if err != nil {
		res.Status, res.Reason, ev.Error = StatusUpstreamError, []string{"credential_broker: " + err.Error()}, err.Error()
		return res
	}
	ev.LeaseID = lease.ID
	defer func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer rcancel()
		if err := p.Broker.Revoke(rctx, lease.ID); err != nil {
			p.Log.Warn("lease revoke failed", "lease", lease.ID, "err", err)
		}
	}()
	cred := upstream.Credential{Token: lease.Token, Scheme: m.Credentials.Header}

	// 6. execute
	var out mcpjson.CallToolResult
	if m.Adapter != nil {
		out, err = p.Adapter.Call(callCtx, m, cred, args)
	} else {
		ex, ok := p.upstreamFor(m.Server)
		if !ok {
			res.Status, res.Reason = StatusUpstreamError, []string{"no upstream for server " + m.Server}
			return res
		}
		name := m.UpstreamName
		if name == "" {
			name = m.Name
		}
		out, err = ex.CallTool(callCtx, cred, name, args)
		if c, ok := ex.(interface{ Open() bool }); ok {
			open := 0
			if c.Open() {
				open = 1
			}
			p.Metrics.Circuits.Store(m.Server, open)
		}
	}
	if err != nil {
		res.Status = StatusUpstreamError
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			res.Reason = []string{fmt.Sprintf("timeout after %dms", m.Limits.TimeoutMS)}
		} else {
			res.Reason = []string{err.Error()}
		}
		ev.Error = err.Error()
		return res
	}

	// 7. post-process (PEP 4)
	out, redacted := applyObligations(out, d, m)
	res.Content, res.Redacted, ev.Redacted = out, redacted, redacted
	res.Status = StatusOK
	if idemKey != "" && m.Idempotent {
		if b, err := json.Marshal(res); err == nil {
			ttl := time.Duration(m.Credentials.TTLSeconds) * time.Second
			if ttl < time.Minute {
				ttl = 10 * time.Minute
			}
			_ = p.Store.Set(ctx, idemKey, b, ttl)
		}
	}
	return res
}

// DelegationRequest is a supervisor asking whether it may hand a task to a
// target agent (PEP 2). Target, Task and Budget are the policy's business
// facts; the caller and the chain are taken from the verified token, never
// from the request, so a caller cannot shorten or forge its own ancestry.
type DelegationRequest struct {
	Target  map[string]any `json:"target"`          // {id, role, tenant_id, trust_level}
	Task    map[string]any `json:"task"`            // {required_trust, est_tokens}
	Budget  map[string]any `json:"budget"`          // {tokens_used, token_limit}
	Chain   []string       `json:"chain,omitempty"` // accepted on the wire, ignored
	TraceID string         `json:"-"`
}

type DelegationResult struct {
	Allow         bool     `json:"allow"`
	Reason        []string `json:"reason,omitempty"`
	DecisionID    string   `json:"decision_id,omitempty"`
	PolicyVersion string   `json:"policy_version,omitempty"`
	TraceID       string   `json:"trace_id"`
	// Token is the specialist's identity, issued only on allow: the parent's
	// end user and tenant, the target's id and role, the chain extended by the
	// parent. The specialist calls the gateway with it; it cannot be minted
	// by an agent service.
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Delegate evaluates valkyrie/delegation/decision for one handoff. Fail-closed
// and audited like a tool call; the audit tool field is "delegate:<target id>".
func (p *Pipeline) Delegate(ctx context.Context, caller authn.Caller, req DelegationRequest) DelegationResult {
	start := time.Now()
	targetID, _ := req.Target["id"].(string)
	res := DelegationResult{TraceID: req.TraceID}
	ev := audit.Event{Time: start, TraceID: req.TraceID, Tenant: caller.TenantID, Subject: caller.Subject,
		AgentID: caller.AgentID, AgentRole: caller.AgentRole, Tool: "delegate:" + targetID, ArgsHash: audit.HashArgs(req.Target)}
	defer func() {
		ev.LatencyMS = float64(time.Since(start).Microseconds()) / 1000
		if res.Allow {
			ev.Outcome = string(StatusOK)
		} else {
			ev.Outcome = string(StatusDenied)
		}
		if p.Audit != nil {
			p.Audit.Emit(ev)
		}
	}()
	targetRole, _ := req.Target["role"].(string)
	if p.Issuer != nil && targetRole == "" {
		res.Reason = []string{"target_role_required"}
		ev.DenyReason = res.Reason
		return res
	}
	in := map[string]any{
		"caller":    map[string]any{"id": caller.AgentID, "role": caller.AgentRole, "tenant_id": caller.TenantID},
		"principal": map[string]any{"sub": caller.Subject, "tenant_id": caller.TenantID},
		"target":    req.Target,
		"task":      req.Task,
		"chain":     caller.Chain,
	}
	if in["chain"] == nil {
		in["chain"] = []string{}
	}
	if req.Budget != nil {
		in["budget"] = req.Budget
	}
	d, err := p.PDP.Decide(ctx, "valkyrie/delegation/decision", in)
	if err != nil {
		res.Reason, ev.Error = []string{"policy_unavailable"}, err.Error()
		return res
	}
	res.Allow, res.Reason, res.DecisionID, res.PolicyVersion = d.Allow, d.DenyReason, d.DecisionID, d.PolicyVersion
	ev.DecisionID, ev.PolicyVersion, ev.DenyReason = d.DecisionID, d.PolicyVersion, d.DenyReason
	if res.Allow && p.Issuer != nil {
		tok, exp, err := p.Issuer.Issue(caller, targetID, targetRole, d.DecisionID)
		if err != nil {
			// Fail closed: an allow we cannot turn into an identity is not an allow.
			res.Allow, res.Reason, ev.Error = false, []string{"delegation_issuer: " + err.Error()}, err.Error()
			return res
		}
		res.Token, res.ExpiresAt = tok, exp
	}
	return res
}

func (p *Pipeline) schemaFor(m registry.Manifest) (*schema.Schema, error) {
	k := m.Name + "@" + m.Version
	if v, ok := p.schemas.Load(k); ok {
		return v.(*schema.Schema), nil
	}
	s, err := schema.Parse(m.InputSchema)
	if err != nil {
		return nil, err
	}
	p.schemas.Store(k, s)
	return s, nil
}

func (p *Pipeline) policyInput(caller authn.Caller, m registry.Manifest, args map[string]any, cc Context) map[string]any {
	in := map[string]any{
		"agent":     map[string]any{"id": caller.AgentID, "role": caller.AgentRole},
		"principal": map[string]any{"sub": caller.Subject, "tenant_id": caller.TenantID},
		"tool": map[string]any{"name": m.Name, "risk_tier": m.RiskTier, "data_classification": m.DataClassification,
			"server": m.Server, "args": args},
		"chain": caller.Chain,
	}
	if cc.Customer != nil {
		in["customer"] = cc.Customer
	}
	if cc.Approval != nil {
		in["approval"] = cc.Approval
	}
	if cc.Budget != nil {
		in["budget"] = cc.Budget
	}
	return in
}

func applyObligations(out mcpjson.CallToolResult, d policy.Decision, m registry.Manifest) (mcpjson.CallToolResult, []string) {
	fields := d.RedactFields()
	var redacted []string
	if len(fields) > 0 {
		if len(out.StructuredContent) > 0 {
			var obj any
			if json.Unmarshal(out.StructuredContent, &obj) == nil {
				if hits := redact(obj, fields); len(hits) > 0 {
					b, _ := json.Marshal(obj)
					out.StructuredContent = b
					redacted = append(redacted, hits...)
				}
			}
		}
		for i, c := range out.Content {
			if c.Type == "text" && strings.HasPrefix(strings.TrimSpace(c.Text), "{") {
				var obj any
				if json.Unmarshal([]byte(c.Text), &obj) == nil {
					if hits := redact(obj, fields); len(hits) > 0 {
						b, _ := json.Marshal(obj)
						out.Content[i].Text = string(b)
						redacted = append(redacted, hits...)
					}
				}
			}
		}
	}
	if max := d.MaxRows(); max > 0 {
		if len(out.StructuredContent) > 0 {
			var obj any
			if json.Unmarshal(out.StructuredContent, &obj) == nil && truncateRows(obj, max) {
				b, _ := json.Marshal(obj)
				out.StructuredContent = b
			}
		}
	}
	limit := m.Limits.MaxResultKB * 1024
	if limit > 0 {
		for i, c := range out.Content {
			if len(c.Text) > limit {
				out.Content[i].Text = c.Text[:limit] + "…[truncated by gateway: max_result_kb]"
			}
		}
		if len(out.StructuredContent) > limit {
			out.StructuredContent = nil
		}
	}
	return out, dedupe(redacted)
}

// truncateRows caps every array in the object to max elements.
func truncateRows(v any, max int) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if arr, ok := val.([]any); ok && len(arr) > max {
				t[k] = arr[:max]
				changed = true
			} else if truncateRows(val, max) {
				changed = true
			}
		}
	case []any:
		for _, el := range t {
			if truncateRows(el, max) {
				changed = true
			}
		}
	}
	return changed
}

func redact(v any, fields []string) []string {
	var hits []string
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if contains(fields, k) {
				t[k] = "[REDACTED]"
				hits = append(hits, k)
				continue
			}
			hits = append(hits, redact(val, fields)...)
		}
	case []any:
		for _, el := range t {
			hits = append(hits, redact(el, fields)...)
		}
	}
	return hits
}

func normalize(args map[string]any) map[string]any {
	b, _ := json.Marshal(args)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

var _ Executor = (*upstream.Client)(nil)
var _ Adapter = (*upstream.HTTPAdapter)(nil)

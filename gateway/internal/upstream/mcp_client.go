// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package upstream executes the allowed call against the MCP server behind
// the tool, over Streamable HTTP. One Client per server; a bounded semaphore
// per server is the backpressure; a circuit breaker opens after consecutive
// failures so one slow upstream cannot pin every gateway goroutine.
package upstream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"valkyrie/gateway/internal/mcpjson"
)

var ErrCircuitOpen = errors.New("upstream: circuit open")
var ErrBusy = errors.New("upstream: too many in-flight calls")

type Client struct {
	Name string
	URL  string
	HTTP *http.Client

	sem          chan struct{}
	failures     atomic.Int32
	openUntil    atomic.Int64 // unix nanos
	maxFailures  int32
	cooldown     time.Duration
	sessionMu    sync.Mutex
	sessionID    string
	initialized  bool
	maxResultLen int64
	rpcID        atomic.Int64
}

type Options struct {
	MaxInFlight  int
	MaxFailures  int
	Cooldown     time.Duration
	MaxResultLen int64 // bytes; results larger than this are truncated (PEP 4 enforces the manifest's limit on top)
}

func New(name, url string, o Options) *Client {
	if o.MaxInFlight <= 0 {
		o.MaxInFlight = 64
	}
	if o.MaxFailures <= 0 {
		o.MaxFailures = 5
	}
	if o.Cooldown <= 0 {
		o.Cooldown = 10 * time.Second
	}
	if o.MaxResultLen <= 0 {
		o.MaxResultLen = 4 << 20
	}
	return &Client{
		Name: name, URL: url,
		HTTP:        &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: o.MaxInFlight, IdleConnTimeout: 90 * time.Second}},
		sem:         make(chan struct{}, o.MaxInFlight),
		maxFailures: int32(o.MaxFailures), cooldown: o.Cooldown, maxResultLen: o.MaxResultLen,
	}
}

// CallTool runs tools/call with the leased credential attached.
func (c *Client) CallTool(ctx context.Context, cred Credential, name string, args map[string]any) (mcpjson.CallToolResult, error) {
	if c.Open() {
		return mcpjson.CallToolResult{}, ErrCircuitOpen
	}
	bearer := cred
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	default:
		return mcpjson.CallToolResult{}, ErrBusy
	}
	if err := c.ensureInitialized(ctx, bearer); err != nil {
		c.recordFailure()
		return mcpjson.CallToolResult{}, err
	}
	params, _ := json.Marshal(mcpjson.CallToolParams{Name: name, Arguments: args})
	resp, err := c.rpc(ctx, bearer, "tools/call", params)
	if err != nil {
		c.recordFailure()
		return mcpjson.CallToolResult{}, err
	}
	c.failures.Store(0)
	if resp.Error != nil {
		return mcpjson.CallToolResult{}, fmt.Errorf("upstream %s: rpc error %d: %s", c.Name, resp.Error.Code, resp.Error.Message)
	}
	var out mcpjson.CallToolResult
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return mcpjson.CallToolResult{}, fmt.Errorf("upstream %s: bad tools/call result: %w", c.Name, err)
	}
	return out, nil
}

// Open reports whether the circuit breaker is currently open.
func (c *Client) Open() bool { return time.Now().UnixNano() < c.openUntil.Load() }

func (c *Client) recordFailure() {
	if c.failures.Add(1) >= c.maxFailures {
		c.openUntil.Store(time.Now().Add(c.cooldown).UnixNano())
		c.failures.Store(0)
	}
}

func (c *Client) ensureInitialized(ctx context.Context, bearer Credential) error {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.initialized {
		return nil
	}
	params, _ := json.Marshal(map[string]any{
		"protocolVersion": mcpjson.ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "valkyrie-gateway", "version": "0.1.0"},
	})
	resp, err := c.rpcLocked(ctx, bearer, "initialize", params)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("upstream %s: initialize: %s", c.Name, resp.Error.Message)
	}
	// notifications/initialized has no id and expects no response.
	note, _ := json.Marshal(mcpjson.Request{JSONRPC: "2.0", Method: "notifications/initialized"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(note))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", mcpjson.ProtocolVersion)
	bearer.Apply(req)
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	if r, err := c.HTTP.Do(req); err == nil {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	c.initialized = true
	return nil
}

func (c *Client) rpc(ctx context.Context, bearer Credential, method string, params json.RawMessage) (mcpjson.Response, error) {
	c.sessionMu.Lock()
	sid := c.sessionID
	c.sessionMu.Unlock()
	resp, newSID, err := c.do(ctx, bearer, sid, method, params)
	if newSID != "" {
		c.sessionMu.Lock()
		c.sessionID = newSID
		c.sessionMu.Unlock()
	}
	return resp, err
}

// rpcLocked is called with sessionMu held.
func (c *Client) rpcLocked(ctx context.Context, bearer Credential, method string, params json.RawMessage) (mcpjson.Response, error) {
	resp, newSID, err := c.do(ctx, bearer, c.sessionID, method, params)
	if newSID != "" {
		c.sessionID = newSID
	}
	return resp, err
}

// do performs one JSON-RPC exchange. It never touches sessionMu; it returns
// any session id the server assigned so the caller can store it.
func (c *Client) do(ctx context.Context, bearer Credential, sid, method string, params json.RawMessage) (mcpjson.Response, string, error) {
	id, _ := json.Marshal(c.rpcID.Add(1))
	body, _ := json.Marshal(mcpjson.Request{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return mcpjson.Response{}, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", mcpjson.ProtocolVersion)
	bearer.Apply(req)
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return mcpjson.Response{}, "", fmt.Errorf("upstream %s: %w", c.Name, err)
	}
	defer resp.Body.Close()
	newSID := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusNotFound && sid != "" {
			// The server forgot our session (restart, idle timeout). Drop it so
			// the next call re-initializes instead of failing forever.
			c.sessionMu.Lock()
			c.sessionID, c.initialized = "", false
			c.sessionMu.Unlock()
		}
		return mcpjson.Response{}, newSID, fmt.Errorf("upstream %s: http %d: %s", c.Name, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	limited := io.LimitReader(resp.Body, c.maxResultLen)
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		r, err := readSSE(limited, string(id))
		return r, newSID, err
	}
	var out mcpjson.Response
	if err := json.NewDecoder(limited).Decode(&out); err != nil {
		return mcpjson.Response{}, newSID, fmt.Errorf("upstream %s: decode: %w", c.Name, err)
	}
	return out, newSID, nil
}

// readSSE scans an event stream until it finds the response whose id matches.
// Streaming pass-through for progress notifications is handled at the API
// layer; here we need only the final response.
func readSSE(r io.Reader, wantID string) (mcpjson.Response, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	var data strings.Builder
	flush := func() (mcpjson.Response, bool) {
		if data.Len() == 0 {
			return mcpjson.Response{}, false
		}
		var msg mcpjson.Response
		err := json.Unmarshal([]byte(data.String()), &msg)
		data.Reset()
		if err != nil || len(msg.ID) == 0 {
			return mcpjson.Response{}, false
		}
		if string(msg.ID) == wantID {
			return msg, true
		}
		return mcpjson.Response{}, false
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if msg, ok := flush(); ok {
				return msg, nil
			}
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if msg, ok := flush(); ok {
		return msg, nil
	}
	if err := sc.Err(); err != nil {
		return mcpjson.Response{}, err
	}
	return mcpjson.Response{}, errors.New("upstream: stream ended without a response")
}

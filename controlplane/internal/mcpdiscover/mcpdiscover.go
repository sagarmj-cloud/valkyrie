// SPDX-License-Identifier: LicenseRef-Valkyrie-Enterprise
// Copyright (c) 2026 Sagar Jadhav

// Package mcpdiscover talks to an MCP server over Streamable HTTP just enough
// to list its tools: initialize, notifications/initialized, tools/list. Used
// by the contract test and by `valkyriectl import-mcp`.
package mcpdiscover

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
	"time"
)

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type rpcResp struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// ListTools lists a server's tools. auth is attached per scheme: "" or
// "Authorization: Bearer" (default) sends a bearer; "X-API-Key" sends a header.
func ListTools(ctx context.Context, url, auth, scheme string) ([]Tool, error) {
	c := &http.Client{Timeout: 10 * time.Second}
	sid := ""
	call := func(id int, method string, params any) (rpcResp, error) {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		applyAuth(req, auth, scheme)
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		resp, err := c.Do(req)
		if err != nil {
			return rpcResp{}, err
		}
		defer resp.Body.Close()
		if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
			sid = s
		}
		if resp.StatusCode/100 != 2 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			return rpcResp{}, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
		}
		if resp.StatusCode == http.StatusAccepted {
			return rpcResp{}, nil
		}
		want := fmt.Sprint(id)
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			sc := bufio.NewScanner(resp.Body)
			sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
			var data strings.Builder
			for sc.Scan() {
				line := sc.Text()
				if strings.HasPrefix(line, "data:") {
					data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				} else if line == "" && data.Len() > 0 {
					var r rpcResp
					if json.Unmarshal([]byte(data.String()), &r) == nil && string(r.ID) == want {
						return r, nil
					}
					data.Reset()
				}
			}
			if data.Len() > 0 {
				var r rpcResp
				if json.Unmarshal([]byte(data.String()), &r) == nil && string(r.ID) == want {
					return r, nil
				}
			}
			return rpcResp{}, errors.New("no response in event stream")
		}
		var r rpcResp
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return rpcResp{}, err
		}
		return r, nil
	}
	if r, err := call(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "valkyriectl", "version": "0.2.0"}}); err != nil {
		return nil, err
	} else if r.Error != nil {
		return nil, fmt.Errorf("initialize: %s", r.Error.Message)
	}
	// notification: no id
	note, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(note))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	applyAuth(req, auth, scheme)
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if resp, err := c.Do(req); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	r, err := call(2, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	if r.Error != nil {
		return nil, fmt.Errorf("tools/list: %s", r.Error.Message)
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &out); err != nil {
		return nil, err
	}
	return out.Tools, nil
}

func applyAuth(req *http.Request, token, scheme string) {
	if token == "" {
		return
	}
	switch {
	case scheme == "" || strings.EqualFold(scheme, "Authorization: Bearer"):
		req.Header.Set("Authorization", "Bearer "+token)
	case strings.Contains(scheme, ":"):
		parts := strings.SplitN(scheme, ":", 2)
		req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])+" "+token)
	default:
		req.Header.Set(scheme, token)
	}
}

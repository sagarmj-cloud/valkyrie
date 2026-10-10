// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package mcpjson holds the JSON-RPC 2.0 envelope and the MCP message shapes
// the gateway needs: initialize, tools/list, tools/call. The gateway does not
// implement the full protocol; it proxies these three methods and rejects the
// rest. That is deliberate: a smaller surface is easier to police.
package mcpjson

import "encoding/json"

const ProtocolVersion = "2025-06-18"

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// JSON-RPC error codes used by the gateway.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
	// Valkyrie-specific (server-defined range).
	CodeDenied           = -32001
	CodeApprovalRequired = -32002
	CodeUnauthenticated  = -32003
)

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type CallToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type CallToolResult struct {
	Content           []Content       `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError,omitempty"`
}

func NewResponse(id json.RawMessage, result any) Response {
	b, _ := json.Marshal(result)
	return Response{JSONRPC: "2.0", ID: id, Result: b}
}

func NewError(id json.RawMessage, code int, msg string, data any) Response {
	return Response{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg, Data: data}}
}

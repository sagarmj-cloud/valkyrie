// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package audit emits one structured event per tool call. Arguments are
// hashed, never logged raw; the decision id links the event to OPA's own
// decision log so the two can be joined in the SIEM.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Event struct {
	Time          time.Time `json:"time"`
	TraceID       string    `json:"trace_id"`
	Tenant        string    `json:"tenant"`
	Subject       string    `json:"sub"`
	AgentID       string    `json:"agent_id"`
	AgentRole     string    `json:"agent_role"`
	Tool          string    `json:"tool"`
	ToolVersion   string    `json:"tool_version"`
	ArgsHash      string    `json:"args_hash"`
	Outcome       string    `json:"outcome"` // allowed | denied | approval_required | error
	DenyReason    []string  `json:"deny_reason,omitempty"`
	DecisionID    string    `json:"decision_id,omitempty"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	LeaseID       string    `json:"lease_id,omitempty"`
	Redacted      []string  `json:"redacted,omitempty"`
	LatencyMS     float64   `json:"latency_ms"`
	Error         string    `json:"error,omitempty"`
}

type Sink interface{ Emit(Event) }

// JSONL writes one JSON object per line (stdout in dev, a file or a
// collector pipe in production).
type JSONL struct {
	mu sync.Mutex
	W  io.Writer
}

func (j *JSONL) Emit(e Event) {
	b, _ := json.Marshal(e)
	j.mu.Lock()
	defer j.mu.Unlock()
	j.W.Write(append(b, '\n'))
}

// Memory keeps events for tests and the /debug endpoint.
type Memory struct {
	mu     sync.Mutex
	Events []Event
}

func (m *Memory) Emit(e Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, e)
}

func (m *Memory) Snapshot() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.Events))
	copy(out, m.Events)
	return out
}

func HashArgs(args any) string {
	b, _ := json.Marshal(args)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

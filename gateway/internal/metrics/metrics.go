// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package metrics exposes Prometheus text-format metrics from the standard
// library: a counter per (tool, outcome), a latency histogram per tool, and
// gauges for in-flight calls and circuit state. No client library: the
// exposition format is three line shapes.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

var buckets = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

type hist struct {
	counts [12]uint64 // 11 buckets + inf
	sum    float64
	n      uint64
}

type Registry struct {
	mu       sync.Mutex
	calls    map[string]map[string]uint64 // tool -> outcome -> n
	latency  map[string]*hist
	denies   map[string]uint64 // reason prefix -> n
	InFlight atomic.Int64
	Circuits sync.Map // server -> open(1)/closed(0)
}

func New() *Registry {
	return &Registry{calls: map[string]map[string]uint64{}, latency: map[string]*hist{}, denies: map[string]uint64{}}
}

func (r *Registry) Observe(tool, outcome string, ms float64, denyReasons []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls[tool] == nil {
		r.calls[tool] = map[string]uint64{}
	}
	r.calls[tool][outcome]++
	h := r.latency[tool]
	if h == nil {
		h = &hist{}
		r.latency[tool] = h
	}
	h.n++
	h.sum += ms
	placed := false
	for i, b := range buckets {
		if ms <= b {
			h.counts[i]++
			placed = true
			break
		}
	}
	if !placed {
		h.counts[len(buckets)]++
	}
	for _, d := range denyReasons {
		if i := strings.IndexByte(d, ':'); i > 0 {
			d = d[:i]
		}
		r.denies[d]++
	}
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.mu.Lock()
		defer r.mu.Unlock()
		var sb strings.Builder
		sb.WriteString("# HELP valkyrie_tool_calls_total Tool calls by tool and outcome.\n# TYPE valkyrie_tool_calls_total counter\n")
		for _, tool := range sortedKeys(r.calls) {
			for _, o := range sortedKeys(r.calls[tool]) {
				fmt.Fprintf(&sb, "valkyrie_tool_calls_total{tool=%q,outcome=%q} %d\n", tool, o, r.calls[tool][o])
			}
		}
		sb.WriteString("# HELP valkyrie_policy_denies_total Policy denies by reason.\n# TYPE valkyrie_policy_denies_total counter\n")
		for _, d := range sortedKeys(r.denies) {
			fmt.Fprintf(&sb, "valkyrie_policy_denies_total{reason=%q} %d\n", d, r.denies[d])
		}
		sb.WriteString("# HELP valkyrie_tool_latency_ms End-to-end gateway latency per tool.\n# TYPE valkyrie_tool_latency_ms histogram\n")
		for _, tool := range sortedKeys(r.latency) {
			h := r.latency[tool]
			var cum uint64
			for i, b := range buckets {
				cum += h.counts[i]
				fmt.Fprintf(&sb, "valkyrie_tool_latency_ms_bucket{tool=%q,le=\"%g\"} %d\n", tool, b, cum)
			}
			cum += h.counts[len(buckets)]
			fmt.Fprintf(&sb, "valkyrie_tool_latency_ms_bucket{tool=%q,le=\"+Inf\"} %d\n", tool, cum)
			fmt.Fprintf(&sb, "valkyrie_tool_latency_ms_sum{tool=%q} %g\n", tool, h.sum)
			fmt.Fprintf(&sb, "valkyrie_tool_latency_ms_count{tool=%q} %d\n", tool, h.n)
		}
		fmt.Fprintf(&sb, "# TYPE valkyrie_inflight_calls gauge\nvalkyrie_inflight_calls %d\n", r.InFlight.Load())
		sb.WriteString("# TYPE valkyrie_upstream_circuit_open gauge\n")
		r.Circuits.Range(func(k, v any) bool {
			fmt.Fprintf(&sb, "valkyrie_upstream_circuit_open{server=%q} %d\n", k, v)
			return true
		})
		w.Write([]byte(sb.String()))
	})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package store is the gateway's shared-state abstraction: idempotency
// results, rate-limit counters and (later) session records. Two
// implementations: an in-process TTL cache for single-replica/dev, and a
// Redis client speaking RESP2 over the standard library so the gateway stays
// dependency-free. Every method is bounded by the caller's context.
package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("store: not found")

type Store interface {
	// Get returns the value for key or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)
	// SetNX sets key only if absent; reports whether it was set.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// Set unconditionally sets key with a TTL.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Incr increments a counter, setting its TTL on first creation, and
	// returns the new value. Used by the rate limiter.
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// Ping reports whether the store is reachable (readiness).
	Ping(ctx context.Context) error
}

// Memory is a bounded TTL cache. When it reaches MaxEntries it evicts
// expired entries first, then the oldest, so it can never grow without bound.
type Memory struct {
	mu         sync.Mutex
	items      map[string]entry
	MaxEntries int
	now        func() time.Time
}

type entry struct {
	val     []byte
	n       int64
	expires time.Time
	created time.Time
}

func NewMemory(maxEntries int) *Memory {
	if maxEntries <= 0 {
		maxEntries = 100_000
	}
	return &Memory{items: map[string]entry{}, MaxEntries: maxEntries, now: time.Now}
}

func (m *Memory) get(key string) (entry, bool) {
	e, ok := m.items[key]
	if !ok {
		return entry{}, false
	}
	if m.now().After(e.expires) {
		delete(m.items, key)
		return entry{}, false
	}
	return e, true
}

func (m *Memory) evictIfFull() {
	if len(m.items) < m.MaxEntries {
		return
	}
	now := m.now()
	var oldestK string
	var oldest time.Time
	for k, e := range m.items {
		if now.After(e.expires) {
			delete(m.items, k)
			continue
		}
		if oldestK == "" || e.created.Before(oldest) {
			oldestK, oldest = k, e.created
		}
	}
	if len(m.items) >= m.MaxEntries && oldestK != "" {
		delete(m.items, oldestK)
	}
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.get(key)
	if !ok {
		return nil, ErrNotFound
	}
	return e.val, nil
}

func (m *Memory) SetNX(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.get(key); ok {
		return false, nil
	}
	m.evictIfFull()
	m.items[key] = entry{val: value, expires: m.now().Add(ttl), created: m.now()}
	return true, nil
}

func (m *Memory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictIfFull()
	m.items[key] = entry{val: value, expires: m.now().Add(ttl), created: m.now()}
	return nil
}

func (m *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.get(key)
	if !ok {
		m.evictIfFull()
		e = entry{expires: m.now().Add(ttl), created: m.now()}
	}
	e.n++
	m.items[key] = e
	return e.n, nil
}

func (m *Memory) Ping(context.Context) error { return nil }

func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

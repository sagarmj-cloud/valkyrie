// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package ratelimit enforces the manifest's rate_per_minute per tenant and
// tool using a fixed one-minute window in the shared store. Fixed windows
// are simple and multi-replica safe; a sliding window costs more round trips
// for little benefit at the per-tool rates manifests declare.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"valkyrie/gateway/internal/store"
)

type Limiter struct {
	Store store.Store
	Now   func() time.Time
}

func New(s store.Store) *Limiter { return &Limiter{Store: s, Now: time.Now} }

// Allow reports whether one more call for (tenant, tool) fits in this
// minute's budget. A store error fails open for availability but is
// returned so the caller can log it; the policy layer remains fail-closed.
func (l *Limiter) Allow(ctx context.Context, tenant, tool string, perMinute int) (bool, int64, error) {
	if perMinute <= 0 {
		return true, 0, nil
	}
	window := l.Now().Unix() / 60
	key := fmt.Sprintf("rl:%s:%s:%d", tenant, tool, window)
	n, err := l.Store.Incr(ctx, key, 2*time.Minute)
	if err != nil {
		return true, 0, err
	}
	return n <= int64(perMinute), n, nil
}

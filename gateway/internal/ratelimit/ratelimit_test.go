// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package ratelimit

import (
	"context"
	"testing"
	"time"

	"valkyrie/gateway/internal/store"
)

func TestFixedWindow(t *testing.T) {
	now := time.Unix(600, 0)
	l := New(store.NewMemory(100))
	l.Now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if ok, _, _ := l.Allow(ctx, "acme", "menu.search_menu", 3); !ok {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	if ok, n, _ := l.Allow(ctx, "acme", "menu.search_menu", 3); ok || n != 4 {
		t.Fatal("4th call in the window must be refused")
	}
	if ok, _, _ := l.Allow(ctx, "other", "menu.search_menu", 3); !ok {
		t.Fatal("limits are per tenant")
	}
	now = now.Add(time.Minute)
	if ok, _, _ := l.Allow(ctx, "acme", "menu.search_menu", 3); !ok {
		t.Fatal("new window must reset")
	}
	if ok, _, _ := l.Allow(ctx, "acme", "x", 0); !ok {
		t.Fatal("zero means unlimited")
	}
}

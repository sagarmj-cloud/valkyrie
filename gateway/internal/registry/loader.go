// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Loader keeps a Registry fresh from either a file path or a control-plane
// URL (registryd's GET /v1/registry). HTTP loads use ETag so a poll that
// finds nothing new costs one round trip and no parsing. A failed poll logs
// and keeps serving the last good registry: stale-but-valid.
type Loader struct {
	Source   string // file path or http(s) URL
	Interval time.Duration
	HTTP     *http.Client
	Log      *slog.Logger
	Token    string // bearer for registryd, if it requires one
	OnChange func(*Registry)
}

func (l *Loader) Load(ctx context.Context) (*Registry, error) {
	if strings.HasPrefix(l.Source, "http://") || strings.HasPrefix(l.Source, "https://") {
		r, _, err := l.fetch(ctx, "")
		return r, err
	}
	return Load(l.Source)
}

func (l *Loader) fetch(ctx context.Context, etag string) (*Registry, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.Source, nil)
	if err != nil {
		return nil, false, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if l.Token != "" {
		req.Header.Set("Authorization", "Bearer "+l.Token)
	}
	c := l.HTTP
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("registry: %s: http %d", l.Source, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, false, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, false, fmt.Errorf("registry: parse: %w", err)
	}
	r, err := FromFile(f)
	if err != nil {
		return nil, false, err
	}
	r.etag = resp.Header.Get("ETag")
	return r, true, nil
}

// Run polls until ctx is done. Only meaningful for HTTP sources; a file
// source is re-read on the same interval (cheap, and handy in dev).
func (l *Loader) Run(ctx context.Context, into *Registry) {
	if l.Interval <= 0 {
		l.Interval = 30 * time.Second
	}
	t := time.NewTicker(l.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var next *Registry
		var changed bool
		var err error
		if strings.HasPrefix(l.Source, "http") {
			into.mu.RLock()
			etag := into.etag
			into.mu.RUnlock()
			next, changed, err = l.fetch(ctx, etag)
		} else {
			next, err = Load(l.Source)
			changed = err == nil && next.Revision() != into.Revision()
		}
		if err != nil {
			if l.Log != nil {
				l.Log.Warn("registry refresh failed; serving last good copy", "err", err)
			}
			continue
		}
		if changed && next != nil {
			into.Replace(next)
			if l.Log != nil {
				l.Log.Info("registry refreshed", "revision", next.Revision(), "tools", len(next.All()))
			}
			if l.OnChange != nil {
				l.OnChange(into)
			}
		}
	}
}

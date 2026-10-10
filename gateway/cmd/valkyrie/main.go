// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// valkyrie — the gateway. Chooses who passes.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"valkyrie/gateway/internal/api"
	"valkyrie/gateway/internal/audit"
	"valkyrie/gateway/internal/authn"
	"valkyrie/gateway/internal/config"
	"valkyrie/gateway/internal/credentials"
	"valkyrie/gateway/internal/metrics"
	"valkyrie/gateway/internal/pipeline"
	"valkyrie/gateway/internal/policy"
	"valkyrie/gateway/internal/registry"
	"valkyrie/gateway/internal/store"
	"valkyrie/gateway/internal/upstream"
)

var version = "0.2.0"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		log.Error("refusing to start", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- registry: file or control plane, refreshed on a TTL
	loader := &registry.Loader{Source: cfg.RegistrySource, Interval: cfg.RegistryInterval, Log: log, Token: cfg.RegistryToken}
	reg, err := loader.Load(ctx)
	if err != nil {
		log.Error("registry", "err", err)
		os.Exit(1)
	}
	go loader.Run(ctx, reg)

	// --- audit sink
	var sink audit.Sink
	if cfg.AuditPath == "-" {
		sink = &audit.JSONL{W: os.Stdout}
	} else {
		f, err := os.OpenFile(cfg.AuditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Error("audit", "err", err)
			os.Exit(1)
		}
		defer f.Close()
		sink = &audit.JSONL{W: f}
	}

	// --- shared store
	var st store.Store
	if cfg.RedisAddr != "" {
		st = store.NewRedis(cfg.RedisAddr, cfg.RedisPassword, cfg.MaxInFlight)
	} else {
		st = store.NewMemory(0)
	}

	// --- caller authentication: JWKS (prod) and/or HMAC (dev, migration)
	var verifiers authn.Chain
	if cfg.OIDCJWKSURL != "" {
		j := authn.NewJWKS(cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCJWKSURL)
		if err := j.Refresh(ctx); err != nil {
			log.Error("jwks", "err", err)
			os.Exit(1)
		}
		verifiers = append(verifiers, j)
	}
	if cfg.Env != "prod" || cfg.AuthSecret != "dev-secret-change-me" {
		verifiers = append(verifiers, authn.HMACVerifier{Secret: []byte(cfg.AuthSecret)})
	}

	// --- credential brokers
	broker := credentials.Router{Signed: credentials.NewSigned([]byte(cfg.LeaseKey), "valkyrie"), Static: credentials.NewStatic(), None: credentials.NoneBroker{}}
	if cfg.VaultAddr != "" {
		v := credentials.NewVault(cfg.VaultAddr, cfg.VaultToken, cfg.VaultMount)
		v.TokenField = cfg.VaultTokenField
		broker.Vault = v
	}

	// --- HTTP adapter with host allow-list
	adapter := upstream.NewHTTPAdapter()
	adapter.SSRFAllowed = func(host string) bool {
		for _, a := range cfg.AdapterAllow {
			if a == "*" || strings.EqualFold(a, host) || (strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:])) {
				return true
			}
		}
		return false
	}

	pdp := policy.NewOPA(cfg.OPAURL)
	mets := metrics.New()
	p := pipeline.New(pipeline.Options{Registry: reg, PDP: pdp, Broker: broker, Audit: sink, Store: st, Metrics: mets, Adapter: adapter, Log: log,
		Factory: func(name string, s registry.Server) pipeline.Executor {
			return upstream.New(name, s.URL, upstream.Options{MaxInFlight: cfg.MaxInFlight})
		}})

	srv := &api.Server{Verifier: verifiers, Pipeline: p, Log: log, Metrics: mets.Handler(), Ready: func(ctx context.Context) error {
		if err := st.Ping(ctx); err != nil {
			return fmt.Errorf("store: %w", err)
		}
		if _, err := pdp.Decide(ctx, "valkyrie/tool_authz/decision", map[string]any{"agent": map[string]any{"role": "readyz"}, "tool": map[string]any{"name": "readyz"}}); err != nil {
			return fmt.Errorf("opa: %w", err)
		}
		if len(reg.All()) == 0 {
			return errors.New("registry: no tools loaded")
		}
		return nil
	}}

	httpSrv := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: cfg.ReadTimeout, IdleTimeout: 120 * time.Second}
	go func() {
		log.Info("valkyrie listening", "version", version, "config", cfg.String(), "tools", len(reg.All()), "revision", reg.Revision())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	log.Info("valkyrie stopped")
}

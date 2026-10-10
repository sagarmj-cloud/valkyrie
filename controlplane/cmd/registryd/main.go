// SPDX-License-Identifier: LicenseRef-Valkyrie-Enterprise
// Copyright (c) 2026 Sagar Jadhav

// registryd — Valkyrie's control plane. Publishes tools, binds roles, serves
// the registry snapshot to gateways and the signed policy bundle to OPA.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"valkyrie/controlplane/internal/api"
	"valkyrie/controlplane/internal/bundle"
	"valkyrie/controlplane/internal/contract"
	"valkyrie/controlplane/internal/store"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	st, err := store.Open(env("REGISTRYD_STATE", "registryd-state.json"))
	if err != nil {
		log.Error("store", "err", err)
		os.Exit(1)
	}
	admin := env("VALKYRIE_REGISTRY_ADMIN_TOKEN", "")
	if admin == "" {
		log.Error("VALKYRIE_REGISTRY_ADMIN_TOKEN is required")
		os.Exit(1)
	}
	srv := &api.Server{
		Store: st, Log: log, AdminToken: admin, ReaderToken: env("VALKYRIE_REGISTRY_TOKEN", ""),
		ContractAuth: contract.Auth{LeaseKey: []byte(env("VALKYRIE_LEASE_KEY", "dev-lease-key-change-me")), Lookup: os.Getenv},
		Bundle:       &bundle.Builder{PolicyDir: env("REGISTRYD_POLICY_DIR", "policies"), SigningKey: []byte(env("VALKYRIE_BUNDLE_KEY", "dev-bundle-key-change-me")), KeyID: env("VALKYRIE_BUNDLE_KEYID", "valkyrie-ci")},
	}
	hs := &http.Server{Addr: env("REGISTRYD_LISTEN", ":8090"), Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Info("registryd listening", "addr", hs.Addr, "revision", st.Revision(), "tools", len(st.Tools()))
		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("serve", "err", err)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
}

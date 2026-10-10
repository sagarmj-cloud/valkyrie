// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

// Package config reads the gateway's settings from the environment. Twelve-
// factor: no config files, so the same binary runs in dev, CI and Kubernetes.
// Validate() refuses to start a production deployment with dev defaults.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env    string // dev | prod
	Listen string

	RegistrySource   string // file path or registryd URL
	RegistryToken    string
	RegistryInterval time.Duration

	OPAURL string

	// Caller authentication
	AuthSecret   string // HS256 dev secret (dev only, or during migration)
	OIDCIssuer   string
	OIDCAudience string
	OIDCJWKSURL  string

	// Credential brokers
	LeaseKey        string // HS256 key shared with first-party servers
	VaultAddr       string
	VaultToken      string
	VaultMount      string
	VaultTokenField string

	// Shared store
	RedisAddr     string
	RedisPassword string

	AuditPath     string // "-" for stdout
	MaxInFlight   int
	ReadTimeout   time.Duration
	ShutdownGrace time.Duration
	AdapterAllow  []string // hosts the HTTP adapter may call ("*" allows all; prod must list)
}

func FromEnv() Config {
	return Config{
		Env:              get("VALKYRIE_ENV", "dev"),
		Listen:           get("VALKYRIE_LISTEN", ":8080"),
		RegistrySource:   get("VALKYRIE_REGISTRY", "registry.json"),
		RegistryToken:    get("VALKYRIE_REGISTRY_TOKEN", ""),
		RegistryInterval: time.Duration(geti("VALKYRIE_REGISTRY_INTERVAL_S", 30)) * time.Second,
		OPAURL:           get("VALKYRIE_OPA_URL", "http://127.0.0.1:8181"),
		AuthSecret:       get("VALKYRIE_AUTH_SECRET", "dev-secret-change-me"),
		OIDCIssuer:       get("VALKYRIE_OIDC_ISSUER", ""),
		OIDCAudience:     get("VALKYRIE_OIDC_AUDIENCE", "valkyrie"),
		OIDCJWKSURL:      get("VALKYRIE_OIDC_JWKS_URL", ""),
		LeaseKey:         get("VALKYRIE_LEASE_KEY", "dev-lease-key-change-me"),
		VaultAddr:        get("VALKYRIE_VAULT_ADDR", ""),
		VaultToken:       get("VALKYRIE_VAULT_TOKEN", ""),
		VaultMount:       get("VALKYRIE_VAULT_MOUNT", "valkyrie-tools"),
		VaultTokenField:  get("VALKYRIE_VAULT_TOKEN_FIELD", "token"),
		RedisAddr:        get("VALKYRIE_REDIS_ADDR", ""),
		RedisPassword:    get("VALKYRIE_REDIS_PASSWORD", ""),
		AuditPath:        get("VALKYRIE_AUDIT", "-"),
		MaxInFlight:      geti("VALKYRIE_MAX_INFLIGHT", 64),
		ReadTimeout:      time.Duration(geti("VALKYRIE_READ_TIMEOUT_S", 30)) * time.Second,
		ShutdownGrace:    time.Duration(geti("VALKYRIE_SHUTDOWN_GRACE_S", 15)) * time.Second,
		AdapterAllow:     splitList(get("VALKYRIE_ADAPTER_ALLOW_HOSTS", "*")),
	}
}

// Validate enforces production invariants. In dev everything is permitted.
func (c Config) Validate() error {
	if c.Env != "prod" {
		return nil
	}
	var errs []string
	if c.AuthSecret == "dev-secret-change-me" && c.OIDCJWKSURL == "" {
		errs = append(errs, "VALKYRIE_OIDC_JWKS_URL is required in prod (or set a non-default VALKYRIE_AUTH_SECRET)")
	}
	if c.LeaseKey == "dev-lease-key-change-me" || len(c.LeaseKey) < 32 {
		errs = append(errs, "VALKYRIE_LEASE_KEY must be a random key of at least 32 bytes in prod")
	}
	if c.RedisAddr == "" {
		errs = append(errs, "VALKYRIE_REDIS_ADDR is required in prod (idempotency and rate limits must be shared across replicas)")
	}
	if len(c.AdapterAllow) == 1 && c.AdapterAllow[0] == "*" {
		errs = append(errs, "VALKYRIE_ADAPTER_ALLOW_HOSTS must list allowed hosts in prod (no wildcard)")
	}
	if c.AuditPath == "-" {
		// stdout is fine when a collector reads it; warn-level only.
	}
	if len(errs) > 0 {
		return errors.New("config: " + strings.Join(errs, "; "))
	}
	return nil
}

func (c Config) String() string {
	return fmt.Sprintf("env=%s listen=%s registry=%s opa=%s oidc=%v vault=%v redis=%v", c.Env, c.Listen, c.RegistrySource, c.OPAURL,
		c.OIDCJWKSURL != "", c.VaultAddr != "", c.RedisAddr != "")
}

func get(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func geti(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return d
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

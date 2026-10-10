// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Sagar Jadhav

package config

import "testing"

func TestProdRefusesDevDefaults(t *testing.T) {
	c := FromEnv()
	c.Env = "prod"
	if err := c.Validate(); err == nil {
		t.Fatal("prod with dev defaults must fail validation")
	}
	c.OIDCJWKSURL, c.LeaseKey, c.RedisAddr, c.AdapterAllow = "https://idp/jwks", "0123456789abcdef0123456789abcdef", "redis:6379", []string{"weather.internal"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid prod config rejected: %v", err)
	}
	c.Env = "dev"
	c.LeaseKey = "x"
	if err := c.Validate(); err != nil {
		t.Fatal("dev must be permissive")
	}
}

func TestProdRequiresOIDCEvenWithCustomHMACSecret(t *testing.T) {
	c := FromEnv()
	c.Env = "prod"
	c.LeaseKey, c.RedisAddr, c.AdapterAllow = "0123456789abcdef0123456789abcdef", "redis:6379", []string{"weather.internal"}
	c.AuthSecret, c.OIDCJWKSURL = "a-strong-custom-secret-that-is-not-default", ""
	if err := c.Validate(); err == nil {
		t.Fatal("prod must not accept self-minted HMAC tokens as the only identity: subject and chain would be unattested")
	}
	c.OIDCJWKSURL = "https://idp/jwks"
	if err := c.Validate(); err != nil {
		t.Fatalf("prod with OIDC rejected: %v", err)
	}
}

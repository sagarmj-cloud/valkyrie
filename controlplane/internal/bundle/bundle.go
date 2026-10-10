// SPDX-License-Identifier: LicenseRef-Valkyrie-Enterprise
// Copyright (c) 2026 Sagar Jadhav

// Package bundle builds the OPA policy bundle the sidecars download:
//
//	/.manifest           revision + roots
//	/.signatures.json    JWT over the file digests (OPA verifies with the configured key)
//	/data.json           policy data: roles, tool tiers, limits, static data (menu, pii_redact…)
//	/<policy>.rego       the Rego files from the policy directory
//
// Roles and tool tiers come from the control plane's store; everything else
// comes from the checked-in data.json so policy authors keep one place for
// static facts. OPA's bundle verification (HS256 here; RSA in prod via
// signing keys in the OPA config) means a tampered bundle is rejected.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"valkyrie/controlplane/internal/store"
)

type Builder struct {
	PolicyDir  string // directory with *.rego and data.json
	SigningKey []byte
	KeyID      string
}

type Built struct {
	Bytes    []byte
	Revision string
	ETag     string
}

func (b *Builder) Build(st *store.Store) (Built, error) {
	// --- data.json: static data merged with control-plane facts
	data := map[string]any{}
	if raw, err := os.ReadFile(filepath.Join(b.PolicyDir, "data.json")); err == nil {
		// UseNumber keeps literals like 16.00 intact: OPA's signature hasher
		// canonicalises JSON by walking the parsed value and re-encoding each
		// primitive, so the digest depends on the exact number text.
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&data); err != nil {
			return Built{}, fmt.Errorf("bundle: data.json: %w", err)
		}
	}
	roles := map[string]any{}
	for name, r := range st.Roles() {
		roles[name] = map[string]any{"tools": r.Tools, "max_tier": r.MaxTier}
	}
	if len(roles) > 0 {
		data["roles"] = roles
	}
	tiers := map[string]any{}
	for _, m := range st.Tools() {
		if m.State == "active" {
			tiers[m.Name] = m.RiskTier
		}
	}
	data["tool_tiers"] = tiers
	data["registry_revision"] = st.Revision()
	// Emit the canonical form OPA hashes: compact, keys sorted, no HTML
	// escaping, number literals preserved — and hash those same bytes.
	dataJSON := canonicalJSON(data)

	files := map[string][]byte{"data.json": dataJSON}
	entries, err := os.ReadDir(b.PolicyDir)
	if err != nil {
		return Built{}, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(b.PolicyDir, e.Name()))
		if err != nil {
			return Built{}, err
		}
		files[e.Name()] = raw
	}
	rev := fmt.Sprintf("r%d-%s", st.Revision(), time.Now().UTC().Format("20060102T150405Z"))
	manifest := canonicalJSON(map[string]any{"revision": rev, "roots": []string{""}})
	files[".manifest"] = manifest

	// --- signatures
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var sigFiles []map[string]any
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		sigFiles = append(sigFiles, map[string]any{"name": n, "hash": hex.EncodeToString(sum[:]), "algorithm": "SHA-256"})
	}
	claims := map[string]any{"files": sigFiles, "keyid": b.KeyID, "scope": "valkyrie"}
	token, err := signHS256(b.SigningKey, b.KeyID, claims)
	if err != nil {
		return Built{}, err
	}
	sigs, _ := json.Marshal(map[string]any{"signatures": []string{token}})
	files[".signatures.json"] = sigs

	// --- tar.gz, deterministic order, .signatures.json first (OPA requirement)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	order := append([]string{".signatures.json"}, names...)
	for _, n := range order {
		content := files[n]
		hdr := &tar.Header{Name: "/" + n, Mode: 0o644, Size: int64(len(content)), ModTime: time.Unix(0, 0)}
		if err := tw.WriteHeader(hdr); err != nil {
			return Built{}, err
		}
		if _, err := tw.Write(content); err != nil {
			return Built{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Built{}, err
	}
	if err := gz.Close(); err != nil {
		return Built{}, err
	}
	sum := sha256.Sum256(buf.Bytes())
	return Built{Bytes: buf.Bytes(), Revision: rev, ETag: `"` + hex.EncodeToString(sum[:8]) + `"`}, nil
}

func signHS256(key []byte, kid string, claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": kid})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hdr)
	p := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func canonicalJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

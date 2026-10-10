// SPDX-License-Identifier: LicenseRef-Valkyrie-Enterprise
// Copyright (c) 2026 Sagar Jadhav

// valkyriectl — operator CLI for the control plane.
//
//	valkyriectl server add <name> <url> [--runtime python|go|node|external]
//	valkyriectl publish <manifest.json|.yaml> [--skip-contract]
//	valkyriectl import-mcp <server-name> <url> --tier N --owner T --scope S [--prefix p] [--out dir] [--auth-env VAR]
//	valkyriectl role bind <role> --max-tier N [--can-delegate] <tool>...
//	valkyriectl tools [--all]
//	valkyriectl changes
//	valkyriectl deprecate <tool>
//
// Env: VALKYRIE_REGISTRYD (default http://127.0.0.1:8090), VALKYRIE_REGISTRY_ADMIN_TOKEN.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"valkyrie/controlplane/internal/mcpdiscover"
	"valkyrie/controlplane/internal/store"
)

var (
	base  = env("VALKYRIE_REGISTRYD", "http://127.0.0.1:8090")
	token = env("VALKYRIE_REGISTRY_ADMIN_TOKEN", "")
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = cmdServer(os.Args[2:])
	case "publish":
		err = cmdPublish(os.Args[2:])
	case "import-mcp":
		err = cmdImport(os.Args[2:])
	case "role":
		err = cmdRole(os.Args[2:])
	case "tools":
		err = cmdTools(os.Args[2:])
	case "changes":
		err = cmdChanges()
	case "deprecate":
		err = call("DELETE", "/v1/tools/"+os.Args[2], nil, nil)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, strings.TrimSpace(`
valkyriectl — Valkyrie control plane CLI
  server add <name> <url> [--runtime R] [--owner O]
  publish <manifest.(json|yaml)> [--skip-contract]
  import-mcp <server> <url> --tier N --owner O --scope S [--prefix P] [--out DIR] [--auth-env VAR] [--classification C]
  role bind <role> --max-tier N [--can-delegate] <tool>...
  tools [--all]
  changes
  deprecate <tool>`))
	os.Exit(2)
}

func call(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if u := os.Getenv("USER"); u != "" {
		req.Header.Set("X-Actor", u)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var pretty bytes.Buffer
		if json.Indent(&pretty, b, "", "  ") == nil {
			return fmt.Errorf("registryd %d:\n%s", resp.StatusCode, pretty.String())
		}
		return fmt.Errorf("registryd %d: %s", resp.StatusCode, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	fmt.Println(string(bytes.TrimSpace(b)))
	return nil
}

func cmdServer(args []string) error {
	if len(args) < 3 || args[0] != "add" {
		usage()
	}
	fs := flag.NewFlagSet("server add", flag.ExitOnError)
	runtime := fs.String("runtime", "external", "runtime label")
	owner := fs.String("owner", "", "owning team")
	fs.Parse(args[3:])
	_ = runtime
	return call("PUT", "/v1/servers/"+args[1], store.Server{URL: args[2], Runtime: *runtime, Owner: *owner}, nil)
}

func loadManifest(path string) (store.Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return store.Manifest{}, err
	}
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		// Keep the CLI dependency-free: convert YAML with the Python helper the
		// repo already ships (same converter the registry build uses).
		cmd := exec.Command("python3", "-c", "import sys,yaml,json;print(json.dumps(yaml.safe_load(sys.stdin)))")
		cmd.Stdin = bytes.NewReader(raw)
		raw, err = cmd.Output()
		if err != nil {
			return store.Manifest{}, fmt.Errorf("yaml convert (needs python3 + pyyaml): %w", err)
		}
	}
	var m store.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return store.Manifest{}, err
	}
	return m, nil
}

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	skip := fs.Bool("skip-contract", false, "skip the live contract test")
	fs.Parse(args)
	if fs.NArg() < 1 {
		usage()
	}
	for _, p := range fs.Args() {
		m, err := loadManifest(p)
		if err != nil {
			return err
		}
		q := ""
		if *skip {
			q = "?skip_contract=1"
		}
		var out struct {
			Revision int64 `json:"revision"`
			Contract struct {
				Checked []string `json:"checked"`
			} `json:"contract"`
		}
		if err := call("PUT", "/v1/tools/"+m.Name+q, m, &out); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		fmt.Printf("published %s@%s (revision %d) — contract: %s\n", m.Name, m.Version, out.Revision, strings.Join(out.Contract.Checked, "; "))
	}
	return nil
}

// cmdImport discovers an existing MCP server's tools and writes one manifest
// per tool, namespaced as <server>.<tool>, with the server's own input schema.
// Risk tier, owner, scope and classification are set from flags — these are
// the facts the server cannot tell you and a human must decide.
func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import-mcp", flag.ExitOnError)
	tier := fs.Int("tier", 1, "risk tier for all imported tools (edit per tool afterwards)")
	owner := fs.String("owner", "", "owning team (required)")
	scope := fs.String("scope", "", "credential scope label (required)")
	prefix := fs.String("prefix", "", "manifest name prefix (default: server name)")
	outDir := fs.String("out", "registry/imported", "directory for generated manifests")
	authEnv := fs.String("auth-env", "", "env var holding the server's API key (sets credentials.type=static); empty = no auth")
	authHeader := fs.String("auth-header", "", "how to send the key: 'Authorization: Bearer' (default) or a header name like X-API-Key")
	class := fs.String("classification", "internal", "data_classification")
	runtime := fs.String("runtime", "external", "runtime label for the server")
	timeout := fs.Int("timeout-ms", 8000, "limits.timeout_ms")
	if len(args) < 2 {
		usage()
	}
	server, url := args[0], args[1]
	fs.Parse(args[2:])
	if *owner == "" || *scope == "" {
		usage()
	}
	if *prefix == "" {
		*prefix = server
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	auth := ""
	if *authEnv != "" {
		auth = os.Getenv(*authEnv)
	}
	tools, err := mcpdiscover.ListTools(ctx, url, auth, *authHeader)
	if err != nil {
		return fmt.Errorf("discover %s: %w", url, err)
	}
	if err := call("PUT", "/v1/servers/"+server, store.Server{URL: url, Runtime: *runtime, Owner: *owner}, nil); err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	creds := store.Credentials{Type: "none", Scope: *scope, TTLSeconds: 120}
	if *authEnv != "" {
		creds = store.Credentials{Type: "static", SecretRef: *authEnv, Scope: *scope, TTLSeconds: 120, Header: *authHeader}
	}
	for _, t := range tools {
		name := *prefix + "." + sanitize(t.Name)
		desc := t.Description
		if len(desc) < 10 {
			desc = "Imported from " + server + ": " + t.Name
		}
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object"}`)
		}
		m := store.Manifest{Name: name, Owner: *owner, Server: server, Version: "1.0.0", Description: desc, RiskTier: *tier,
			DataClassification: *class, InputSchema: schema, Credentials: creds,
			Limits: store.Limits{TimeoutMS: *timeout, RatePerMinute: 120, MaxResultKB: 256}, Idempotent: *tier <= 1, UpstreamName: t.Name}
		if *tier >= 3 {
			m.Approval = &store.Approval{RequiredAboveUSD: 0}
		}
		b, _ := json.MarshalIndent(m, "", "  ")
		p := filepath.Join(*outDir, name+".json")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s  (upstream tool %q, tier %d)\n", p, t.Name, *tier)
	}
	fmt.Printf("\n%d manifests drafted. Review tiers and descriptions, then:\n  valkyriectl publish %s/*.json\n  valkyriectl role bind <role> --max-tier %d %s.<tool> ...\n", len(tools), *outDir, *tier, *prefix)
	return nil
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == '-', r == ' ', r == '.':
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" || out[0] < 'a' || out[0] > 'z' {
		out = "t_" + out
	}
	return out
}

func cmdRole(args []string) error {
	if len(args) < 2 || args[0] != "bind" {
		usage()
	}
	fs := flag.NewFlagSet("role bind", flag.ExitOnError)
	maxTier := fs.Int("max-tier", 0, "maximum risk tier this role may call")
	canDelegate := fs.Bool("can-delegate", false, "allow this role to hand tasks to other agents (PEP 2)")
	fs.Parse(args[2:])
	if fs.NArg() == 0 {
		usage()
	}
	return call("PUT", "/v1/roles/"+args[1], store.Role{Tools: fs.Args(), MaxTier: *maxTier, CanDelegate: *canDelegate}, nil)
}

func cmdTools(args []string) error {
	fs := flag.NewFlagSet("tools", flag.ExitOnError)
	all := fs.Bool("all", false, "include deprecated")
	fs.Parse(args)
	q := ""
	if *all {
		q = "?state=all"
	}
	var out struct {
		Revision int64            `json:"revision"`
		Tools    []store.Manifest `json:"tools"`
	}
	if err := call("GET", "/v1/tools"+q, nil, &out); err != nil {
		return err
	}
	fmt.Printf("registry revision %d — %d tools\n", out.Revision, len(out.Tools))
	fmt.Printf("  %-32s %-8s %-5s %-12s %-14s %-9s %s\n", "TOOL", "VERSION", "TIER", "CLASS", "SERVER", "CREDS", "OWNER")
	for _, m := range out.Tools {
		ct := m.Credentials.Type
		if ct == "" {
			ct = "lease"
		}
		state := ""
		if m.State != "active" {
			state = " (" + m.State + ")"
		}
		fmt.Printf("  %-32s %-8s %-5d %-12s %-14s %-9s %s%s\n", m.Name, m.Version, m.RiskTier, m.DataClassification, m.Server, ct, m.Owner, state)
	}
	return nil
}

func cmdChanges() error {
	var out []store.Change
	if err := call("GET", "/v1/changes", nil, &out); err != nil {
		return err
	}
	for _, c := range out {
		fmt.Printf("  r%-5d %s  %-8s %-7s %-10s %s\n", c.Revision, c.Time.Format("2006-01-02 15:04:05"), c.Actor, c.Kind, c.Action, c.Summary)
	}
	return nil
}

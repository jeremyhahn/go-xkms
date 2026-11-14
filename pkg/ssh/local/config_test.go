// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package local_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/local"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestLoadConfig_PrecedenceAndIdentityFileAccumulation covers the core
// resolution rule: single-valued directives are first-file-wins, while
// IdentityFile accumulates across every loaded file, user file first.
func TestLoadConfig_PrecedenceAndIdentityFileAccumulation(t *testing.T) {
	dir := t.TempDir()
	userFile := filepath.Join(dir, "user_config")
	systemFile := filepath.Join(dir, "system_config")

	// The user file wins for HostName/User/Port even though the system
	// file also matches; both files contribute IdentityFile entries.
	writeFile(t, userFile, `
Host myhost
    HostName user.example.com
    User alice
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
`)
	writeFile(t, systemFile, `
Host myhost
    HostName system.example.com
    User bob
    Port 22022
    IdentityFile ~/.ssh/id_rsa
`)

	cfg, err := local.LoadConfig(userFile, systemFile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	hc := cfg.Lookup("myhost")
	if hc.HostName != "user.example.com" {
		t.Errorf("HostName = %q, want user file's value", hc.HostName)
	}
	if hc.User != "alice" {
		t.Errorf("User = %q, want user file's value", hc.User)
	}
	if hc.Port != 2222 {
		t.Errorf("Port = %d, want user file's value 2222", hc.Port)
	}
	if len(hc.IdentityFiles) != 2 {
		t.Fatalf("IdentityFiles = %v, want 2 entries", hc.IdentityFiles)
	}
	if !strings.HasSuffix(hc.IdentityFiles[0], "/.ssh/id_ed25519") {
		t.Errorf("IdentityFiles[0] = %q, want user file's entry first", hc.IdentityFiles[0])
	}
	if !strings.HasSuffix(hc.IdentityFiles[1], "/.ssh/id_rsa") {
		t.Errorf("IdentityFiles[1] = %q, want system file's entry second", hc.IdentityFiles[1])
	}
}

// TestLoadConfig_MissingFilesAreSkipped verifies an absent path is treated
// like OpenSSH treats it — as an empty config, not an error — regardless
// of whether other paths in the list exist. A host no loaded file
// configures falls back to its alias, port 22, and no user or identities.
func TestLoadConfig_MissingFilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	writeFile(t, present, "Host foo\n    Port 2200\n")

	cfg, err := local.LoadConfig(filepath.Join(dir, "does-not-exist"), present)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	hc := cfg.Lookup("foo")
	if hc.Port != 2200 {
		t.Errorf("Port = %d, want 2200 from the present file", hc.Port)
	}

	hc = cfg.Lookup("anything.example.com")
	want := &local.HostConfig{Alias: "anything.example.com", HostName: "anything.example.com", Port: 22}
	if hc.Alias != want.Alias || hc.HostName != want.HostName || hc.Port != want.Port {
		t.Fatalf("Lookup fallback = %+v, want %+v", hc, want)
	}
	if hc.User != "" {
		t.Errorf("User = %q, want empty", hc.User)
	}
	if len(hc.IdentityFiles) != 0 {
		t.Errorf("IdentityFiles = %v, want empty", hc.IdentityFiles)
	}
}

// TestLoadConfig_MalformedFile verifies a present-but-unparsable file
// surfaces *ConfigParseError rather than being silently skipped like a
// missing file.
func TestLoadConfig_MalformedFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad_config")
	// "Match Exec" is explicitly rejected by the parser (arbitrary command
	// execution from an untrusted config file).
	writeFile(t, bad, "Match exec true\n    HostName wat.example.com\n")

	_, err := local.LoadConfig(bad)
	var parseErr *local.ConfigParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *ConfigParseError, got %T: %v", err, err)
	}
	if parseErr.Path != bad {
		t.Errorf("ConfigParseError.Path = %q, want %q", parseErr.Path, bad)
	}
	if !strings.Contains(parseErr.Error(), bad) {
		t.Errorf("Error() missing path: %q", parseErr.Error())
	}
}

// TestLoadConfig_Include exercises the ssh_config(5) Include directive
// using an absolute include path (the one form the underlying parser
// resolves without touching the real $HOME — its relative-Include
// resolution goes through the process's real home directory / /etc/ssh
// and is not independently injectable, so it is intentionally not
// exercised here).
func TestLoadConfig_Include(t *testing.T) {
	dir := t.TempDir()
	included := filepath.Join(dir, "included_config")
	writeFile(t, included, `
Host myhost
    Port 2200
    IdentityFile ~/.ssh/id_included
`)

	main := filepath.Join(dir, "main_config")
	writeFile(t, main, `
Include `+included+`

Host myhost
    HostName main.example.com
    IdentityFile ~/.ssh/id_ed25519
`)

	cfg, err := local.LoadConfig(main)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	hc := cfg.Lookup("myhost")
	if hc.Port != 2200 {
		t.Errorf("Port = %d, want 2200 from included file", hc.Port)
	}
	if hc.HostName != "main.example.com" {
		t.Errorf("HostName = %q, want main file's value", hc.HostName)
	}
	if len(hc.IdentityFiles) != 2 {
		t.Fatalf("IdentityFiles = %v, want 2 entries (included + main)", hc.IdentityFiles)
	}
	if !strings.HasSuffix(hc.IdentityFiles[0], "/.ssh/id_included") {
		t.Errorf("IdentityFiles[0] = %q, want included file's entry first", hc.IdentityFiles[0])
	}
	if !strings.HasSuffix(hc.IdentityFiles[1], "/.ssh/id_ed25519") {
		t.Errorf("IdentityFiles[1] = %q, want main file's entry second", hc.IdentityFiles[1])
	}
}

// TestAliases_FiltersWildcardsAndMatchBlocks verifies Aliases returns only
// literal Host patterns, in file-then-declaration order, deduplicated, and
// excludes wildcard patterns, negated patterns, and Match blocks.
func TestAliases_FiltersWildcardsAndMatchBlocks(t *testing.T) {
	dir := t.TempDir()
	userFile := filepath.Join(dir, "user_config")
	systemFile := filepath.Join(dir, "system_config")

	writeFile(t, userFile, `
Host alpha
    HostName alpha.example.com

Host *.internal !excluded.internal
    User bastion

Match host beta
    HostName beta.example.com

Host alpha beta
    Port 22
`)
	writeFile(t, systemFile, `
Host gamma
    HostName gamma.example.com

Host alpha
    Port 2201
`)

	cfg, err := local.LoadConfig(userFile, systemFile)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	got := cfg.Aliases()
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("Aliases = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Aliases = %v, want %v", got, want)
		}
	}
}

// TestLookupStrict covers both branches of LookupStrict: a configured
// alias resolves exactly like Lookup, and an unconfigured one returns
// *HostNotConfiguredError instead of a synthesized default.
func TestLookupStrict(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config")
	writeFile(t, f, "Host known\n    HostName known.example.com\n")

	cfg, err := local.LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	hc, err := cfg.LookupStrict("known")
	if err != nil {
		t.Fatalf("LookupStrict(known): %v", err)
	}
	if hc.HostName != "known.example.com" {
		t.Errorf("HostName = %q", hc.HostName)
	}

	_, err = cfg.LookupStrict("unknown.example.com")
	var notConfigured *local.HostNotConfiguredError
	if !errors.As(err, &notConfigured) {
		t.Fatalf("expected *HostNotConfiguredError, got %T: %v", err, err)
	}
	if notConfigured.Alias != "unknown.example.com" {
		t.Errorf("HostNotConfiguredError.Alias = %q", notConfigured.Alias)
	}
}

// TestLookup_InvalidPortIsTreatedAsUnset covers the "unparsable Port value
// does not fail the whole lookup" rule.
func TestLookup_InvalidPortIsTreatedAsUnset(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config")
	writeFile(t, f, "Host myhost\n    Port not-a-number\n")

	cfg, err := local.LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	hc := cfg.Lookup("myhost")
	if hc.Port != 22 {
		t.Errorf("Port = %d, want fallback default 22", hc.Port)
	}
}

// TestLookup_IdentityAgentNonePreservedVerbatim verifies the "none"
// sentinel is not token-expanded.
func TestLookup_IdentityAgentNonePreservedVerbatim(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "config")
	writeFile(t, f, "Host myhost\n    IdentityAgent none\n")

	cfg, err := local.LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	hc := cfg.Lookup("myhost")
	if hc.IdentityAgent != "none" {
		t.Errorf("IdentityAgent = %q, want \"none\" verbatim", hc.IdentityAgent)
	}
}

// TestDefaultConfigPaths verifies the two well-known OpenSSH locations are
// returned in priority order without touching either file.
func TestDefaultConfigPaths(t *testing.T) {
	paths := local.DefaultConfigPaths()
	if len(paths) != 2 {
		t.Fatalf("DefaultConfigPaths returned %d paths, want 2", len(paths))
	}
	if !strings.HasSuffix(paths[0], filepath.Join(".ssh", "config")) {
		t.Errorf("paths[0] = %q, want a .ssh/config suffix", paths[0])
	}
	if paths[1] != "/etc/ssh/ssh_config" {
		t.Errorf("paths[1] = %q, want /etc/ssh/ssh_config", paths[1])
	}
}

// TestLoadConfig_OpenFailureNotNotExist covers the branch where opening a
// present path fails for a reason other than "does not exist" — an
// embedded NUL byte makes the open syscall fail deterministically on any
// platform/user, without relying on filesystem permission semantics that
// behave differently when tests run as root.
func TestLoadConfig_OpenFailureNotNotExist(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "bad\x00name")

	_, err := local.LoadConfig(badPath)
	var parseErr *local.ConfigParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected *ConfigParseError, got %T: %v", err, err)
	}
}

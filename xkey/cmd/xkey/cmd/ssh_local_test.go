// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunSSHLocalHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	cfg := "Host cli-alias\n  HostName cli.example.com\n  User dave\n  Port 2201\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := &cobra.Command{RunE: runSSHLocalHosts}
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("runSSHLocalHosts: %v", err)
	}
	if !strings.Contains(out.String(), "cli-alias") || !strings.Contains(out.String(), "dave@cli.example.com") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestRunSSHLocalHosts_Empty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cmd := &cobra.Command{RunE: runSSHLocalHosts}
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("runSSHLocalHosts: %v", err)
	}
	if !strings.Contains(out.String(), "No ssh_config hosts found") {
		t.Fatalf("expected empty-list message, got: %s", out.String())
	}
}

func TestRunSSHLocalKeys_Empty(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("SSH_AUTH_SOCK", "")

	cmd := &cobra.Command{RunE: runSSHLocalKeys}
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("runSSHLocalKeys: %v", err)
	}
	if !strings.Contains(out.String(), "No local keys found") {
		t.Fatalf("expected empty-list message, got: %s", out.String())
	}
}

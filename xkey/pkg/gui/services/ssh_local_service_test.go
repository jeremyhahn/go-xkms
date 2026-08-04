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

package services

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestSSHLocal_ListConfigHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	cfg := "Host gui-test-alias\n  HostName gui.example.com\n  User carol\n  Port 2200\n"
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	svc := NewSSHLocalService()
	svc.SetLogger(slog.Default())

	hosts, err := svc.ListConfigHosts()
	if err != nil {
		t.Fatalf("ListConfigHosts: %v", err)
	}
	var found *SSHConfigHostEntry
	for i := range hosts {
		if hosts[i].Alias == "gui-test-alias" {
			found = &hosts[i]
		}
	}
	if found == nil {
		t.Fatalf("expected alias in %+v", hosts)
	}
	if found.Hostname != "gui.example.com" || found.User != "carol" || found.Port != 2200 {
		t.Fatalf("unexpected entry: %+v", found)
	}
}

func TestSSHLocal_ListConfigHosts_ParseError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "config"), []byte("Match exec true\n  HostName x\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	svc := NewSSHLocalService()
	if _, err := svc.ListConfigHosts(); err == nil {
		t.Fatal("expected error for malformed ssh_config")
	}
}

func TestSSHLocal_ListLocalKeys_Empty(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("SSH_AUTH_SOCK", "")

	svc := NewSSHLocalService()
	keys, err := svc.ListLocalKeys()
	if err != nil {
		t.Fatalf("ListLocalKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no keys, got %+v", keys)
	}
}

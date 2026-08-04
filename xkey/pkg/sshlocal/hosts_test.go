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

package sshlocal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeSSHConfig writes contents to $HOME/.ssh/config under a freshly
// t.Setenv'd HOME, so ListConfigHosts (which always consults the real
// DefaultLocalSSHConfigPaths()) resolves deterministically regardless of the
// host machine's own configuration.
func writeSSHConfig(t *testing.T, contents string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}
	path := filepath.Join(sshDir, "config")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return home
}

func TestListConfigHosts_ResolvesAlias(t *testing.T) {
	writeSSHConfig(t, "Host xkms-test-alias\n"+
		"  HostName real.example.com\n"+
		"  User bob\n"+
		"  Port 2222\n"+
		"  IdentityFile ~/.ssh/id_test\n")

	hosts, err := ListConfigHosts()
	if err != nil {
		t.Fatalf("ListConfigHosts: %v", err)
	}

	var found *ConfigHostEntry
	for i := range hosts {
		if hosts[i].Alias == "xkms-test-alias" {
			found = &hosts[i]
		}
	}
	if found == nil {
		t.Fatalf("expected alias %q in %+v", "xkms-test-alias", hosts)
	}
	if found.Hostname != "real.example.com" || found.User != "bob" || found.Port != 2222 {
		t.Fatalf("unexpected entry: %+v", found)
	}
	if len(found.IdentityFiles) != 1 || filepath.Base(found.IdentityFiles[0]) != "id_test" {
		t.Fatalf("unexpected identity files: %v", found.IdentityFiles)
	}
}

func TestListConfigHosts_NoConfigFile(t *testing.T) {
	// A HOME with no ~/.ssh at all — an absent config is not an error.
	t.Setenv("HOME", t.TempDir())

	if _, err := ListConfigHosts(); err != nil {
		t.Fatalf("expected no error with no ssh_config present, got %v", err)
	}
}

func TestListConfigHosts_MalformedConfig(t *testing.T) {
	// "Match exec" is explicitly rejected by the underlying parser (arbitrary
	// command execution from an untrusted config file), giving us a
	// deterministic parse failure to test the error path against.
	writeSSHConfig(t, "Match exec true\n  HostName wat.example.com\n")

	_, err := ListConfigHosts()
	var target *ConfigLoadError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigLoadError, got %T: %v", err, err)
	}
}

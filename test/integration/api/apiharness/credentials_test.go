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

package apiharness

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// credentialFiles writes stand-in suite CA, ceremony root and admin
// credential files and points the harness's environment at them.
func credentialFiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		caFileEnv:     "suite-ca",
		ceremonyCAEnv: "ceremony-root",
		adminCertEnv:  "admin-cert",
		adminKeyEnv:   "admin-key",
	}
	for env, body := range files {
		path := filepath.Join(dir, body+".pem")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(env, path)
	}
	t.Setenv(unifiedCAEnv, filepath.Join(dir, "absent", "ca-bundle.pem"))
	return dir
}

func TestWriteTrustBundle_HoldsSuiteCeremonyAndUnifiedCAs(t *testing.T) {
	dir := credentialFiles(t)

	path, err := writeTrustBundle()
	if err != nil {
		t.Fatalf("writeTrustBundle before unseal = %v, want nil", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "suite-ca") || !strings.Contains(string(got), "ceremony-root") {
		t.Fatalf("bundle = %q, want the suite CA and the ceremony root", got)
	}

	unified := filepath.Join(dir, "unified.pem")
	if err := os.WriteFile(unified, []byte("unified-ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(unifiedCAEnv, unified)
	path, err = writeTrustBundle()
	if err != nil {
		t.Fatalf("writeTrustBundle after unseal = %v, want nil", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "unified-ca") {
		t.Fatalf("bundle = %q, want the unified listener's CA once persisted", got)
	}
}

func TestWriteTrustBundle_MissingCeremonyRootFails(t *testing.T) {
	dir := credentialFiles(t)
	t.Setenv(ceremonyCAEnv, filepath.Join(dir, "missing.pem"))

	if _, err := writeTrustBundle(); !errors.Is(err, ErrAdminCredential) {
		t.Fatalf("writeTrustBundle = %v, want ErrAdminCredential", err)
	}
}

func TestClientTLSArgs_CarriesCAAndAdminCredential(t *testing.T) {
	credentialFiles(t)

	args, err := ClientTLSArgs()
	if err != nil {
		t.Fatalf("ClientTLSArgs = %v, want nil", err)
	}
	for _, flag := range []string{"--tls-ca", "--tls-cert", "--tls-key"} {
		i := slices.Index(args, flag)
		if i < 0 || i+1 >= len(args) || args[i+1] == "" {
			t.Fatalf("args = %q, want %s with a path", args, flag)
		}
	}
	if args[slices.Index(args, "--tls-cert")+1] != AdminCertFile() ||
		args[slices.Index(args, "--tls-key")+1] != AdminKeyFile() {
		t.Fatalf("args = %q, want the admin credential paths", args)
	}

	t.Setenv(adminKeyEnv, filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := ClientTLSArgs(); !errors.Is(err, ErrAdminCredential) {
		t.Fatalf("ClientTLSArgs without the key = %v, want ErrAdminCredential", err)
	}
}

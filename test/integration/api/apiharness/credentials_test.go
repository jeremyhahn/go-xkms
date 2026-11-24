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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
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

func TestTrustBundleFile_HoldsSuiteCeremonyAndUnifiedCAs(t *testing.T) {
	dir := credentialFiles(t)

	path, err := TrustBundleFile()
	if err != nil {
		t.Fatalf("TrustBundleFile before unseal = %v, want nil", err)
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
	path, err = TrustBundleFile()
	if err != nil {
		t.Fatalf("TrustBundleFile after unseal = %v, want nil", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "unified-ca") {
		t.Fatalf("bundle = %q, want the unified listener's CA once persisted", got)
	}
}

func TestTrustBundleFile_MissingCeremonyRootFails(t *testing.T) {
	dir := credentialFiles(t)
	t.Setenv(ceremonyCAEnv, filepath.Join(dir, "missing.pem"))

	if _, err := TrustBundleFile(); !errors.Is(err, ErrAdminCredential) {
		t.Fatalf("TrustBundleFile = %v, want ErrAdminCredential", err)
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

// writeSelfSigned writes a self-signed ECDSA certificate and key as PEM.
func writeSelfSigned(t *testing.T, certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "apiharness-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClientTLSConfig_TrustsBundleAndPresentsAdminCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "admin-cert.pem"), filepath.Join(dir, "admin-key.pem")
	writeSelfSigned(t, cert, key)
	t.Setenv(caFileEnv, cert)
	t.Setenv(ceremonyCAEnv, cert)
	t.Setenv(unifiedCAEnv, filepath.Join(dir, "absent", "ca-bundle.pem"))
	t.Setenv(adminCertEnv, cert)
	t.Setenv(adminKeyEnv, key)

	cfg, err := ClientTLSConfig()
	if err != nil {
		t.Fatalf("ClientTLSConfig = %v, want nil", err)
	}
	if cfg.RootCAs == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("config = %+v, want a root pool and one client certificate", cfg)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("ClientTLSConfig must verify the server")
	}

	t.Setenv(adminKeyEnv, filepath.Join(dir, "missing.pem"))
	if _, err := ClientTLSConfig(); !errors.Is(err, ErrAdminCredential) {
		t.Fatalf("ClientTLSConfig without the key = %v, want ErrAdminCredential", err)
	}
	t.Setenv(adminKeyEnv, key)
	t.Setenv(ceremonyCAEnv, filepath.Join(dir, "missing-root.pem"))
	if _, err := ClientTLSConfig(); !errors.Is(err, ErrAdminCredential) {
		t.Fatalf("ClientTLSConfig without the ceremony root = %v, want ErrAdminCredential", err)
	}
}

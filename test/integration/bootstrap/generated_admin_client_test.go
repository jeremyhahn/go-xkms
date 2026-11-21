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

package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// generateTestCerts runs the bootstrap suite's generator into a temp dir
// and returns the cert dir and config file it wrote.
func generateTestCerts(t *testing.T) (certDir, configFile string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not available")
	}
	dir := t.TempDir()
	certDir = filepath.Join(dir, "certs")
	configFile = filepath.Join(dir, "xkmsd.yaml")
	cmd := exec.Command("sh", filepath.Join("scripts", "generate-test-certs.sh"))
	cmd.Env = append(os.Environ(),
		"CERT_DIR="+certDir,
		"TEST_DATA_DIR="+filepath.Join(dir, "data"),
		"CONFIG_FILE="+configFile,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate-test-certs.sh: %v\n%s", err, out)
	}
	return certDir, configFile
}

// TestGeneratedAdminClientCredential checks that the generator writes the
// administrator client credential the suite presents on the admin mTLS
// routes (/api/v1/bootstrap/keys): a key pair whose certificate chains to
// the generated CA for client authentication, and a config whose TLS
// listener trusts that CA and asks for a client certificate.
func TestGeneratedAdminClientCredential(t *testing.T) {
	certDir, configFile := generateTestCerts(t)

	certFile := filepath.Join(certDir, "admin-client.crt")
	keyFile := filepath.Join(certDir, "admin-client.key")
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("admin client credential: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse admin client certificate: %v", err)
	}

	caPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca.crt holds no certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("admin client certificate does not chain to the test CA for clientAuth: %v", err)
	}

	for k, v := range composeServerEnv {
		t.Setenv(k, v)
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("config.Load(generated xkmsd.yaml): %v", err)
	}
	if cfg.TLS.CAFile != filepath.Join(certDir, "ca.crt") {
		t.Fatalf("tls.ca_file = %q, want the generated CA %q", cfg.TLS.CAFile, filepath.Join(certDir, "ca.crt"))
	}
	switch cfg.TLS.ClientAuth {
	case "request", "require", "verify", "require_and_verify":
	default:
		t.Fatalf("tls.client_auth = %q: the listener never asks for the admin client certificate", cfg.TLS.ClientAuth)
	}
	if !cfg.Auth.Enabled || !cfg.Auth.MTLS {
		t.Fatalf("auth enabled=%v mtls=%v: the admin client certificate authenticates nothing", cfg.Auth.Enabled, cfg.Auth.MTLS)
	}
}

// TestGeneratedConfigServerCanBindItsHost checks the generated config does
// not make xkmsd refuse to start on its own listen address: a sealed barrier
// (the passphrase default) serves the unauthenticated sealed window, which
// xkmsd refuses to bind on a non-loopback host unless the config opts in.
// That refusal is what made the xkms-server container exit (1) at start.
func TestGeneratedConfigServerCanBindItsHost(t *testing.T) {
	_, configFile := generateTestCerts(t)
	for k, v := range composeServerEnv {
		t.Setenv(k, v)
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("config.Load(generated xkmsd.yaml): %v", err)
	}
	loopback := cfg.Server.Host == "127.0.0.1" || cfg.Server.Host == "::1" || cfg.Server.Host == "localhost"
	unsealedAtBoot := cfg.Barrier.Strategy == "none"
	if !loopback && !unsealedAtBoot && !cfg.Barrier.SealedWindowAllowRemote {
		t.Fatalf("server.host %q with barrier.strategy %q: xkmsd refuses to bind the sealed window", cfg.Server.Host, cfg.Barrier.Strategy)
	}
}

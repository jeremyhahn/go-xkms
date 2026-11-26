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

package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// readPair parses the PEM certificate and EC private key run wrote.
func readPair(t *testing.T, certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatalf("%s has no PEM block", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatalf("%s has no PEM block", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	return cert, key
}

// TestRunCA covers the -ca mode the acme-tpm suite uses to generate its
// software-TPM EK root at test time (#1993): the certificate is a
// self-signed CA, its public key is the generated key's, and every run
// generates a new key.
func TestRunCA(t *testing.T) {
	dir := t.TempDir()
	var keys []*ecdsa.PrivateKey
	for i, name := range []string{"first", "second"} {
		certPath := filepath.Join(dir, name, "ek-root.crt")
		keyPath := filepath.Join(dir, name, "ek-root.key")
		if err := run(certPath, keyPath, "swtpm Test EK CA", 1, true); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		cert, key := readPair(t, certPath, keyPath)

		if !cert.BasicConstraintsValid || !cert.IsCA {
			t.Fatalf("run %d: certificate is not a CA (BasicConstraintsValid=%v IsCA=%v)",
				i, cert.BasicConstraintsValid, cert.IsCA)
		}
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			t.Fatalf("run %d: certificate KeyUsage %v lacks CertSign", i, cert.KeyUsage)
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			t.Fatalf("run %d: certificate is not self-signed: %v", i, err)
		}
		if !key.PublicKey.Equal(cert.PublicKey) {
			t.Fatalf("run %d: certificate public key does not match the generated key", i)
		}
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("run %d: stat key: %v", i, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("run %d: key mode %o, want 600", i, perm)
		}
		keys = append(keys, key)
	}
	if keys[0].Equal(keys[1]) {
		t.Fatal("two runs generated the same key")
	}
}

// TestRunLeafIsNotCA pins the default mode: the ACME listener's TLS
// certificate stays a leaf.
func TestRunLeafIsNotCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "acme.crt")
	keyPath := filepath.Join(dir, "acme.key")
	if err := run(certPath, keyPath, "acme-server", 1, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	cert, _ := readPair(t, certPath, keyPath)
	if cert.IsCA {
		t.Fatal("leaf certificate is a CA")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("leaf ExtKeyUsage %v, want [ServerAuth]", cert.ExtKeyUsage)
	}
}

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
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ek-root", "ca.crt")
	keyPath := filepath.Join(dir, "ek-root", "ca.key")

	if err := writeCA(certPath, keyPath, "swtpm Test EK CA", 2); err != nil {
		t.Fatalf("writeCA: %v", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("cert file has no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Errorf("IsCA=%v BasicConstraintsValid=%v, want both true", cert.IsCA, cert.BasicConstraintsValid)
	}
	if want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign; cert.KeyUsage != want {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, want)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "swtpm-test" {
		t.Errorf("subject O = %v, want [swtpm-test]", cert.Subject.Organization)
	}
	if cert.Subject.CommonName != "swtpm Test EK CA" {
		t.Errorf("subject CN = %q, want %q", cert.Subject.CommonName, "swtpm Test EK CA")
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		t.Fatalf("key file has no EC PRIVATE KEY PEM block")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("key curve = %v, want P-256", key.Curve.Params().Name)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		t.Errorf("cert public key does not match the private key")
	}

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("cert does not self-verify: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("cert does not verify against itself as root: %v", err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("key file mode = %o, want 600", mode)
	}
}

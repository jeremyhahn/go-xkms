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

package pivcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

// newTestCA creates a self-signed CA certificate and returns the cert and key.
func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return cert, key
}

// newTestLeaf creates a leaf certificate signed by the given CA with ClientAuth EKU.
func newTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Client",
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	return cert
}

// TestVerifyChain_Valid verifies that a leaf certificate signed by a trusted CA passes chain verification.
func TestVerifyChain_Valid(t *testing.T) {
	ca, caKey := newTestCA(t)
	leaf := newTestLeaf(t, ca, caKey)

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	if err := VerifyChain(leaf, roots, nil); err != nil {
		t.Fatalf("expected valid chain to pass, got error: %v", err)
	}
}

// TestVerifyChain_UntrustedRoot verifies that a leaf signed by an untrusted CA is rejected.
func TestVerifyChain_UntrustedRoot(t *testing.T) {
	// Create two separate CAs; sign leaf with ca1 but trust only ca2.
	ca1, ca1Key := newTestCA(t)
	ca2, _ := newTestCA(t)

	leaf := newTestLeaf(t, ca1, ca1Key)

	roots := x509.NewCertPool()
	roots.AddCert(ca2) // ca1 not trusted

	err := VerifyChain(leaf, roots, nil)
	if err == nil {
		t.Fatal("expected untrusted chain to fail, got nil error")
	}
}

// TestThumbprintSHA256 verifies that ThumbprintSHA256 returns a 64-character hex string
// and produces consistent output for the same certificate.
func TestThumbprintSHA256(t *testing.T) {
	ca, caKey := newTestCA(t)
	leaf := newTestLeaf(t, ca, caKey)

	thumb1 := ThumbprintSHA256(leaf)
	thumb2 := ThumbprintSHA256(leaf)

	if thumb1 != thumb2 {
		t.Fatalf("thumbprint not deterministic: %q != %q", thumb1, thumb2)
	}

	if len(thumb1) != 64 {
		t.Fatalf("expected 64-character hex thumbprint, got %d characters: %q", len(thumb1), thumb1)
	}

	if _, err := hex.DecodeString(thumb1); err != nil {
		t.Fatalf("thumbprint is not valid hex: %v", err)
	}
}

// TestVerifyChain_NilLeaf verifies that passing a nil leaf returns an error.
func TestVerifyChain_NilLeaf(t *testing.T) {
	roots := x509.NewCertPool()
	err := VerifyChain(nil, roots, nil)
	if err == nil {
		t.Fatal("expected error for nil leaf, got nil")
	}
}

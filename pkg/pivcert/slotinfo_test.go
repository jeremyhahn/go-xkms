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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// newTestCert creates a self-signed certificate with the given key.
func newTestCert(t *testing.T, pub, priv any) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(0x1234abcd),
		Subject:               pkix.Name{CommonName: "Slot Info", Organization: []string{"Test"}},
		Issuer:                pkix.Name{CommonName: "Slot Info"},
		NotBefore:             time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// TestNewSlotInfo_DescribesCertificate verifies the slot info mirrors the
// certificate it describes.
func TestNewSlotInfo_DescribesCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	cert := newTestCert(t, &key.PublicKey, key)

	storedAt := time.Date(2025, time.June, 1, 12, 0, 0, 0, time.UTC)
	info := NewSlotInfo(PIVSlotDigitalSignature, cert, storedAt)

	if info.Slot != PIVSlotDigitalSignature {
		t.Errorf("Slot = %q, want %q", info.Slot, PIVSlotDigitalSignature)
	}
	if info.Subject != cert.Subject.String() {
		t.Errorf("Subject = %q, want %q", info.Subject, cert.Subject.String())
	}
	if info.Issuer != cert.Issuer.String() {
		t.Errorf("Issuer = %q, want %q", info.Issuer, cert.Issuer.String())
	}
	if info.SerialNumber != "1234abcd" {
		t.Errorf("SerialNumber = %q, want 1234abcd", info.SerialNumber)
	}
	if info.NotBefore != cert.NotBefore.Format(time.RFC3339) {
		t.Errorf("NotBefore = %q, want %q", info.NotBefore, cert.NotBefore.Format(time.RFC3339))
	}
	if info.NotAfter != cert.NotAfter.Format(time.RFC3339) {
		t.Errorf("NotAfter = %q, want %q", info.NotAfter, cert.NotAfter.Format(time.RFC3339))
	}
	if info.Algorithm != "ECDSA" {
		t.Errorf("Algorithm = %q, want ECDSA", info.Algorithm)
	}
	if info.KeySize != 384 {
		t.Errorf("KeySize = %d, want 384", info.KeySize)
	}
	if info.Fingerprint != ThumbprintSHA256(cert) {
		t.Errorf("Fingerprint = %q, want %q", info.Fingerprint, ThumbprintSHA256(cert))
	}
	if !info.StoredAt.Equal(storedAt) {
		t.Errorf("StoredAt = %v, want %v", info.StoredAt, storedAt)
	}
}

// TestNewSlotInfo_NilCertificate verifies a missing certificate produces an
// empty description rather than a panic.
func TestNewSlotInfo_NilCertificate(t *testing.T) {
	storedAt := time.Date(2025, time.June, 1, 12, 0, 0, 0, time.UTC)
	info := NewSlotInfo(PIVSlotAuthentication, nil, storedAt)

	if info.Slot != PIVSlotAuthentication {
		t.Errorf("Slot = %q, want %q", info.Slot, PIVSlotAuthentication)
	}
	if info.Subject != "" || info.Fingerprint != "" || info.KeySize != 0 {
		t.Errorf("NewSlotInfo(nil) = %+v, want an empty description", info)
	}
	if !info.StoredAt.Equal(storedAt) {
		t.Errorf("StoredAt = %v, want %v", info.StoredAt, storedAt)
	}
}

// TestKeyAlgorithmAndSize covers each public key type PIV certificates carry.
func TestKeyAlgorithmAndSize(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	tests := []struct {
		name          string
		cert          *x509.Certificate
		wantAlgorithm string
		wantSize      int
	}{
		{"RSA", newTestCert(t, &rsaKey.PublicKey, rsaKey), "RSA", 2048},
		{"ECDSA", newTestCert(t, &ecKey.PublicKey, ecKey), "ECDSA", 256},
		{"Ed25519", newTestCert(t, edPub, edPriv), "Ed25519", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KeyAlgorithmName(tt.cert); got != tt.wantAlgorithm {
				t.Errorf("KeyAlgorithmName() = %q, want %q", got, tt.wantAlgorithm)
			}
			if got := KeySize(tt.cert); got != tt.wantSize {
				t.Errorf("KeySize() = %d, want %d", got, tt.wantSize)
			}
		})
	}
}

// TestKeyAlgorithmAndSize_Unrecognized verifies certificates without a usable
// public key report unknown rather than guessing.
func TestKeyAlgorithmAndSize_Unrecognized(t *testing.T) {
	tests := []struct {
		name string
		cert *x509.Certificate
	}{
		{"nil certificate", nil},
		{"no public key", &x509.Certificate{}},
		{"unknown algorithm", &x509.Certificate{PublicKeyAlgorithm: x509.PublicKeyAlgorithm(99)}},
		{"DSA placeholder", &x509.Certificate{PublicKeyAlgorithm: x509.DSA}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algorithm := KeyAlgorithmName(tt.cert)
			if tt.cert != nil && tt.cert.PublicKeyAlgorithm == x509.DSA {
				if algorithm != "DSA" {
					t.Errorf("KeyAlgorithmName() = %q, want DSA", algorithm)
				}
			} else if algorithm != "Unknown" {
				t.Errorf("KeyAlgorithmName() = %q, want Unknown", algorithm)
			}

			if size := KeySize(tt.cert); size != 0 {
				t.Errorf("KeySize() = %d, want 0", size)
			}
		})
	}
}

// TestKeySize_MalformedECDSAKey verifies an ECDSA key without curve parameters
// reports an unknown size instead of panicking.
func TestKeySize_MalformedECDSAKey(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          &ecdsa.PublicKey{},
	}

	if size := KeySize(cert); size != 0 {
		t.Errorf("KeySize() = %d, want 0", size)
	}
}

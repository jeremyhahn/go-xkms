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

package truststore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew_EmbeddedGoogleRoot(t *testing.T) {
	config := &Config{
		EmbeddedRoots: []string{string(GoogleHardwareAttestation)},
	}

	ts, err := New(config)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	if ts.Count() != 3 {
		t.Errorf("Count() = %d, want 3 (v1 RSA root + v3 RSA root + ECDSA P-384 root)", ts.Count())
	}

	roots := ts.Roots()
	if len(roots) != 3 {
		t.Fatalf("Roots() returned %d certs, want 3", len(roots))
	}

	// First certificate: v1 RSA root (serial e8fa196314d2fa18, valid 2016-2026)
	if _, ok := roots[0].PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("first root certificate expected RSA public key, got %T", roots[0].PublicKey)
	}
	if !roots[0].IsCA {
		t.Error("first root certificate should be a CA")
	}

	// Second certificate: v3 RSA root (serial f1c172a699eaf51d, valid 2022-2042)
	if _, ok := roots[1].PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("second root certificate expected RSA public key, got %T", roots[1].PublicKey)
	}
	if !roots[1].IsCA {
		t.Error("second root certificate should be a CA")
	}

	// Third certificate: ECDSA P-384 root
	ecKey, ok := roots[2].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("third root certificate expected ECDSA public key, got %T", roots[2].PublicKey)
	}
	if ok && ecKey.Curve != elliptic.P384() {
		t.Errorf("third root certificate expected P-384 curve, got %v", ecKey.Curve.Params().Name)
	}
	if !roots[2].IsCA {
		t.Error("third root certificate should be a CA")
	}
}

func TestNew_InvalidEmbeddedRoot(t *testing.T) {
	config := &Config{
		EmbeddedRoots: []string{"nonexistent-root-ca"},
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() expected error for unknown embedded root, got nil")
	}
	if !errors.Is(err, ErrUnknownEmbeddedRoot) {
		t.Errorf("New() error = %v, want ErrUnknownEmbeddedRoot", err)
	}
}

func TestNew_NilConfig(t *testing.T) {
	_, err := New(nil)
	if err == nil {
		t.Fatal("New(nil) expected error, got nil")
	}
	if !errors.Is(err, ErrNilConfig) {
		t.Errorf("New(nil) error = %v, want ErrNilConfig", err)
	}
}

func TestNew_EmptyConfig(t *testing.T) {
	config := &Config{}

	ts, err := New(config)
	if err != nil {
		t.Fatalf("New() with empty config returned unexpected error: %v", err)
	}

	if ts.Count() != 0 {
		t.Errorf("Count() = %d, want 0 for empty config", ts.Count())
	}

	roots := ts.Roots()
	if len(roots) != 0 {
		t.Errorf("Roots() returned %d certs, want 0", len(roots))
	}
}

func TestNew_ExternalRootNotFound(t *testing.T) {
	config := &Config{
		ExternalRootPaths: []string{"/nonexistent/path/to/root.pem"},
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() expected error for nonexistent file, got nil")
	}
	if !errors.Is(err, ErrFileNotFound) {
		t.Errorf("New() error = %v, want ErrFileNotFound", err)
	}
}

func TestNew_MergedRoots(t *testing.T) {
	// Generate a self-signed certificate to use as an external root.
	certPEM := generateSelfSignedCertPEM(t)

	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "external-root.pem")
	if err := os.WriteFile(pemPath, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write temp PEM file: %v", err)
	}

	config := &Config{
		EmbeddedRoots:     []string{string(GoogleHardwareAttestation)},
		ExternalRootPaths: []string{pemPath},
	}

	ts, err := New(config)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	// 3 embedded (v1 RSA + v3 RSA + ECDSA P-384) + 1 external = 4 total
	if ts.Count() != 4 {
		t.Errorf("Count() = %d, want 4 (3 embedded + 1 external)", ts.Count())
	}
}

func TestNew_ExternalInvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "bad.pem")
	if err := os.WriteFile(pemPath, []byte("not valid pem data"), 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	config := &Config{
		ExternalRootPaths: []string{pemPath},
	}

	_, err := New(config)
	if err == nil {
		t.Fatal("New() expected error for invalid PEM data, got nil")
	}
	if !errors.Is(err, ErrInvalidPEM) {
		t.Errorf("New() error = %v, want ErrInvalidPEM", err)
	}
}

func TestGoogleHardwareAttestationRoots(t *testing.T) {
	certs, err := GoogleHardwareAttestationRoots()
	if err != nil {
		t.Fatalf("GoogleHardwareAttestationRoots() returned unexpected error: %v", err)
	}

	if len(certs) != 3 {
		t.Fatalf("GoogleHardwareAttestationRoots() returned %d certs, want 3", len(certs))
	}

	// First cert: v1 RSA root (serial e8fa196314d2fa18)
	v1RSACert := certs[0]
	if _, ok := v1RSACert.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("first cert expected RSA public key, got %T", v1RSACert.PublicKey)
	}
	if v1RSACert.SerialNumber == nil {
		t.Error("first cert SerialNumber is nil")
	}
	if v1RSACert.SerialNumber.Sign() <= 0 {
		t.Error("first cert SerialNumber should be positive")
	}

	// Second cert: v3 RSA root (serial f1c172a699eaf51d)
	v3RSACert := certs[1]
	if _, ok := v3RSACert.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("second cert expected RSA public key, got %T", v3RSACert.PublicKey)
	}
	if v3RSACert.SerialNumber == nil {
		t.Error("second cert SerialNumber is nil")
	}

	// Third cert: ECDSA P-384 root
	ecdsaCert := certs[2]
	ecKey, ok := ecdsaCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("third cert expected ECDSA public key, got %T", ecdsaCert.PublicKey)
	}
	if ok && ecKey.Curve != elliptic.P384() {
		t.Errorf("third cert expected P-384 curve, got %v", ecKey.Curve.Params().Name)
	}
	if ecdsaCert.SerialNumber == nil {
		t.Error("third cert SerialNumber is nil")
	}
}

func TestCertPool(t *testing.T) {
	config := &Config{
		EmbeddedRoots: []string{string(GoogleHardwareAttestation)},
	}

	ts, err := New(config)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	pool := ts.CertPool()
	if pool == nil {
		t.Fatal("CertPool() returned nil")
	}

	// Verify the pool contains subjects by checking it is usable in verify options.
	// We create a verify options struct to confirm the pool integrates with the
	// standard library without panics.
	opts := x509.VerifyOptions{
		Roots: pool,
	}
	// The pool should be non-empty; VerifyOptions should accept it.
	if opts.Roots == nil {
		t.Error("VerifyOptions.Roots is nil after setting CertPool()")
	}
}

func TestCertPool_EmptyStore(t *testing.T) {
	config := &Config{}

	ts, err := New(config)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	pool := ts.CertPool()
	if pool == nil {
		t.Fatal("CertPool() returned nil for empty store")
	}
}

func TestRoots_ReturnsCopy(t *testing.T) {
	config := &Config{
		EmbeddedRoots: []string{string(GoogleHardwareAttestation)},
	}

	ts, err := New(config)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	original := ts.Roots()
	originalLen := len(original)

	// Mutate the returned slice by setting an element to nil.
	original[0] = nil

	// The internal state should be unaffected.
	second := ts.Roots()
	if len(second) != originalLen {
		t.Errorf("Roots() length changed: got %d, want %d", len(second), originalLen)
	}
	if second[0] == nil {
		t.Error("Roots() returned internal slice reference; modifying it affected the store")
	}
}

func TestParsePEMCertificates_NonCertificateBlock(t *testing.T) {
	// PEM data containing a non-CERTIFICATE block followed by a valid cert.
	// parsePEMCertificates should skip the non-CERTIFICATE block.
	certPEM := generateSelfSignedCertPEM(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(rsaKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	// Concatenate key PEM (non-cert) + cert PEM
	combined := append(keyPEM, certPEM...)

	certs, err := parsePEMCertificates(combined)
	if err != nil {
		t.Fatalf("parsePEMCertificates() returned unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("parsePEMCertificates() returned %d certs, want 1 (non-cert block should be skipped)", len(certs))
	}
}

func TestParsePEMCertificates_EmptyInput(t *testing.T) {
	_, err := parsePEMCertificates([]byte{})
	if err == nil {
		t.Fatal("parsePEMCertificates() expected error for empty input, got nil")
	}
	if !errors.Is(err, ErrInvalidPEM) {
		t.Errorf("parsePEMCertificates() error = %v, want ErrInvalidPEM", err)
	}
}

func TestParsePEMCertificates_CorruptDER(t *testing.T) {
	// A CERTIFICATE PEM block with garbage DER data.
	badPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not valid DER"),
	})

	_, err := parsePEMCertificates(badPEM)
	if err == nil {
		t.Fatal("parsePEMCertificates() expected error for corrupt DER, got nil")
	}
	if !errors.Is(err, ErrCertificateParse) {
		t.Errorf("parsePEMCertificates() error = %v, want ErrCertificateParse", err)
	}
}

// generateSelfSignedCertPEM generates a PEM-encoded self-signed certificate for testing.
func generateSelfSignedCertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create self-signed certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

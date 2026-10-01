// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ca

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// =============================================================================
// Test fixtures: a manufacturer-shaped EK trust chain built in software.
// =============================================================================

// signTestCert issues a certificate from template, signed by parent/parentKey
// (or self-signed when parent is nil), and returns the parsed result.
func signTestCert(t *testing.T, template, parent *x509.Certificate, signerKey *ecdsa.PrivateKey, subjectKey *ecdsa.PublicKey) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, subjectKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return parseDER(t, der)
}

// newTestEKRoot builds a self-signed root CA standing in for a TPM
// manufacturer's root certificate.
func newTestEKRoot(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := generateTestECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return signTestCert(t, template, nil, key, &key.PublicKey), key
}

// newTestEKIntermediate builds a manufacturer intermediate signed by parent.
func newTestEKIntermediate(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := generateTestECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return signTestCert(t, template, parent, parentKey, &key.PublicKey), key
}

// ekLeafOptions customizes newTestEKLeaf.
type ekLeafOptions struct {
	extKeyUsageAny bool
	tcgEKU         bool
	expired        bool
	authorityKeyID []byte
}

// newTestEKLeaf builds an endorsement key certificate signed by parent,
// carrying the EKU configuration opts requests.
func newTestEKLeaf(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, opts ekLeafOptions) *x509.Certificate {
	t.Helper()
	key := generateTestECDSAKey(t)
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(time.Hour)
	if opts.expired {
		notBefore = time.Now().Add(-48 * time.Hour)
		notAfter = time.Now().Add(-24 * time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(3),
		Subject:        pkix.Name{CommonName: cn},
		AuthorityKeyId: opts.authorityKeyID,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       x509.KeyUsageKeyEncipherment,
	}
	if opts.extKeyUsageAny {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if opts.tcgEKU {
		template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{OIDTCGKpEKCertificate}
	}
	return signTestCert(t, template, parent, parentKey, &key.PublicKey)
}

// writePEMBundle writes certs PEM-encoded to a new file under t.TempDir()
// and returns its path.
func writePEMBundle(t *testing.T, name string, certs ...*x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	var buf []byte
	for _, cert := range certs {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write pem bundle %s: %v", path, err)
	}
	return path
}

// trustAnchorsFile builds a TCGConfig trusting the certificates in a single
// PEM file.
func trustAnchorsFile(t *testing.T, certs ...*x509.Certificate) *TCGConfig {
	t.Helper()
	path := writePEMBundle(t, "anchors.pem", certs...)
	return &TCGConfig{TrustAnchors: &truststore.Config{ExternalRootPaths: []string{path}}}
}

// =============================================================================
// TCGConfig.ekRootPool
// =============================================================================

func TestEkRootPool_NilConfig(t *testing.T) {
	var cfg *TCGConfig
	_, err := cfg.ekRootPool()
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestEkRootPool_NilTrustAnchors(t *testing.T) {
	cfg := &TCGConfig{}
	_, err := cfg.ekRootPool()
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestEkRootPool_EmptyTrustAnchors(t *testing.T) {
	cfg := &TCGConfig{TrustAnchors: &truststore.Config{}}
	_, err := cfg.ekRootPool()
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestEkRootPool_FromFile(t *testing.T) {
	root, _ := newTestEKRoot(t, "Root")
	cfg := trustAnchorsFile(t, root)

	pool, err := cfg.ekRootPool()
	if err != nil {
		t.Fatalf("ekRootPool() error: %v", err)
	}
	if pool == nil {
		t.Fatal("ekRootPool() returned nil pool")
	}
	if len(pool.Subjects()) != 1 { //nolint:staticcheck // test-only introspection
		t.Errorf("pool has %d entries, want 1", len(pool.Subjects())) //nolint:staticcheck // test-only introspection
	}
}

func TestEkRootPool_ConcatenatedIntermediateBothUsable(t *testing.T) {
	// A manufacturer's root and intermediate concatenated into one file both
	// land in the pool -- x509.CertPool draws no distinction between a
	// self-signed and a non-self-signed entry.
	root, rootKey := newTestEKRoot(t, "Root")
	intermediate, _ := newTestEKIntermediate(t, "Intermediate", root, rootKey)
	cfg := trustAnchorsFile(t, root, intermediate)

	pool, err := cfg.ekRootPool()
	if err != nil {
		t.Fatalf("ekRootPool() error: %v", err)
	}
	if len(pool.Subjects()) != 2 { //nolint:staticcheck // test-only introspection
		t.Errorf("pool has %d entries, want 2", len(pool.Subjects())) //nolint:staticcheck // test-only introspection
	}
}

func TestEkRootPool_MultipleFilesCombine(t *testing.T) {
	root1, _ := newTestEKRoot(t, "Root1")
	root2, _ := newTestEKRoot(t, "Root2")
	cfg := &TCGConfig{TrustAnchors: &truststore.Config{
		ExternalRootPaths: []string{
			writePEMBundle(t, "root1.pem", root1),
			writePEMBundle(t, "root2.pem", root2),
		},
	}}

	pool, err := cfg.ekRootPool()
	if err != nil {
		t.Fatalf("ekRootPool() error: %v", err)
	}
	if len(pool.Subjects()) != 2 { //nolint:staticcheck // test-only introspection
		t.Errorf("pool has %d entries, want 2", len(pool.Subjects())) //nolint:staticcheck // test-only introspection
	}
}

func TestEkRootPool_MissingFile(t *testing.T) {
	cfg := &TCGConfig{TrustAnchors: &truststore.Config{
		ExternalRootPaths: []string{filepath.Join(t.TempDir(), "does-not-exist.pem")},
	}}
	_, err := cfg.ekRootPool()
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestEkRootPool_GarbagePEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(path, []byte("not pem data"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := &TCGConfig{TrustAnchors: &truststore.Config{ExternalRootPaths: []string{path}}}
	_, err := cfg.ekRootPool()
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestEkRootPool_UnknownEmbeddedRoot(t *testing.T) {
	cfg := &TCGConfig{TrustAnchors: &truststore.Config{EmbeddedRoots: []string{"does-not-exist"}}}
	_, err := cfg.ekRootPool()
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

// =============================================================================
// parseEKCertificateChain
// =============================================================================

func TestParseEKCertificateChain_DER(t *testing.T) {
	root, _ := newTestEKRoot(t, "Root")
	leaf, _, err := parseEKCertificateChain(root.Raw)
	if err != nil {
		t.Fatalf("parseEKCertificateChain() error: %v", err)
	}
	if leaf.Subject.CommonName != "Root" {
		t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, "Root")
	}
}

func TestParseEKCertificateChain_PEMWithIntermediate(t *testing.T) {
	root, rootKey := newTestEKRoot(t, "Root")
	intermediate, intKey := newTestEKIntermediate(t, "Intermediate", root, rootKey)
	leafCert := newTestEKLeaf(t, "EK", intermediate, intKey, ekLeafOptions{extKeyUsageAny: true})

	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw})...,
	)

	leaf, intermediates, err := parseEKCertificateChain(bundle)
	if err != nil {
		t.Fatalf("parseEKCertificateChain() error: %v", err)
	}
	if leaf.Subject.CommonName != "EK" {
		t.Errorf("leaf CommonName = %q, want %q", leaf.Subject.CommonName, "EK")
	}
	if len(intermediates) != 1 || intermediates[0].Subject.CommonName != "Intermediate" {
		t.Fatalf("intermediates = %v, want [Intermediate]", intermediates)
	}
}

func TestParseEKCertificateChain_Empty(t *testing.T) {
	_, _, err := parseEKCertificateChain(nil)
	if !errors.Is(err, ErrTCGInvalidEKCert) {
		t.Fatalf("error = %v, want %v", err, ErrTCGInvalidEKCert)
	}
}

func TestParseEKCertificateChain_GarbageDER(t *testing.T) {
	_, _, err := parseEKCertificateChain([]byte("not a certificate"))
	if !errors.Is(err, ErrTCGInvalidEKCert) {
		t.Fatalf("error = %v, want %v", err, ErrTCGInvalidEKCert)
	}
}

func TestParseEKCertificateChain_GarbagePEMIntermediate(t *testing.T) {
	root, _ := newTestEKRoot(t, "Root")
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})...,
	)
	_, _, err := parseEKCertificateChain(bundle)
	if !errors.Is(err, ErrTCGInvalidEKCert) {
		t.Fatalf("error = %v, want %v", err, ErrTCGInvalidEKCert)
	}
}

// =============================================================================
// (*CA).verifyEKCertificateChain
// =============================================================================

func TestVerifyEKCertificateChain_TrustedRootPasses(t *testing.T) {
	root, rootKey := newTestEKRoot(t, "Root")
	leaf := newTestEKLeaf(t, "EK", root, rootKey, ekLeafOptions{extKeyUsageAny: true})

	ca := &CA{config: &MultiIdentityCAConfig{TCGConfig: trustAnchorsFile(t, root)}}
	if err := ca.verifyEKCertificateChain(leaf, nil); err != nil {
		t.Fatalf("verifyEKCertificateChain() error: %v", err)
	}
}

func TestVerifyEKCertificateChain_TrustedIntermediateConfiguredPasses(t *testing.T) {
	root, rootKey := newTestEKRoot(t, "Root")
	intermediate, intKey := newTestEKIntermediate(t, "Intermediate", root, rootKey)
	leaf := newTestEKLeaf(t, "EK", intermediate, intKey, ekLeafOptions{extKeyUsageAny: true})

	ca := &CA{config: &MultiIdentityCAConfig{TCGConfig: trustAnchorsFile(t, root, intermediate)}}
	if err := ca.verifyEKCertificateChain(leaf, nil); err != nil {
		t.Fatalf("verifyEKCertificateChain() error: %v", err)
	}
}

func TestVerifyEKCertificateChain_RequestSuppliedIntermediatePasses(t *testing.T) {
	root, rootKey := newTestEKRoot(t, "Root")
	intermediate, intKey := newTestEKIntermediate(t, "Intermediate", root, rootKey)
	leaf := newTestEKLeaf(t, "EK", intermediate, intKey, ekLeafOptions{extKeyUsageAny: true})

	// Only the root is configured; the intermediate arrives with the
	// request, as a device might concatenate it after the leaf.
	ca := &CA{config: &MultiIdentityCAConfig{TCGConfig: trustAnchorsFile(t, root)}}
	if err := ca.verifyEKCertificateChain(leaf, []*x509.Certificate{intermediate}); err != nil {
		t.Fatalf("verifyEKCertificateChain() error: %v", err)
	}
}

func TestVerifyEKCertificateChain_UnknownRootRefused(t *testing.T) {
	trustedRoot, _ := newTestEKRoot(t, "Trusted")
	unrelatedRoot, unrelatedKey := newTestEKRoot(t, "Unrelated")
	leaf := newTestEKLeaf(t, "EK", unrelatedRoot, unrelatedKey, ekLeafOptions{extKeyUsageAny: true})

	ca := &CA{config: &MultiIdentityCAConfig{TCGConfig: trustAnchorsFile(t, trustedRoot)}}

	err := ca.verifyEKCertificateChain(leaf, nil)
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestVerifyEKCertificateChain_MissingEKURefused(t *testing.T) {
	root, rootKey := newTestEKRoot(t, "Root")
	leaf := newTestEKLeaf(t, "EK", root, rootKey, ekLeafOptions{}) // no EKU at all

	ca := &CA{config: &MultiIdentityCAConfig{TCGConfig: trustAnchorsFile(t, root)}}

	err := ca.verifyEKCertificateChain(leaf, nil)
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestVerifyEKCertificateChain_ExpiredRefused(t *testing.T) {
	root, rootKey := newTestEKRoot(t, "Root")
	leaf := newTestEKLeaf(t, "EK", root, rootKey, ekLeafOptions{extKeyUsageAny: true, expired: true})

	ca := &CA{config: &MultiIdentityCAConfig{TCGConfig: trustAnchorsFile(t, root)}}

	err := ca.verifyEKCertificateChain(leaf, nil)
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestVerifyEKCertificateChain_NoAnchorsConfiguredRefused(t *testing.T) {
	root, rootKey := newTestEKRoot(t, "Root")
	leaf := newTestEKLeaf(t, "EK", root, rootKey, ekLeafOptions{extKeyUsageAny: true})

	// ca.config is nil entirely -- the common case for a CA that has never
	// been given TCG settings.
	ca := &CA{}
	err := ca.verifyEKCertificateChain(leaf, nil)
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}

	// ca.config set but TCGConfig nil.
	ca2 := &CA{config: &MultiIdentityCAConfig{}}
	err = ca2.verifyEKCertificateChain(leaf, nil)
	if !errors.Is(err, ErrTCGEKCertUntrusted) {
		t.Fatalf("error = %v, want %v", err, ErrTCGEKCertUntrusted)
	}
}

func TestVerifyEKCertificateChain_NilLeafRefused(t *testing.T) {
	ca := &CA{config: &MultiIdentityCAConfig{TCGConfig: &TCGConfig{TrustAnchors: &truststore.Config{ExternalRootPaths: []string{"unused"}}}}}
	err := ca.verifyEKCertificateChain(nil, nil)
	if !errors.Is(err, ErrTCGInvalidEKCert) {
		t.Fatalf("error = %v, want %v", err, ErrTCGInvalidEKCert)
	}
}

func TestVerifyEKCertificateChain_ErrorWrapsUnderlyingCause(t *testing.T) {
	trustedRoot, _ := newTestEKRoot(t, "Trusted")
	unrelatedRoot, unrelatedKey := newTestEKRoot(t, "Unrelated")
	leaf := newTestEKLeaf(t, "EK", unrelatedRoot, unrelatedKey, ekLeafOptions{extKeyUsageAny: true})

	ca := &CA{config: &MultiIdentityCAConfig{TCGConfig: trustAnchorsFile(t, trustedRoot)}}

	err := ca.verifyEKCertificateChain(leaf, nil)
	var joined *errs.Joined
	if !errors.As(err, &joined) {
		t.Fatalf("error = %v, want *errs.Joined wrapping the x509 chain error", err)
	}
	if joined.Cause == nil {
		t.Error("errs.Joined.Cause is nil, want the underlying x509 verify error")
	}
}

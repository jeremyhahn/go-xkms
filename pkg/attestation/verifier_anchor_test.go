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

package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// anchorChain is a generated attestation chain: a vendor root that acts as the
// trust anchor, a device attestation CA, and the leaf attestation certificate.
type anchorChain struct {
	root  *x509.Certificate
	inter *x509.Certificate
	leaf  *x509.Certificate
}

// leafFirst returns the chain in wire order, excluding the root.
func (c *anchorChain) leafFirst() []*x509.Certificate {
	return []*x509.Certificate{c.leaf, c.inter}
}

// leafFirstWithRoot returns the chain in wire order including the root.
func (c *anchorChain) leafFirstWithRoot() []*x509.Certificate {
	return []*x509.Certificate{c.leaf, c.inter, c.root}
}

func newAnchorChain(t *testing.T, name string, leafNotBefore, leafNotAfter time.Time) *anchorChain {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name + " Root CA"},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root := createAnchorCert(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: name + " Attestation CA"},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	inter := createAnchorCert(t, interTemplate, root, &interKey.PublicKey, rootKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: name + " Attestation Leaf"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leaf := createAnchorCert(t, leafTemplate, inter, &leafKey.PublicKey, interKey)

	return &anchorChain{root: root, inter: inter, leaf: leaf}
}

func newValidAnchorChain(t *testing.T, name string) *anchorChain {
	t.Helper()
	return newAnchorChain(t, name, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// createAnchorCert signs template with parent and returns the parsed
// certificate. signerKey is the issuer's private key; pub is the subject's
// public key.
func createAnchorCert(t *testing.T, template, parent *x509.Certificate, pub any, signerKey any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signerKey)
	if err != nil {
		t.Fatalf("create certificate %q: %v", template.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %q: %v", template.Subject.CommonName, err)
	}
	return cert
}

func TestVerifyChainAnchored_NoAnchorsFailsClosed(t *testing.T) {
	chain := newValidAnchorChain(t, "Vendor")
	v := NewVerifier(nil)

	err := v.VerifyChainAnchored(&AttestationStatement{
		Format:           "tpm2",
		CertificateChain: chain.leafFirstWithRoot(),
	}, &VerifyOptions{})

	if !errors.Is(err, ErrNoTrustAnchors) {
		t.Fatalf("expected ErrNoTrustAnchors, got %v", err)
	}
}

// TestVerifyChainAnchored_ForgedChainRejected is the core regression test: a
// fully self-consistent chain minted by an attacker must not verify against a
// verifier holding a different anchor.
func TestVerifyChainAnchored_ForgedChainRejected(t *testing.T) {
	genuine := newValidAnchorChain(t, "Vendor")
	forged := newValidAnchorChain(t, "Attacker")

	// The forged chain is internally consistent by construction.
	if err := forged.leaf.CheckSignatureFrom(forged.inter); err != nil {
		t.Fatalf("forged chain is not self-consistent: %v", err)
	}
	if err := forged.inter.CheckSignatureFrom(forged.root); err != nil {
		t.Fatalf("forged chain is not self-consistent: %v", err)
	}

	v := NewVerifier([]*x509.Certificate{genuine.root})

	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
	}{
		{"without forged root", forged.leafFirst()},
		{"with forged root appended", forged.leafFirstWithRoot()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := v.VerifyChainAnchored(&AttestationStatement{
				Format:           "yubikey-piv",
				CertificateChain: tc.chain,
			}, &VerifyOptions{})
			if !errors.Is(err, ErrChainNotAnchored) {
				t.Fatalf("expected ErrChainNotAnchored, got %v", err)
			}
		})
	}
}

func TestVerifyChainAnchored_TrustedChainAccepted(t *testing.T) {
	genuine := newValidAnchorChain(t, "Vendor")
	v := NewVerifier([]*x509.Certificate{genuine.root})

	for _, tc := range []struct {
		name  string
		chain []*x509.Certificate
	}{
		{"leaf and intermediate", genuine.leafFirst()},
		{"leaf, intermediate and root", genuine.leafFirstWithRoot()},
		{"anchor alone", []*x509.Certificate{genuine.root}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.VerifyChainAnchored(&AttestationStatement{
				Format:           "tpm2",
				CertificateChain: tc.chain,
			}, &VerifyOptions{}); err != nil {
				t.Fatalf("expected chain to verify, got %v", err)
			}
		})
	}
}

func TestVerifyChainAnchored_AnchorsFromOptions(t *testing.T) {
	genuine := newValidAnchorChain(t, "Vendor")
	v := NewVerifier(nil)

	if err := v.VerifyChainAnchored(&AttestationStatement{
		Format:           "tpm2",
		CertificateChain: genuine.leafFirst(),
	}, &VerifyOptions{TrustedRoots: []*x509.Certificate{genuine.root}}); err != nil {
		t.Fatalf("expected per-call anchors to be honored, got %v", err)
	}
}

func TestVerifyChainAnchored_ExpiredLeafRejected(t *testing.T) {
	expired := newAnchorChain(t, "Vendor",
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	v := NewVerifier([]*x509.Certificate{expired.root})

	err := v.VerifyChainAnchored(&AttestationStatement{
		Format:           "tpm2",
		CertificateChain: expired.leafFirst(),
	}, &VerifyOptions{})
	if !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("expected ErrCertificateExpired, got %v", err)
	}
}

func TestVerifyChainAnchored_EmptyChainRejected(t *testing.T) {
	genuine := newValidAnchorChain(t, "Vendor")
	v := NewVerifier([]*x509.Certificate{genuine.root})

	err := v.VerifyChainAnchored(&AttestationStatement{
		Format:           "tpm2",
		CertificateChain: nil,
	}, &VerifyOptions{})
	if !errors.Is(err, ErrEmptyCertificateChain) {
		t.Fatalf("expected ErrEmptyCertificateChain, got %v", err)
	}
}

func TestVerifyChainAnchored_NilStatementRejected(t *testing.T) {
	genuine := newValidAnchorChain(t, "Vendor")
	v := NewVerifier([]*x509.Certificate{genuine.root})

	if err := v.VerifyChainAnchored(nil, &VerifyOptions{}); !errors.Is(err, ErrNilStatement) {
		t.Fatalf("expected ErrNilStatement, got %v", err)
	}
	if err := v.VerifyChain(nil, &VerifyOptions{}); !errors.Is(err, ErrNilStatement) {
		t.Fatalf("expected ErrNilStatement, got %v", err)
	}
}

// TestVerifyChain_ConfiguredAnchorsAreEnforced asserts configured anchors are
// never accepted and then ignored: VerifyChain enforces them when present.
func TestVerifyChain_ConfiguredAnchorsAreEnforced(t *testing.T) {
	genuine := newValidAnchorChain(t, "Vendor")
	forged := newValidAnchorChain(t, "Attacker")
	v := NewVerifier([]*x509.Certificate{genuine.root})

	if err := v.VerifyChain(&AttestationStatement{
		Format:           "tpm2",
		CertificateChain: forged.leafFirstWithRoot(),
	}, &VerifyOptions{}); !errors.Is(err, ErrChainNotAnchored) {
		t.Fatalf("expected ErrChainNotAnchored, got %v", err)
	}

	if err := v.VerifyChain(&AttestationStatement{
		Format:           "tpm2",
		CertificateChain: genuine.leafFirst(),
	}, &VerifyOptions{}); err != nil {
		t.Fatalf("expected genuine chain to verify, got %v", err)
	}
}

func TestTrustAnchorCount(t *testing.T) {
	genuine := newValidAnchorChain(t, "Vendor")

	if got := NewVerifier(nil).TrustAnchorCount(); got != 0 {
		t.Fatalf("expected 0 anchors, got %d", got)
	}
	if got := NewVerifier([]*x509.Certificate{genuine.root, genuine.inter}).TrustAnchorCount(); got != 2 {
		t.Fatalf("expected 2 anchors, got %d", got)
	}
}

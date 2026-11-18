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

package attestation_test

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

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// snapshotTestRoot returns a self-signed CA certificate named cn.
func snapshotTestRoot(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		IsCA:                  true,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// shiftingLister answers its first read with roots and every later read
// with later (or laterErr): a store that changes between two reads.
type shiftingLister struct {
	roots    []*x509.Certificate
	laterErr error
	reads    int
}

func (s *shiftingLister) CertificatesByPurpose(truststore.CertPurpose) ([]*x509.Certificate, error) {
	s.reads++
	if s.reads == 1 {
		return s.roots, nil
	}
	return nil, s.laterErr
}

// TestVerifyChainAnchored_OneAnchorSnapshot: the store-backed anchors are
// read once per verification. A store that holds a root at the emptiness
// check and is empty (or fails) at the chain check must not let a
// self-signed chain the caller minted pass as structural-only.
func TestVerifyChainAnchored_OneAnchorSnapshot(t *testing.T) {
	storeErr := errors.New("store down")
	for _, tc := range []struct {
		name     string
		laterErr error
	}{
		{"empty on the second read", nil},
		{"error on the second read", storeErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lister := &shiftingLister{roots: []*x509.Certificate{snapshotTestRoot(t, "store root")}, laterErr: tc.laterErr}
			v := attestation.NewVerifier(nil,
				attestation.WithTrustStore(lister, nil),
				attestation.WithChainPurpose(truststore.PurposeTPMManufacturer))
			minted := snapshotTestRoot(t, "caller-minted root")
			stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{minted}}
			if err := v.VerifyChainAnchored(stmt, nil); err == nil {
				t.Fatal("a self-signed chain passed while the store changed between reads")
			}
		})
	}
}

// TestVerifyChainAnchored_StoreErrorIsReturned: a store that cannot answer
// refuses the chain with its error, not as a missing anchor.
func TestVerifyChainAnchored_StoreErrorIsReturned(t *testing.T) {
	storeErr := errors.New("store down")
	lister := &shiftingLister{laterErr: storeErr, reads: 1}
	v := attestation.NewVerifier(nil,
		attestation.WithTrustStore(lister, nil),
		attestation.WithChainPurpose(truststore.PurposeTPMManufacturer))
	stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{snapshotTestRoot(t, "minted")}}
	if err := v.VerifyChainAnchored(stmt, nil); !errors.Is(err, storeErr) {
		t.Fatalf("VerifyChainAnchored error = %v, want the store error", err)
	}
}

// A chain purpose that anchors nothing (the PurposeSynced quarantine) is
// refused before the store is read: a root a paired device pushed never
// anchors an attestation, even when the store lists it under that purpose.
func TestVerifyChainAnchored_QuarantinedPurposeRefused(t *testing.T) {
	synced := snapshotTestRoot(t, "synced root")
	lister := &shiftingLister{roots: []*x509.Certificate{synced}}
	v := attestation.NewVerifier(nil,
		attestation.WithTrustStore(lister, nil),
		attestation.WithChainPurpose(truststore.PurposeSynced))
	stmt := &attestation.AttestationStatement{Format: "tpm2", CertificateChain: []*x509.Certificate{synced}}
	if err := v.VerifyChainAnchored(stmt, nil); !errors.Is(err, truststore.ErrNotAnchorPurpose) {
		t.Fatalf("VerifyChainAnchored error = %v, want ErrNotAnchorPurpose", err)
	}
	if lister.reads != 0 {
		t.Fatalf("store read %d times, want 0 for a quarantined purpose", lister.reads)
	}
}

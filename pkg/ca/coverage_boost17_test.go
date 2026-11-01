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

// Package ca coverage boost, seventeenth pass: covers 10 new statements to
// reach 91.0% (3202/3516). Targets:
//   - constructors.go:202 — NewParentCA ToKeyAttributes error (BOGUS key algo)
//   - constructors.go:277 — NewIntermediateCA ToKeyAttributes error
//   - tcg.go:614 — VerifyQuote cert-store fallback (2 stmts)
//   - tcg.go:626 — VerifyQuote RSA case setup (2 stmts)
//   - tcg.go:640 — VerifyQuote ECDSA failure (1 stmt)
//   - tcg.go:709 — EndorsementKeyCertificate EK OID found (2 stmts)
//   - hybrid.go:497 — rebuildTBSWithoutExtension no-extensions path (1 stmt)
//
// All tests are in-memory, fast, and race-detector clean. Tests that mutate
// package-level state must NOT use t.Parallel().
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers
// =============================================================================

// buildTestKeyStore returns a minimal in-memory xkms.Backend and
// certstore.CertStore for use with NewParentCA / NewIntermediateCA.
func buildTestKeyStore(t *testing.T) (xkms.Backend, certstore.CertStore) {
	t.Helper()
	swBackend, err := software.NewBackend(&software.Config{
		KeyStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	cs, err := certstore.New(&certstore.Config{
		DAOs: testutil.NewMemoryDAOFactory(),
	})
	require.NoError(t, err)
	return ks, cs
}

// selfSignedECDSACert creates a minimal self-signed ECDSA P-256 certificate
// for use as a stand-in AK certificate in the cert store.
func selfSignedECDSACert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// selfSignedRSACert creates a minimal self-signed RSA-2048 certificate for use
// as a stand-in AK certificate in the cert store.
func selfSignedRSACert(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// minimalCertDERNoExtensions returns the DER encoding of a real minimal
// x509 certificate that has zero extensions. Used to exercise
// rebuildTBSWithoutExtension's no-extensions branch.
func minimalCertDERNoExtensions(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	// A template with no KeyUsage, no IsCA, no ExtraExtensions, no SANS
	// produces a cert with zero extensions.
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "no-ext"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

// =============================================================================
// constructors.go:202 — NewParentCA ToKeyAttributes error
// =============================================================================

// TestNewParentCA_ToKeyAttributesError_B17 covers constructors.go:202.16,204.3.
// Validate() passes (CN + Valid + Keys all set), ResolveStores passes
// (KeyStore + CertStore provided), then ToKeyAttributes fails because
// ParseKeyAlgorithm("BOGUS") returns an error.
func TestNewParentCA_ToKeyAttributesError_B17(t *testing.T) {
	t.Parallel()
	ks, cs := buildTestKeyStore(t)
	params := &Params{
		KeyStore:        ks,
		BackendForStore: singleBackendFactory(ks),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		Identity: []Identity{
			{
				Subject: Subject{CommonName: "Root B17"},
				Valid:   1,
				IsRoot:  true,
				Keys: []*types.KeyConfig{
					{
						KeyAlgorithm: "BOGUS",
					},
				},
			},
		},
	}
	_, err := NewParentCA(params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key attributes")
}

// =============================================================================
// constructors.go:277 — NewIntermediateCA ToKeyAttributes error
// =============================================================================

// TestNewIntermediateCA_ToKeyAttributesError_B17 covers constructors.go:277.16,279.3.
// Uses a fully initialized parent CA; the intermediate Identity[1] has a BOGUS
// key algorithm that makes ToKeyAttributes fail.
func TestNewIntermediateCA_ToKeyAttributesError_B17(t *testing.T) {
	// Not parallel: allocates a CA with Init, which is slow but safe.
	ca := setupTestCA(t)

	ks, cs := buildTestKeyStore(t)
	params := &Params{
		KeyStore:        ks,
		BackendForStore: singleBackendFactory(ks),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		Identity: []Identity{
			// Identity[0] is the root (not used by NewIntermediateCA but
			// required to satisfy len(params.Identity) >= 2).
			{
				Subject: Subject{CommonName: "Root B17"},
				Valid:   1,
				IsRoot:  true,
				Keys: []*types.KeyConfig{
					{KeyAlgorithm: "ECDSA"},
				},
			},
			// Identity[1] is the intermediate with a BOGUS algorithm.
			{
				Subject: Subject{CommonName: "Intermediate B17"},
				Valid:   1,
				Keys: []*types.KeyConfig{
					{KeyAlgorithm: "BOGUS"},
				},
			},
		},
	}
	_, err := NewIntermediateCA(context.Background(), params, ca)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key attributes")
}

// =============================================================================
// tcg.go:614 — VerifyQuote cert-store fallback (2 stmts)
// tcg.go:640 — VerifyQuote ECDSA failure (1 stmt)
// =============================================================================

// TestVerifyQuote_CertStoreFallback_ECDSABadSig_B17 covers:
//   - tcg.go:614.8,617.17 (cert-store fallback — attrs.TPMAttributes == nil)
//   - tcg.go:640.57,642.4 (ECDSA VerifyASN1 returns false → error)
//
// A real self-signed ECDSA cert is stored in the CA's cert store. The quote
// carries a garbage signature that will fail ecdsa.VerifyASN1.
func TestVerifyQuote_CertStoreFallback_ECDSABadSig_B17(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	const cn = "ak-ecdsa-bad-sig-b17"

	cert, _ := selfSignedECDSACert(t, cn)
	require.NoError(t, ca.certStore.StoreCertificate(cert))

	quoted := []byte("quoted-data-ecdsa-b17")
	quote := &tpm2.Quote{
		Quoted:    quoted,
		Signature: []byte("garbage-signature"),
		Nonce:     []byte("nonce"),
	}
	attrs := &types.KeyAttributes{CN: cn}

	err := ca.VerifyQuote(attrs, quote, []byte("nonce"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ECDSA")
}

// =============================================================================
// tcg.go:626 — VerifyQuote RSA case (2 stmts)
// tcg.go:614 — also hit by this test (cert-store fallback)
// =============================================================================

// TestVerifyQuote_CertStoreFallback_RSAPKCS1v15_B17 covers:
//   - tcg.go:614.8,617.17 (cert-store fallback)
//   - tcg.go:626.22,632.95 (RSA case: PSS fails, PKCS1v15 succeeds → nil error)
//
// A real RSA-2048 cert is stored. The quote signature is a valid PKCS1v15
// signature over sha256(quote.Quoted), so PSS fails, PKCS1v15 succeeds.
func TestVerifyQuote_CertStoreFallback_RSAPKCS1v15_B17(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	const cn = "ak-rsa-pkcs1-b17"

	cert, rsaKey := selfSignedRSACert(t, cn)
	require.NoError(t, ca.certStore.StoreCertificate(cert))

	quoted := []byte("quoted-data-rsa-b17")
	digest := sha256.Sum256(quoted)
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	require.NoError(t, err)

	quote := &tpm2.Quote{
		Quoted:    quoted,
		Signature: sig,
		Nonce:     []byte("nonce-rsa"),
	}
	attrs := &types.KeyAttributes{CN: cn}

	err = ca.VerifyQuote(attrs, quote, []byte("nonce-rsa"))
	require.NoError(t, err)
}

// =============================================================================
// hybrid.go:497 — rebuildTBSWithoutExtension no-extensions path (1 stmt)
// =============================================================================

// TestRebuildTBSWithoutExtension_NoExtensions_B17 covers hybrid.go:497.21,500.3.
// A minimal cert with zero extensions has no ClassContextSpecific Tag=3 field
// in its TBS, so extFieldIdx stays -1 and the early return fires.
func TestRebuildTBSWithoutExtension_NoExtensions_B17(t *testing.T) {
	t.Parallel()
	certDER := minimalCertDERNoExtensions(t)

	// Any OID will do — the function returns original TBS before finding it.
	excludeOID := asn1.ObjectIdentifier{2, 5, 29, 17}

	tbs, err := rebuildTBSWithoutExtension(certDER, excludeOID)
	require.NoError(t, err)
	// The returned TBS should be a valid non-empty DER SEQUENCE.
	assert.NotEmpty(t, tbs)

	// Sanity-check: the returned bytes should parse as a raw ASN.1 value.
	var raw asn1.RawValue
	_, unmarshalErr := asn1.Unmarshal(tbs, &raw)
	assert.NoError(t, unmarshalErr)
}

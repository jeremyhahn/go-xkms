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

// Package ca coverage boost, sixteenth pass: targets remaining uncovered
// functions identified after boost15. All tests are in-memory, fast,
// race-detector clean. Tests that mutate package-level state (aiaHTTPClient)
// or shared CA fields must NOT use t.Parallel().
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// tbs_determinism.go — ExtractTBSBytes empty TBS SEQUENCE (line 115)
// =============================================================================

// TestExtractTBSBytes_EmptyTBS_B16 covers tbs_determinism.go:115.17,117.3 by
// providing DER where the outer SEQUENCE contains a valid inner SEQUENCE with
// zero content bytes, causing tbs.Empty() to return true.
func TestExtractTBSBytes_EmptyTBS_B16(t *testing.T) {
	t.Parallel()
	// Build DER manually:
	//   0x30 0x02 = outer SEQUENCE, 2 bytes of content
	//   0x30 0x00 = inner SEQUENCE, 0 bytes of content (empty TBS)
	emptyTBSDER := []byte{0x30, 0x02, 0x30, 0x00}
	_, err := ExtractTBSBytes(emptyTBSDER)
	assert.ErrorIs(t, err, ErrEmptyTBSCertificate)
}

// =============================================================================
// hybrid.go — VerifyHybridCertificate: altSigAlg present, altSigValue absent (line 253)
// =============================================================================

// TestVerifyHybridCertificate_AltSigAlgNoValue_B16 covers hybrid.go:253.27,258.3
// by constructing a self-signed certificate that includes the altSignatureAlgorithm
// extension (OID 2.5.29.73) but not the altSignatureValue extension (OID 2.5.29.74).
// The classical signature verifies successfully; the absence of altSigValue triggers
// the error at line 253.
func TestVerifyHybridCertificate_AltSigAlgNoValue_B16(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	// altSignatureAlgorithm OID: 2.5.29.73
	altSigAlgOID := asn1.ObjectIdentifier{2, 5, 29, 73}
	// Encode a minimal AlgorithmIdentifier as the extension value.
	algID := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}}
	algIDBytes, encErr := asn1.Marshal(algID)
	require.NoError(t, encErr)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "hybrid-altsigalg-only-b16"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{
				// altSignatureAlgorithm — present
				Id:    altSigAlgOID,
				Value: algIDBytes,
			},
			// altSignatureValue (2.5.29.74) intentionally omitted
		},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	quantumIssuer := &quantum.MLDSAPublicKey{Algorithm: "ML-DSA-44", Key: []byte("pubkey")}

	// Classical signature verifies (self-signed). altSigAlg found. altSigValue
	// not found → HybridVerificationError at line 253.
	verErr := VerifyHybridCertificate(certDER, cert, quantumIssuer)
	assert.Error(t, verErr)
}

// =============================================================================
// quantum.go — verifyQuantumCertificate: unknown signature algorithm OID (line 274)
// =============================================================================

// TestVerifyQuantumCertificate_UnknownSignatureOID_B16 covers
// quantum.go:274.16,276.3 by crafting a DER "certificate" whose
// SignatureAlgorithm field uses an OID not in algorithmOIDMap.
//
// verifyQuantumCertificate calls:
//  1. asn1.Unmarshal(certDER, &rawCert)      — outer parse (line 254)
//  2. asn1.Unmarshal(rawCert.FullBytes, &inner) — inner parse (line 268)
//  3. oidToQuantumAlgorithm(...)              — OID lookup (line 273)
//
// For (2) to succeed, rawCert.FullBytes must be a SEQUENCE containing the
// three certificate fields. rawCert.FullBytes == certDER, so certDER itself
// must be the three-field SEQUENCE, NOT a double-wrapped SEQUENCE.
// We achieve this by marshalling the struct directly (asn1.Marshal already
// produces a SEQUENCE).
func TestVerifyQuantumCertificate_UnknownSignatureOID_B16(t *testing.T) {
	t.Parallel()
	issuerPubKey := &quantum.MLDSAPublicKey{Algorithm: "ML-DSA-44", Key: []byte("key")}

	// Build the certificate DER directly as a struct (produces one SEQUENCE
	// with the three fields). No extra wrapping.
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	inner := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{0x05, 0x00}},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: unknownOID},
		SignatureValue:     asn1.BitString{Bytes: []byte{0xAB}, BitLength: 8},
	}
	certDER, err := asn1.Marshal(inner)
	require.NoError(t, err)

	// Outer Unmarshal succeeds (rawCert.FullBytes == certDER), no trailing data.
	// Inner Unmarshal on rawCert.FullBytes == certDER succeeds (same SEQUENCE).
	// oidToQuantumAlgorithm(unknownOID) returns an error → line 274.
	verErr := verifyQuantumCertificate(certDER, issuerPubKey)
	assert.Error(t, verErr)
}

// =============================================================================
// quantum.go — verifyQuantumCertificate: verifyMLDSASignature error (line 291)
// =============================================================================

// TestVerifyQuantumCertificate_BadMLDSAKeyBytes_B16 covers
// quantum.go:291.16,293.3 by crafting a DER certificate whose
// SignatureAlgorithm uses the ML-DSA-44 OID (so oidToQuantumAlgorithm
// succeeds and the algorithm matches) but where the issuer public key
// contains bytes that cannot be unmarshalled as an ML-DSA-44 key, causing
// verifyMLDSASignature to return an error.
func TestVerifyQuantumCertificate_BadMLDSAKeyBytes_B16(t *testing.T) {
	t.Parallel()
	// ML-DSA-44 OID: 2.16.840.1.101.3.4.3.17
	mldsa44OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	issuerPubKey := &quantum.MLDSAPublicKey{
		Algorithm: "ML-DSA-44",
		Key:       []byte("garbage-key-bytes-too-short-for-mldsa44"),
	}

	// Build the certificate DER directly as a struct (one SEQUENCE, three fields).
	inner := struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{0x05, 0x00}},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: mldsa44OID},
		SignatureValue:     asn1.BitString{Bytes: []byte{0xAB}, BitLength: 8},
	}
	certDER, err := asn1.Marshal(inner)
	require.NoError(t, err)

	// oidToQuantumAlgorithm returns "ML-DSA-44". Algorithm matches issuerPubKey.
	// verifyMLDSASignature tries to unmarshal garbage key bytes → error → line 291.
	verErr := verifyQuantumCertificate(certDER, issuerPubKey)
	assert.Error(t, verErr)
}

// =============================================================================
// ca_extensions.go — SignedBlob: getSigner error (line 105)
// =============================================================================

// TestSignedBlob_SignerError_B16 covers ca_extensions.go:105.16,107.3 by
// invalidating the CA issuing identity after initialization so getSigner()
// returns an error when SignedBlob is called.
// NOT parallel — mutates CA config.
func TestSignedBlob_SignerError_B16(t *testing.T) {
	ca := setupTestCA(t)

	// Corrupt the issuing identity so getSigner returns ErrInvalidConfig.
	ca.config.SelectedCA = -1

	_, err := ca.SignedBlob(context.Background(), []byte("test-blob-data"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSigningFailed)
}

// =============================================================================
// constructors.go — initializeAsIntermediate: parent.CACertificate() error (line 337)
// =============================================================================

// TestInitializeAsIntermediate_ParentCertError_B16 covers
// constructors.go:337.16,339.3 by passing an uninitialized CA as the parent.
// parent.CACertificate() returns ErrNotInitialized because parent.initialized
// is false, causing initializeAsIntermediate to return at line 337-339.
func TestInitializeAsIntermediate_ParentCertError_B16(t *testing.T) {
	t.Parallel()
	// caInstance must be uninitialized so the ErrAlreadyInitialized guard
	// at line 332 does not fire and execution reaches line 336.
	caInstance := setupUninitializedCA(t)

	// parent is also uninitialized so CACertificate() returns ErrNotInitialized.
	parent := setupUninitializedCA(t)
	parentIdentity := Identity{
		Subject: Subject{CommonName: "Parent CA B16"},
		IsRoot:  true,
		Keys:    []*types.KeyConfig{{KeyAlgorithm: types.AlgorithmECDSA, StoreType: types.StoreSoftware, KeyType: "CA"}},
	}

	err := initializeAsIntermediate(context.Background(), caInstance, parentIdentity, parent)
	assert.Error(t, err)
}

// =============================================================================
// attestation.go — ImportLocalAttestation: quote import error (line 202)
// =============================================================================

// TestImportLocalAttestation_QuoteImportError_B16 covers
// attestation.go:202.78,204.3 by calling ImportLocalAttestation with a
// non-nil Quote on a CA whose issuing identity is invalidated so
// ImportAttestationQuote (and therefore ImportAttestation) fails.
// NOT parallel — mutates CA config.
func TestImportLocalAttestation_QuoteImportError_B16(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	akAttrs := &types.KeyAttributes{CN: "import-local-attest-b16"}

	// Invalidate the issuing identity so Signer() fails.
	ca.config.SelectedCA = -1

	quote := &tpm2.Quote{
		Quoted: []byte("quoted-data"),
		// EventLog and PCRs omitted; they will never be reached because
		// the quote import fails first.
	}

	err := ca.ImportLocalAttestation(context.Background(), akAttrs, quote)
	assert.Error(t, err)
}

// =============================================================================
// tcg.go — IssueEKCertificate: x509.CreateCertificate fails (line 166)
// =============================================================================

// TestIssueEKCertificate_NilRSAKey_B16 covers tcg.go:166.16,168.3 by passing
// a zero-value *rsa.PublicKey (nil N, E=0). IssueEKCertificate classifies it
// as RSA (passes the type switch) but x509.CreateCertificate fails when it
// tries to marshal the invalid RSA key.
func TestIssueEKCertificate_NilRSAKey_B16(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// A zero-value rsa.PublicKey passes the (*rsa.PublicKey) type check but
	// has a nil N field which causes x509 marshalling to fail.
	badRSAPub := &rsa.PublicKey{} // N=nil, E=0

	req := &CertificateRequest{
		Subject: Subject{CommonName: "ek-bad-rsa-b16"},
		Valid:   365,
	}

	_, err := ca.IssueEKCertificate(context.Background(), req, badRSAPub)
	assert.Error(t, err)
}

// =============================================================================
// tcg.go — IssueAKCertificate: x509.CreateCertificate fails (line 267)
// =============================================================================

// TestIssueAKCertificate_NilRSAKey_B16 covers tcg.go:267.16,269.3 by passing
// a zero-value *rsa.PublicKey (nil N) so that x509.CreateCertificate fails
// when marshalling the RSA key.
func TestIssueAKCertificate_NilRSAKey_B16(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	badRSAPub := &rsa.PublicKey{} // N=nil, E=0

	req := &CertificateRequest{
		Subject: Subject{CommonName: "ak-bad-rsa-b16"},
		Valid:   365,
	}

	_, err := ca.IssueAKCertificate(context.Background(), req, badRSAPub)
	assert.Error(t, err)
}

// =============================================================================
// service_adapter.go — SignTCGCSRIDevIDRaw: request block after unmarshal (lines 232-239)
// =============================================================================

// TestSignTCGCSRIDevIDRaw_UnmarshalSucceeds_B16 covers
// service_adapter.go:232.2,239.50 (2 statements) by providing valid-structure
// packed CSR bytes so that tpm2.UnmarshalIDevIDCSR succeeds (reaching the
// request-construction block at line 232) before SignTCGCSRIDevID fails
// at CSR signature verification.
func TestSignTCGCSRIDevIDRaw_UnmarshalSucceeds_B16(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)

	// Build a minimal self-signed cert to embed as the EK cert in the CSR.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ek-cert-b16"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	ekDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	// Use the helper from tcg_enrollment_test.go to pack a valid-structure CSR.
	packedCSR := buildPackedCSRWithEkCert(t, ekDER)

	// UnmarshalIDevIDCSR will succeed (valid structure); SignTCGCSRIDevID
	// will fail at CSR signature verification because the placeholder
	// signature is not valid. Lines 232-239 are covered.
	_, _, signErr := ca.SignTCGCSRIDevIDRaw(context.Background(), "ek-test-b16", "test-org-b16", packedCSR)
	assert.Error(t, signErr)
}

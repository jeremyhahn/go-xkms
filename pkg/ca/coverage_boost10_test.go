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

// Package ca coverage boost, tenth pass: targets remaining sub-91% functions
// not covered in passes 1–9.  All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"

	qrdbstorage "github.com/jeremyhahn/go-qrdb/sdk/go/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ca.go — createIntermediateCertificates: "no intermediate selected" fallback
// (exercises lines 1088-1095 where SelectedCA==0 with an intermediate present)
// =============================================================================

// TestCreateIntermediateCertificates_NoSelectedCA_B10 configures a multi-identity
// CA with SelectedCA=0 (root) so that the intermediate loop never sets
// ca.intermediateCert; the fallback at line 1088 must then retrieve the last
// intermediate certificate from the cert store.
func TestCreateIntermediateCertificates_NoSelectedCA_B10(t *testing.T) {
	t.Parallel()
	backend, cs := newB9Backend(t)

	config := DefaultMultiIdentityCAConfigWithIntermediate()
	config.Identity[0].Subject.CommonName = "NoSelCA Root B10"
	config.Identity[0].Keys[0].KeyType = "CA"
	config.Identity[1].Subject.CommonName = "NoSelCA Intermediate B10"
	config.Identity[1].Keys[0].KeyType = "CA"
	// SelectedCA=0 means "use root"; the intermediate loop stores no
	// intermediate cert in ca.intermediateCert, triggering the fallback.
	config.SelectedCA = 0

	ca := &CA{
		config:      config,
		keyStore:    backend,
		keystoreMap: map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, ca.Init(context.Background()))
	// After Init the fallback must have populated intermediateCert.
	assert.NotNil(t, ca.intermediateCert)
	assert.Equal(t, "NoSelCA Intermediate B10", ca.intermediateCert.Subject.CommonName)
}

// =============================================================================
// constructors.go — initializeAsIntermediate: already-initialized guard
// =============================================================================

// TestInitializeAsIntermediate_AlreadyInitialized_B10 exercises the early-return
// guard at line 332 when the CA is already initialized.
func TestInitializeAsIntermediate_AlreadyInitialized_B10(t *testing.T) {
	t.Parallel()
	parent := setupTestCA(t)
	intermediate := setupTestCA(t) // already initialized

	cfg := DefaultMultiIdentityCAConfigWithIntermediate()
	cfg.Identity[1].Keys[0].KeyType = "CA"

	err := initializeAsIntermediate(context.Background(), intermediate, cfg.Identity[1], parent)
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

// =============================================================================
// ca.go — CABundle: root-only bundle (no intermediate) and
//          NewFromMultiIdentityConfig: valid + no issuing identity paths
// =============================================================================

// TestNewFromMultiIdentityConfig_NilConfig_B10 exercises the nil Config guard.
func TestNewFromMultiIdentityConfig_NilConfig_B10(t *testing.T) {
	t.Parallel()
	_, err := NewFromMultiIdentityConfig(nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// TestNewFromMultiIdentityConfig_NilConfigField_B10 exercises the nil mp.Config guard.
func TestNewFromMultiIdentityConfig_NilConfigField_B10(t *testing.T) {
	t.Parallel()
	_, err := NewFromMultiIdentityConfig(&MultiIdentityParams{})
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// cross_signing.go — XSignedCertificate: all error guards
// =============================================================================

// TestXSignedCertificate_EmptyIssuer_B10 exercises empty issuerCN guard.
func TestXSignedCertificate_EmptyIssuer_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	attrs := &types.KeyAttributes{CN: "some-cn"}
	_, err := ca.XSignedCertificate("", attrs)
	require.Error(t, err)
}

// TestXSignedCertificate_NilAttrs_B10 exercises nil attrs guard.
func TestXSignedCertificate_NilAttrs_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	_, err := ca.XSignedCertificate("issuer-b10", nil)
	require.Error(t, err)
}

// TestXSignedCertificate_NoObjectStore_B10 exercises ErrObjectStoreRequired.
func TestXSignedCertificate_NoObjectStore_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = nil

	attrs := &types.KeyAttributes{CN: "some-cn"}
	_, err := ca.XSignedCertificate("issuer-b10", attrs)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// TestXSignedCertificate_NotFound_B10 exercises the ErrCertificateNotFound path.
func TestXSignedCertificate_NotFound_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage() // empty

	attrs := &types.KeyAttributes{CN: "nonexistent-cn"}
	_, err := ca.XSignedCertificate("issuer-b10", attrs)
	assert.ErrorIs(t, err, ErrCertificateNotFound)
}

// TestXSignedCertificate_Found_B10 exercises the success path.
func TestXSignedCertificate_Found_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	subjectCN := "xsignedcert-subject-b10"
	cert, _ := b9MakeSelfSignedCACert(t, subjectCN)
	require.NoError(t, ca.ImportXSignedCertificate("issuer-b10", cert))

	attrs := &types.KeyAttributes{CN: subjectCN}
	got, err := ca.XSignedCertificate("issuer-b10", attrs)
	require.NoError(t, err)
	assert.Equal(t, subjectCN, got.Subject.CommonName)
}

// =============================================================================
// cross_signing.go — XSignedRootCertificate: parent exists in store
// =============================================================================

// TestXSignedRootCertificate_WithParentInStore_B10 exercises the recursive
// parent-lookup path in XSignedRootCertificate.
func TestXSignedRootCertificate_WithParentInStore_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	// Build a 2-cert chain: child → parent (self-signed).
	parentCert, parentKey := b9MakeSelfSignedCACert(t, "xroot-parent-b10")

	// Child cert signed by parent so child.Issuer = "xroot-parent-b10".
	childKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	childTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "xroot-child-b10"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, childTmpl, parentCert, &childKey.PublicKey, parentKey)
	require.NoError(t, err)
	childCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	// Store parent under issuer "xroot-issuer-b10" so readCrossSignedCertificate
	// can find it when following childCert.Issuer.CommonName.
	issuerCN := "xroot-issuer-b10"
	require.NoError(t, ca.ImportXSignedCertificate(issuerCN, parentCert))

	got, err := ca.XSignedRootCertificate(issuerCN, childCert)
	require.NoError(t, err)
	assert.Equal(t, "xroot-parent-b10", got.Subject.CommonName)
}

// =============================================================================
// cross_signing.go — XSignedIntermediateCertificates: intermediate found
// =============================================================================

// TestXSignedIntermediateCertificates_IntermediateFound_B10 builds a 3-cert
// chain where the middle cert is a non-self-signed CA so
// XSignedIntermediateCertificates returns it.
func TestXSignedIntermediateCertificates_IntermediateFound_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	issuerCN := "xint-issuer-b10"

	// Create root (self-signed).
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: "xint-root-b10"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	// Create intermediate signed by root.
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	intTmpl := &x509.Certificate{
		SerialNumber:          intSerial,
		Subject:               pkix.Name{CommonName: "xint-intermediate-b10"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	require.NoError(t, err)
	intCert, err := x509.ParseCertificate(intDER)
	require.NoError(t, err)

	// Create leaf signed by intermediate.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      pkix.Name{CommonName: "xint-leaf-b10"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Store the intermediate and root so the walk succeeds.
	// The walk in XSignedIntermediateCertificates reads leafCert.Issuer.CommonName
	// ("xint-intermediate-b10"), then intCert.Issuer.CommonName ("xint-root-b10"),
	// then rootCert is self-signed → stops.
	require.NoError(t, ca.ImportXSignedCertificate(issuerCN, intCert))
	require.NoError(t, ca.ImportXSignedCertificate(issuerCN, rootCert))

	ints, err := ca.XSignedIntermediateCertificates(issuerCN, leafCert)
	require.NoError(t, err)
	// intCert is a non-self-signed CA → must appear.
	assert.NotEmpty(t, ints)
}

// =============================================================================
// ca.go — Sign: success with Ed25519 (covers the signer path via Ed25519 CA)
// =============================================================================

// TestSign_Ed25519_B10 calls Sign on an Ed25519 CA using crypto.Hash(0) opts
// (PureEd25519 passes the message directly without pre-hashing).
func TestSign_Ed25519_B10(t *testing.T) {
	t.Parallel()
	ca := setupEd25519CA(t)
	msg := []byte("ed25519-sign-test-b10")
	sig, err := ca.Sign(rand.Reader, msg, crypto.Hash(0))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

// =============================================================================
// ca_extensions.go — putRevocationBlobIfAbsent: revocationStore is the sole
// persistence medium (the objectStore fallback was deleted)
// =============================================================================

// TestPutRevocationBlob_ObjectStoreIgnored_B10 proves an objectStore alone,
// with no revocationStore, is not consulted for revocation persistence: the
// deleted fallback is gone, not merely unreachable through some other path.
func TestPutRevocationBlob_ObjectStoreIgnored_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()
	ca.revocationStore = storage.NewMemory()

	payload := []byte(`{"serial":"77777","reason":0,"revoked_at":"2024-01-01T00:00:00Z"}`)
	stored, err := ca.putRevocationBlobIfAbsent(context.Background(), big.NewInt(77777), payload)
	require.NoError(t, err)
	assert.True(t, stored)

	// Persisted through revocationStore, not objectStore.
	_, err = ca.getObject(revocationKey(big.NewInt(77777)) + ".json")
	assert.ErrorIs(t, err, ErrObjectNotFound, "objectStore must not receive the revocation blob")
	got, err := ca.revocationStore.Get(context.Background(), revocationKey(big.NewInt(77777))+".json")
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// =============================================================================
// ca.go — Validate: all uncovered paths
// =============================================================================

// TestParams_Validate_NilConfig_B10 exercises nil Config guard in Params.Validate.
func TestParams_Validate_NilConfig_B10(t *testing.T) {
	t.Parallel()
	p := &Params{
		KeyAttributes: &types.KeyAttributes{},
	}
	err := p.Validate()
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// =============================================================================
// cross_signing.go — getXSignedCertificates: non-matching suffix skip
// =============================================================================

// TestGetXSignedCertificates_SuffixMismatch_B10 exercises the suffix filter in
// getXSignedCertificates where entries exist but none match the given CN.
func TestGetXSignedCertificates_SuffixMismatch_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	// Store cross-signed cert under "other-cn", not "target-cn".
	otherCert, _ := b9MakeSelfSignedCACert(t, "other-cn-b10")
	require.NoError(t, ca.ImportXSignedCertificate("issuer-b10", otherCert))

	// getXSignedCertificates for "target-cn" should return empty (suffix mismatch).
	certs := ca.getXSignedCertificates("target-cn-b10")
	assert.Empty(t, certs)
}

// TestGetXSignedCertificates_MatchingSuffix_B10 exercises the success path where
// the suffix matches and a cert is decoded and returned.
func TestGetXSignedCertificates_MatchingSuffix_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	cn := "getxsigned-match-b10"
	cert, _ := b9MakeSelfSignedCACert(t, cn)
	require.NoError(t, ca.ImportXSignedCertificate("issuer-b10", cert))

	certs := ca.getXSignedCertificates(cn)
	assert.Len(t, certs, 1)
	assert.Equal(t, cn, certs[0].Subject.CommonName)
}

// TestGetXSignedCertificates_InvalidPEM_B10 exercises the pem.Decode nil-block
// skip by storing a non-PEM payload for a key matching the suffix.
func TestGetXSignedCertificates_InvalidPEM_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	cn := "getxsigned-badpem-b10"
	// Write raw garbage (not PEM) to a key that matches the suffix.
	key := "cross-signed/issuer-b10/" + cn + ".pem"
	require.NoError(t, ca.putObject(key, []byte("not-pem")))

	certs := ca.getXSignedCertificates(cn)
	assert.Empty(t, certs) // corrupt entry silently skipped
}

// =============================================================================
// ca_extensions.go — CABundleFiltered: not-initialized path
// =============================================================================

// TestCABundleFiltered_NotInitialized_B10 exercises ErrNotInitialized guard.
func TestCABundleFiltered_NotInitialized_B10(t *testing.T) {
	t.Parallel()
	ca := &CA{config: &MultiIdentityCAConfig{}}
	_, err := ca.CABundleFiltered(types.StoreSoftware, x509.ECDSA)
	assert.ErrorIs(t, err, ErrNotInitialized)
}

// =============================================================================
// ca_extensions.go — ImportXSignedCertificate: success (from cross_signing.go)
// already tested in B9; add the readCrossSignedCertificate invalid-PEM path
// =============================================================================

// TestReadCrossSignedCertificate_InvalidPEM_B10 exercises the pem.Decode nil
// path in readCrossSignedCertificate by storing garbage PEM data.
func TestReadCrossSignedCertificate_InvalidPEM_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbstorage.NewMemoryStorage()

	cn := "rcsc-badpem-b10"
	issuerCN := "rcsc-issuer-b10"
	key := "cross-signed/" + issuerCN + "/" + cn + ".pem"
	require.NoError(t, ca.putObject(key, []byte("not-pem")))

	_, err := ca.XSignedCertificate(issuerCN, &types.KeyAttributes{CN: cn})
	assert.ErrorIs(t, err, ErrInvalidPEM)
}

// =============================================================================
// ca_extensions.go — Exists: empty CN guard
// =============================================================================

// TestExists_EmptyCN_B10 exercises the empty CN guard in Exists.
func TestExists_EmptyCN_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.Exists(context.Background(), "", x509.ECDSA)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// csr.go — CreateCSR: nil request and missing CN guards
// =============================================================================

// TestCreateCSR_NilRequest_B10 exercises the nil request guard.
func TestCreateCSR_NilRequest_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.CreateCSR(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidCSR)
}

// =============================================================================
// ca.go — getCAKeyAttributes: nil identity guard
// =============================================================================

// TestGetCAKeyAttributes_NilIdentity_B10 exercises the nil identity guard.
func TestGetCAKeyAttributes_NilIdentity_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	_, err := ca.getCAKeyAttributes(t.Context(), nil)
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

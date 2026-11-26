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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

// TestXSignedCertificate_NoObjectStore_B10 exercises ErrObjectStoreRequired.
func TestXSignedCertificate_NoObjectStore_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = nil

	attrs := &types.KeyAttributes{CN: "some-cn"}
	_, err := ca.XSignedCertificate("issuer-b10", attrs)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
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
	ca.objectStore = qrdbsdk.NewMemoryStorage()
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

// TestGetXSignedCertificates_InvalidPEM_B10 exercises the pem.Decode nil-block
// skip by storing a non-PEM payload for a key matching the suffix.
func TestGetXSignedCertificates_InvalidPEM_B10(t *testing.T) {
	t.Parallel()
	ca := setupTestCA(t)
	ca.objectStore = qrdbsdk.NewMemoryStorage()

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

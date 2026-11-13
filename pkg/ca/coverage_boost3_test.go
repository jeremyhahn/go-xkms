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

// Package ca coverage boost, third pass: targets low-coverage functions
// remaining after the first and second passes.  All tests are in-memory,
// fast, race-free.
package ca

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// OCSP — VerifyOCSPResponse
// =============================================================================

func TestVerifyOCSPResponse_EmptyInput_B3(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	_, err := resp.VerifyOCSPResponse(nil)
	assert.ErrorIs(t, err, ErrOCSPInvalidRequest)
}

func TestVerifyOCSPResponse_InvalidBytes_B3(t *testing.T) {
	ca := setupTestCA(t)
	resp := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	_, err := resp.VerifyOCSPResponse([]byte("not-an-ocsp-response"))
	assert.ErrorIs(t, err, ErrOCSPResponseFailed)
}

// =============================================================================
// OCSP — CreateOCSPRequest
// =============================================================================

func TestCreateOCSPRequest_NilCert(t *testing.T) {
	_, err := CreateOCSPRequest(nil, nil, nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ImportDistributionCRLs — nil cert + no distribution points + no object store
// =============================================================================

func TestImportDistributionCRLs_NoObjectStore(t *testing.T) {
	ca := setupTestCA(t) // no object store
	cert := &x509.Certificate{
		CRLDistributionPoints: []string{"http://example.com/crl.crl"},
	}
	err := ca.ImportDistributionCRLs(cert)
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// =============================================================================
// ImportIssuingCAs — nil cert + no AIA paths
// =============================================================================

func TestImportIssuingCAs_NilCert_B3(t *testing.T) {
	ca := setupTestCA(t)
	err := ca.ImportIssuingCAs(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// ImportAttestationKeyCertificate — guard paths
// =============================================================================

func TestImportAttestationKeyCertificate_NoObjectStore(t *testing.T) {
	ca := setupTestCA(t) // no object store
	attrs := &types.KeyAttributes{CN: "ak-no-store"}
	err := ca.ImportAttestationKeyCertificate(context.Background(), attrs, []byte("notavalidder"))
	assert.ErrorIs(t, err, ErrObjectStoreRequired)
}

// =============================================================================
// TBS determinism
// =============================================================================

func TestExtractTBSBytes_EmptyInput(t *testing.T) {
	_, err := ExtractTBSBytes(nil)
	assert.ErrorIs(t, err, ErrTBSNilInput)
}

// =============================================================================
// profiles.go — Register / Get / List
// =============================================================================

func TestProfileRegistry_Register_NilProfile(t *testing.T) {
	r := NewDefaultProfileRegistry()
	err := r.Register("nil-profile", nil)
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

func TestProfileRegistry_Register_EmptyName(t *testing.T) {
	r := NewDefaultProfileRegistry()
	err := r.Register("  ", NewClientProfile())
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

// =============================================================================
// listRevocationBlobs — revocationStore is the sole source, objectStore
// entries are never consulted
// =============================================================================

// TestListRevocationBlobs_ObjectStoreEntryIgnored_B3 proves an entry written
// directly to objectStore under the revocation key prefix is not surfaced by
// listRevocationBlobs: the deleted objectStore fallback is gone, not merely
// unreachable through some other path.
func TestListRevocationBlobs_ObjectStoreEntryIgnored_B3(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	key := revocationKeyPrefix + "test-serial.json"
	require.NoError(t, ca.putObject(key, []byte(`{"serial":"01"}`)))

	blobs, err := ca.listRevocationBlobs(context.Background())
	require.NoError(t, err)
	assert.Empty(t, blobs, "objectStore entries must not be surfaced")
}

// =============================================================================
// hybrid.go — extractTBS valid/invalid paths
// =============================================================================

func TestExtractTBS_InvalidInput(t *testing.T) {
	_, err := extractTBS([]byte("not-a-cert"))
	assert.Error(t, err)
}

// =============================================================================
// NewIntermediateCA — missing parent / not initialized fast-paths
// =============================================================================

func TestNewIntermediateCA_NilParams(t *testing.T) {
	_, err := NewIntermediateCA(context.Background(), nil, nil)
	assert.Error(t, err)
}

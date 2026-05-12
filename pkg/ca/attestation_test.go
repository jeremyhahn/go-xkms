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

// Package ca tests for attestation blob lifecycle. Complements
// session1_extensions_test.go by covering the per-blob convenience wrappers
// (ImportAttestationEventLog, ImportAttestationPCRs, ImportAttestationQuote)
// and the nil-input error paths that protect the underlying storage layout
// from partial writes.
package ca

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ImportAttestation — input validation
// =============================================================================

// TestImportAttestation_NilAttrs asserts that nil KeyAttributes are rejected
// with ErrInvalidRequest before any object-store interaction occurs.
func TestImportAttestation_NilAttrs(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportAttestation(nil, AttestBlobQuote, []byte("data"))
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

// TestImportAttestation_EmptyData asserts that an empty data payload is
// rejected. Storing a zero-byte blob would leave a dangling signature record
// that VerifyAttestation* cannot reconcile.
func TestImportAttestation_EmptyData(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportAttestation(&types.KeyAttributes{CN: "ak"}, AttestBlobQuote, []byte{})
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

// =============================================================================
// ImportAttestationKeyCertificate — input validation
// =============================================================================

// TestImportAttestationKeyCertificate_NilAttrs asserts that nil attrs are
// rejected with ErrInvalidRequest.
func TestImportAttestationKeyCertificate_NilAttrs(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportAttestationKeyCertificate(nil, []byte("not-a-cert"))
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

// TestImportAttestationKeyCertificate_EmptyCertificate asserts that an empty
// DER payload is rejected. x509.ParseCertificate would have returned a
// generic parse error; the explicit guard gives callers a typed error up
// front.
func TestImportAttestationKeyCertificate_EmptyCertificate(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportAttestationKeyCertificate(&types.KeyAttributes{CN: "ak"}, nil)
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// TestImportAttestationKeyCertificate_InvalidDER asserts that a non-DER
// payload is rejected with ErrInvalidCertificate.
func TestImportAttestationKeyCertificate_InvalidDER(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportAttestationKeyCertificate(&types.KeyAttributes{CN: "ak"}, []byte("not-a-cert"))
	assert.ErrorIs(t, err, ErrInvalidCertificate)
}

// =============================================================================
// Per-blob convenience wrappers
// =============================================================================

// TestImportAttestationEventLog_Roundtrip asserts that the event-log wrapper
// delegates to ImportAttestation with AttestBlobEventLog and that the
// resulting signature verifies correctly.
func TestImportAttestationEventLog_Roundtrip(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	attrs := &types.KeyAttributes{CN: "ak-eventlog"}
	data := []byte("event-log-payload")
	require.NoError(t, ca.ImportAttestationEventLog(attrs, data))
	require.NoError(t, ca.VerifyAttestationEventLog(attrs, data))
}

// TestImportAttestationPCRs_Roundtrip asserts the PCRs wrapper.
func TestImportAttestationPCRs_Roundtrip(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	attrs := &types.KeyAttributes{CN: "ak-pcrs"}
	data := []byte("pcr-snapshot")
	require.NoError(t, ca.ImportAttestationPCRs(attrs, data))
	require.NoError(t, ca.VerifyAttestationPCRs(attrs, data))
}

// TestImportAttestationQuote_Roundtrip asserts the quote wrapper.
func TestImportAttestationQuote_Roundtrip(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	attrs := &types.KeyAttributes{CN: "ak-quote"}
	data := []byte("quote-payload")
	require.NoError(t, ca.ImportAttestationQuote(attrs, data))
	require.NoError(t, ca.VerifyAttestationQuote(attrs, data))
}

// TestImportLocalAttestation_NilQuote asserts that a nil *tpm2.Quote is
// rejected with ErrInvalidRequest.
func TestImportLocalAttestation_NilQuote(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.ImportLocalAttestation(&types.KeyAttributes{CN: "ak"}, nil)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

// =============================================================================
// Verify — mismatched / missing blobs
// =============================================================================

// TestVerifyAttestationQuote_NotFound asserts ErrCertificateNotFound (or a
// storage-layer error) when verification is attempted for an AK that has no
// stored quote.
func TestVerifyAttestationQuote_NotFound(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.VerifyAttestationQuote(&types.KeyAttributes{CN: "never-imported"}, []byte("x"))
	assert.Error(t, err, "verification against an absent blob must return an error")
}

// TestVerifyAttestationQuote_NilAttrs asserts that nil attrs are rejected.
func TestVerifyAttestationQuote_NilAttrs(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	err := ca.VerifyAttestationQuote(nil, []byte("x"))
	assert.Error(t, err)
}

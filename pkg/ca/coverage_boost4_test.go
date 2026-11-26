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

// Package ca coverage boost, fourth pass: targets low-coverage functions
// remaining after the third pass.  All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Verify — cross-signer path with non-nil xsigner (object-store empty)
// =============================================================================

func TestVerify_WithNonNilXSigner_NoXSignedCerts(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		TenantID: testTenant,
		Subject:  Subject{CommonName: "verify-xsign-b4"},
		SANS:     &SubjectAlternativeNames{DNS: []string{"verify-xsign-b4.local"}},
		Valid:    365,
	})
	require.NoError(t, err)

	// Use an ECDSA key as the xsigner. The object store has no xsigned certs,
	// so the cross-sign-aware pool falls back to the native roots and the
	// verify should still succeed.
	ecKey, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, genErr)

	chains, err := ca.Verify(issued.Certificate, ecKey)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

// =============================================================================
// TLSConfigWithXSigner — root cert nil path
// =============================================================================

func TestTLSConfigWithXSigner_RootCertNil(t *testing.T) {
	ca := setupTestCA(t)
	issueCertAndSaveToKeyStore(t, ca, "tls-xsign-root-nil-b4")
	attrs := softwareKeyAttrs("tls-xsign-root-nil-b4")

	// Force root cert to nil so the function hits the "root == nil → return cfg" branch.
	ca.mu.Lock()
	origRoot := ca.rootCert
	ca.rootCert = nil
	ca.mu.Unlock()
	defer func() {
		ca.mu.Lock()
		ca.rootCert = origRoot
		ca.mu.Unlock()
	}()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cfg, err := ca.TLSConfigWithXSigner(context.Background(), attrs, ecKey)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

// =============================================================================
// ImportLocalAttestation — non-nil quote with object store
// =============================================================================

func TestImportLocalAttestation_WithEventLog_B4(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	attrs := &types.KeyAttributes{CN: "ak-eventlog-b4"}

	quote := &tpm2.Quote{
		Quoted:    []byte("quoted-bytes-2"),
		Signature: []byte("sig2"),
		PCRs:      []byte("pcr-snapshot-2"),
		EventLog:  []byte("event-log-data"),
	}

	err := ca.ImportLocalAttestation(context.Background(), attrs, quote)
	require.NoError(t, err)
}

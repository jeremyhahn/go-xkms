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

// Package ca coverage boost, sixth pass: uses httptest.Server to cover the
// HTTP download paths in ImportDistributionCRLs.
// All tests are in-memory, fast, race-free.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ImportDistributionCRLs — HTTP success path via httptest.Server
// =============================================================================

// buildTestCRL creates a valid DER-encoded CRL signed by the given issuer.
func buildTestCRL(t *testing.T, issuerKey *ecdsa.PrivateKey, issuerCert *x509.Certificate) []byte {
	t.Helper()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, issuerCert, issuerKey)
	require.NoError(t, err)
	return crlDER
}

func TestImportDistributionCRLs_AlreadyImported(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crl-issuer-2"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &key.PublicKey, key)
	require.NoError(t, err)
	issuerCert, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	crlDER := buildTestCRL(t, key, issuerCert)

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crlDER)
	}))
	defer srv.Close()

	ca := setupTestCAWithObjectStore(t)
	allowLoopbackFetch(ca)
	cert := &x509.Certificate{
		CRLDistributionPoints: []string{srv.URL + "/test.crl"},
	}

	// First import.
	require.NoError(t, ca.ImportDistributionCRLs(cert))
	// Second import — should be skipped (object store already has it).
	require.NoError(t, ca.ImportDistributionCRLs(cert))
	assert.Equal(t, 1, callCount, "second import should skip the download")
}

func TestImportDistributionCRLs_InvalidCRLBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-a-crl"))
	}))
	defer srv.Close()

	ca := setupTestCAWithObjectStore(t)
	allowLoopbackFetch(ca)
	cert := &x509.Certificate{
		CRLDistributionPoints: []string{srv.URL + "/bad.crl"},
	}

	err := ca.ImportDistributionCRLs(cert)
	assert.ErrorIs(t, err, ErrCRLGenerationFailed)
}

// =============================================================================
// lookupRevocation — objectStore is never consulted for revocation state
// =============================================================================

func TestLookupRevocation_IgnoresObjectStore(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)

	// A record in the legacy object store is not revocation state: the
	// revocation store is the sole persistence medium.
	require.NoError(t, ca.putObject(
		revocationKeyPrefix+"999888777.json",
		[]byte(`{"serial":"999888777"}`),
	))

	info, err := ca.lookupRevocation(context.Background(), big.NewInt(999888777))
	require.NoError(t, err)
	assert.Nil(t, info)
}

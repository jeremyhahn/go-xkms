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

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	objstore "github.com/jeremyhahn/go-objstore/pkg/common"
	objmemory "github.com/jeremyhahn/go-objstore/pkg/memory"
	"github.com/stretchr/testify/require"
)

// failCloseReader wraps an io.ReadCloser and reports a fixed error from
// Close, so a test can exercise a reader-Close error path without depending
// on a real backend that can fail on demand.
type failCloseReader struct {
	io.ReadCloser
	closeErr error
}

func (r *failCloseReader) Close() error {
	_ = r.ReadCloser.Close()
	return r.closeErr
}

// failCloseStore decorates an objstore.Storage so every successful Get
// returns a reader whose Close fails, exercising the reader-Close error path
// in ImportDistributionCRLs.
type failCloseStore struct {
	objstore.Storage
	closeErr error
}

func (s *failCloseStore) Get(key string) (io.ReadCloser, error) {
	rc, err := s.Storage.Get(key)
	if err != nil {
		return nil, err
	}
	return &failCloseReader{ReadCloser: rc, closeErr: s.closeErr}, nil
}

// TestImportDistributionCRLs_ReaderCloseErrorSurfaces verifies that a Close
// failure on the "already imported, skip" reader is reported to the caller
// rather than silently discarded (#701).
func TestImportDistributionCRLs_ReaderCloseErrorSurfaces(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crl-close-err-issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	require.NoError(t, err)
	issuerCert, err := x509.ParseCertificate(issuerDER)
	require.NoError(t, err)

	crlDER := buildTestCRL(t, issuerKey, issuerCert)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(crlDER)
	}))
	defer srv.Close()

	closeErr := errors.New("crl_import_close_error_test: simulated reader close failure")
	ca := setupTestCA(t)
	ca.objectStore = &failCloseStore{Storage: objmemory.New(), closeErr: closeErr}

	cert := &x509.Certificate{
		CRLDistributionPoints: []string{srv.URL + "/test.crl"},
	}

	// First import stores the CRL via Put, not Get, so no Close failure yet.
	require.NoError(t, ca.ImportDistributionCRLs(cert))

	// Second import hits the "already imported" branch and must surface the
	// reader Close error instead of dropping it.
	err = ca.ImportDistributionCRLs(cert)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStorageError)
	require.Contains(t, err.Error(), closeErr.Error())
}

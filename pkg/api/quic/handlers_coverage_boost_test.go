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

//go:build !frost

package quic

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestHandleVerify_FullSuccess exercises the full verify success path.
func TestHandleVerify_FullSuccess(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "vkey", KeyType: backend.KEY_TYPE_TLS, StoreType: backend.STORE_SW, KeyAlgorithm: x509.ECDSA},
		}, nil
	}
	mockKS.SetKey("vkey", key)

	data := []byte("test data")
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	require.NoError(t, err)

	body, err := json.Marshal(VerifyRequest{
		Data:      data,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Hash:      "SHA256",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "vkey", "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleSign_FullSuccess exercises the full sign success path.
func TestHandleSign_FullSuccess(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "skey", KeyType: backend.KEY_TYPE_TLS, StoreType: backend.STORE_SW, KeyAlgorithm: x509.ECDSA},
		}, nil
	}
	mockKS.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		return key, nil
	}

	body, err := json.Marshal(SignRequest{Data: []byte("data"), Hash: "SHA256"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleSign(rec, req, "skey", "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleDeleteCert_FullSuccess exercises the delete cert success path.
func TestHandleDeleteCert_FullSuccess(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.SetCert("cert-id", makeTestCert(t))

	req := httptest.NewRequest(http.MethodDelete, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleDeleteCert(rec, req, "cert-id")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleCertExists_NotFound exercises the cert-not-found path.
func TestHandleCertExists_NotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleCertExists(rec, req, "nonexistent")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleCertExists_Found exercises the cert-found path.
func TestHandleCertExists_Found(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.SetCert("found-cert", makeTestCert(t))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleCertExists(rec, req, "found-cert")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleCA_MethodNotAllowed exercises wrong HTTP methods for CA handlers.
func TestHandleCA_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
	}{
		{"GetCABundle", server.handleGetCABundle, http.MethodDelete},
		{"GetCACertificate", server.handleGetCACertificate, http.MethodDelete},
		{"IssueCertificate", server.handleIssueCertificate, http.MethodGet},
		{"RevokeCertificate", server.handleRevokeCertificate, http.MethodGet},
		{"GenerateCRL", server.handleGenerateCRL, http.MethodDelete},
		{"SignCSR", server.handleSignCSR, http.MethodGet},
		{"IsRevoked", server.handleIsRevoked, http.MethodDelete},
		{"IssueEKCert", server.handleIssueEKCertificate, http.MethodGet},
		{"IssueAKCert", server.handleIssueAKCertificate, http.MethodGet},
		{"SignTCGCSR", server.handleSignTCGCSR, http.MethodGet},
		{"EnrollDevice", server.handleEnrollDevice, http.MethodGet},
		{"CopyKey", server.handleCopyKey, http.MethodGet},
		{"TLSCertificate", server.handleTLSCertificate, http.MethodPost},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			rec := httptest.NewRecorder()
			tt.handler(rec, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}

// TestHandleInit_MethodNotAllowed exercises wrong HTTP methods for init handlers.
func TestHandleInit_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
	}{
		{"ClaimCertBegin", server.handleClaimCertBegin, http.MethodGet},
		{"ClaimCertComplete", server.handleClaimCertComplete, http.MethodGet},
		{"ClaimShare", server.handleClaimShare, http.MethodGet},
		{"SignCSRInit", server.handleSignCSRInit, http.MethodGet},
		{"CredentialSubmit", server.handleCredentialSubmit, http.MethodGet},
		{"CredentialStrategy", server.handleCredentialStrategy, http.MethodPost},
		{"BarrierDeleteRecoveryKeys", server.handleBarrierDeleteRecoveryKeys, http.MethodGet},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			rec := httptest.NewRecorder()
			tt.handler(rec, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}

// TestHandlePIV_MethodNotAllowed exercises wrong HTTP methods for PIV handlers.
func TestHandlePIV_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("ExportPIVCert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rec := httptest.NewRecorder()
		server.handlePIVExportCertificate(rec, req, "9a", "software")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("GeneratePIVKey", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		server.handlePIVGenerateKey(rec, req, "9a", "")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("GeneratePIVCSR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		server.handlePIVGenerateCSR(rec, req, "9a", "")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("ImportPIVCert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		server.handlePIVImportCertificate(rec, req, "9a", "")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}

// TestHandleCrypto_WrongMethods exercises wrong methods for crypto handlers.
func TestHandleCrypto_WrongMethods(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("Encrypt_Get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		server.handleEncrypt(rec, req, "k", "sw")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("Decrypt_Get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		server.handleDecrypt(rec, req, "k", "sw")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("AsymEncrypt_Get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		server.handleAsymmetricEncrypt(rec, req, "k", "sw")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}

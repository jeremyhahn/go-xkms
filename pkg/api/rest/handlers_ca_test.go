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

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	transport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCAServicer implements caServicer for testing.
type mockCAServicer struct {
	getBundleResp   *transport.GetCABundleResponse
	getBundleErr    error
	getCertResp     *transport.GetCACertificateResponse
	getCertErr      error
	signCSRResp     *transport.SignCSRResponse
	signCSRErr      error
	issueCertResp   *transport.IssueCertificateResponse
	issueCertErr    error
	revokeCertResp  *transport.RevokeCertificateResponse
	revokeCertErr   error
	generateCRLResp *transport.GenerateCRLResponse
	generateCRLErr  error
	isRevokedResp   *transport.IsRevokedResponse
	isRevokedErr    error
}

func (m *mockCAServicer) GetCABundle(_ context.Context, _ *transport.GetCABundleRequest) (*transport.GetCABundleResponse, error) {
	return m.getBundleResp, m.getBundleErr
}
func (m *mockCAServicer) GetCACertificate(_ context.Context, _ *transport.GetCACertificateRequest) (*transport.GetCACertificateResponse, error) {
	return m.getCertResp, m.getCertErr
}
func (m *mockCAServicer) SignCSR(_ context.Context, _ *transport.SignCSRRequest) (*transport.SignCSRResponse, error) {
	return m.signCSRResp, m.signCSRErr
}
func (m *mockCAServicer) IssueCertificate(_ context.Context, _ *transport.IssueCertificateRequest) (*transport.IssueCertificateResponse, error) {
	return m.issueCertResp, m.issueCertErr
}
func (m *mockCAServicer) RevokeCertificate(_ context.Context, _ *transport.RevokeCertificateRequest) (*transport.RevokeCertificateResponse, error) {
	return m.revokeCertResp, m.revokeCertErr
}
func (m *mockCAServicer) GenerateCRL(_ context.Context, _ *transport.GenerateCRLRequest) (*transport.GenerateCRLResponse, error) {
	return m.generateCRLResp, m.generateCRLErr
}
func (m *mockCAServicer) IsRevoked(_ context.Context, _ *transport.IsRevokedRequest) (*transport.IsRevokedResponse, error) {
	return m.isRevokedResp, m.isRevokedErr
}

func newTestCAHandlers(mock *mockCAServicer) *CAHandlers {
	return NewCAHandlers(mock, slog.Default())
}

func TestNewCAHandlers_NilLogger(t *testing.T) {
	h := NewCAHandlers(&mockCAServicer{}, nil)
	assert.NotNil(t, h)
	assert.NotNil(t, h.logger)
}

func TestHandleGetCABundle_Success(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{
		getBundleResp: &transport.GetCABundleResponse{BundlePEM: []byte("cert-pem")},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle?store_type=x509", nil)
	w := httptest.NewRecorder()
	h.HandleGetCABundle(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleGetCABundle_Error(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{getBundleErr: xkms.ErrNotConfigured})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/bundle", nil)
	w := httptest.NewRecorder()
	h.HandleGetCABundle(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleGetCACertificate_Success(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{
		getCertResp: &transport.GetCACertificateResponse{CertificatePEM: []byte("cert")},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificate?identity=root", nil)
	w := httptest.NewRecorder()
	h.HandleGetCACertificate(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleGetCACertificate_Error(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{getCertErr: xkms.ErrCertNotFound})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificate", nil)
	w := httptest.NewRecorder()
	h.HandleGetCACertificate(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleSignCSR_Success(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{
		signCSRResp: &transport.SignCSRResponse{CertificatePEM: []byte("cert"), SerialNumber: "123"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/sign-csr",
		strings.NewReader(`{"csr_pem":"LS0tLS1CRUdJTi0tLS0t"}`))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleSignCSR_InvalidJSON(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/sign-csr", strings.NewReader(`{bad`))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSignCSR_MissingCSR(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/sign-csr", strings.NewReader(`{"csr_pem":""}`))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSignCSR_Error(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{signCSRErr: errors.New("internal")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/sign-csr",
		strings.NewReader(`{"csr_pem":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()
	h.HandleSignCSR(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleIssueCertificate_Success(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{
		issueCertResp: &transport.IssueCertificateResponse{CertificatePEM: []byte("cert"), SerialNumber: "456"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/issue",
		strings.NewReader(`{"common_name":"test.example.com","profile":"server"}`))
	w := httptest.NewRecorder()
	h.HandleIssueCertificate(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestHandleIssueCertificate_InvalidJSON(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/issue", strings.NewReader(`{bad`))
	w := httptest.NewRecorder()
	h.HandleIssueCertificate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueCertificate_MissingCommonName(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/issue",
		strings.NewReader(`{"common_name":"","profile":"server"}`))
	w := httptest.NewRecorder()
	h.HandleIssueCertificate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueCertificate_MissingProfile(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/issue",
		strings.NewReader(`{"common_name":"test","profile":""}`))
	w := httptest.NewRecorder()
	h.HandleIssueCertificate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueCertificate_Error(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{issueCertErr: xkms.ErrInvalidKeyAttributes})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/issue",
		strings.NewReader(`{"common_name":"test","profile":"server"}`))
	w := httptest.NewRecorder()
	h.HandleIssueCertificate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRevokeCertificate_Success(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{
		revokeCertResp: &transport.RevokeCertificateResponse{Success: true},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/revoke",
		strings.NewReader(`{"serial_number":"789"}`))
	w := httptest.NewRecorder()
	h.HandleRevokeCertificate(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleRevokeCertificate_InvalidJSON(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/revoke", strings.NewReader(`{bad`))
	w := httptest.NewRecorder()
	h.HandleRevokeCertificate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRevokeCertificate_MissingSerial(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/revoke",
		strings.NewReader(`{"serial_number":""}`))
	w := httptest.NewRecorder()
	h.HandleRevokeCertificate(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleRevokeCertificate_Error(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{revokeCertErr: errors.New("revoke failed")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/revoke",
		strings.NewReader(`{"serial_number":"789"}`))
	w := httptest.NewRecorder()
	h.HandleRevokeCertificate(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleGenerateCRL_Success(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{
		generateCRLResp: &transport.GenerateCRLResponse{CRLPEM: []byte("crl-data")},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/crl", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.HandleGenerateCRL(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleGenerateCRL_EmptyBody(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{
		generateCRLResp: &transport.GenerateCRLResponse{CRLPEM: []byte("crl-data")},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/crl", strings.NewReader(``))
	w := httptest.NewRecorder()
	h.HandleGenerateCRL(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleGenerateCRL_Error(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{generateCRLErr: errors.New("crl failed")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/crl", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	h.HandleGenerateCRL(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleIsRevoked_Success(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{
		isRevokedResp: &transport.IsRevokedResponse{Revoked: false},
	})
	r := chi.NewRouter()
	r.Get("/api/v1/ca/revoked/{serial}", h.HandleIsRevoked)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/revoked/123456", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp transport.IsRevokedResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Revoked)
}

func TestHandleIsRevoked_MissingSerial(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/revoked/", nil)
	w := httptest.NewRecorder()
	h.HandleIsRevoked(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIsRevoked_Error(t *testing.T) {
	h := newTestCAHandlers(&mockCAServicer{isRevokedErr: xkms.ErrCertNotFound})
	r := chi.NewRouter()
	r.Get("/api/v1/ca/revoked/{serial}", h.HandleIsRevoked)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/revoked/999", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestMapCAError_AllCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"NotConfigured", xkms.ErrNotConfigured, http.StatusServiceUnavailable},
		{"NilRequest", xkms.ErrNilRequest, http.StatusBadRequest},
		{"NilData", xkms.ErrNilData, http.StatusBadRequest},
		{"InvalidKeyAttributes", xkms.ErrInvalidKeyAttributes, http.StatusBadRequest},
		{"CertNotFound", xkms.ErrCertNotFound, http.StatusNotFound},
		{"InvalidEncodingPEM", xkms.ErrInvalidEncodingPEM, http.StatusBadRequest},
		{"Unknown", errors.New("unknown"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantStatus, mapCAError(tt.err))
		})
	}
}

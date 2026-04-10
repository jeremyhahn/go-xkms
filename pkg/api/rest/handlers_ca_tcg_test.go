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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	transport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
)

// mockTCGCAServicer implements both caServicer and tcgCAServicer for testing.
type mockTCGCAServicer struct {
	mockCAServicer
	issueEKResp *transport.IssueEKCertificateResponse
	issueEKErr  error
	issueAKResp *transport.IssueAKCertificateResponse
	issueAKErr  error
	signTCGResp *transport.SignTCGCSRResponse
	signTCGErr  error
	enrollResp  *transport.EnrollDeviceResponse
	enrollErr   error
}

func (m *mockTCGCAServicer) IssueEKCertificate(_ context.Context, _ *transport.IssueEKCertificateRequest) (*transport.IssueEKCertificateResponse, error) {
	return m.issueEKResp, m.issueEKErr
}

func (m *mockTCGCAServicer) IssueAKCertificate(_ context.Context, _ *transport.IssueAKCertificateRequest) (*transport.IssueAKCertificateResponse, error) {
	return m.issueAKResp, m.issueAKErr
}

func (m *mockTCGCAServicer) SignTCGCSR(_ context.Context, _ *transport.SignTCGCSRRequest) (*transport.SignTCGCSRResponse, error) {
	return m.signTCGResp, m.signTCGErr
}

func (m *mockTCGCAServicer) EnrollDevice(_ context.Context, _ *transport.EnrollDeviceRequest) (*transport.EnrollDeviceResponse, error) {
	return m.enrollResp, m.enrollErr
}

func newTestTCGCAHandlers(mock *mockTCGCAServicer) *CAHandlers {
	return NewCAHandlers(mock, slog.Default())
}

// --- tcgCAError ---

func TestTCGCAError_Error(t *testing.T) {
	err := &tcgCAError{msg: "test error"}
	assert.Equal(t, "test error", err.Error())
}

// --- HandleIssueEKCertificate ---

func TestHandleIssueEKCertificate_Success(t *testing.T) {
	mock := &mockTCGCAServicer{
		issueEKResp: &transport.IssueEKCertificateResponse{
			CertificatePEM: []byte("ek-cert"),
			SerialNumber:   "100",
		},
	}
	h := newTestTCGCAHandlers(mock)

	body := `{"common_name":"device1","ek_public_key":"ZGF0YQ=="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ek",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	h.HandleIssueEKCertificate(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestHandleIssueEKCertificate_NotSupported(t *testing.T) {
	h := NewCAHandlers(&mockCAServicer{}, slog.Default())

	body := `{"common_name":"device1","ek_public_key":"ZGF0YQ=="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ek",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	h.HandleIssueEKCertificate(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleIssueEKCertificate_InvalidJSON(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ek",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.HandleIssueEKCertificate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueEKCertificate_MissingCommonName(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ek",
		strings.NewReader(`{"common_name":"","ek_public_key":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleIssueEKCertificate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueEKCertificate_MissingEKPublicKey(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ek",
		strings.NewReader(`{"common_name":"device1"}`))
	w := httptest.NewRecorder()

	h.HandleIssueEKCertificate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueEKCertificate_Error(t *testing.T) {
	mock := &mockTCGCAServicer{
		issueEKErr: errors.New("ek failed"),
	}
	h := newTestTCGCAHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ek",
		strings.NewReader(`{"common_name":"device1","ek_public_key":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleIssueEKCertificate(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- HandleIssueAKCertificate ---

func TestHandleIssueAKCertificate_Success(t *testing.T) {
	mock := &mockTCGCAServicer{
		issueAKResp: &transport.IssueAKCertificateResponse{
			CertificatePEM: []byte("ak-cert"),
			SerialNumber:   "200",
		},
	}
	h := newTestTCGCAHandlers(mock)

	body := `{"common_name":"device1","public_key":"ZGF0YQ=="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ak",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	h.HandleIssueAKCertificate(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestHandleIssueAKCertificate_NotSupported(t *testing.T) {
	h := NewCAHandlers(&mockCAServicer{}, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ak",
		strings.NewReader(`{"common_name":"d1","public_key":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleIssueAKCertificate(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleIssueAKCertificate_InvalidJSON(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ak",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.HandleIssueAKCertificate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueAKCertificate_MissingCommonName(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ak",
		strings.NewReader(`{"common_name":"","public_key":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleIssueAKCertificate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueAKCertificate_MissingPublicKey(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ak",
		strings.NewReader(`{"common_name":"device1"}`))
	w := httptest.NewRecorder()

	h.HandleIssueAKCertificate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleIssueAKCertificate_Error(t *testing.T) {
	mock := &mockTCGCAServicer{
		issueAKErr: errors.New("ak failed"),
	}
	h := newTestTCGCAHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/ak",
		strings.NewReader(`{"common_name":"d1","public_key":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleIssueAKCertificate(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- HandleSignTCGCSR ---

func TestHandleSignTCGCSR_Success(t *testing.T) {
	mock := &mockTCGCAServicer{
		signTCGResp: &transport.SignTCGCSRResponse{},
	}
	h := newTestTCGCAHandlers(mock)

	body := `{"common_name":"device1","tcg_csr":"ZGF0YQ=="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/sign-csr",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	h.HandleSignTCGCSR(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleSignTCGCSR_NotSupported(t *testing.T) {
	h := NewCAHandlers(&mockCAServicer{}, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/sign-csr",
		strings.NewReader(`{"common_name":"d1","tcg_csr":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleSignTCGCSR(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleSignTCGCSR_InvalidJSON(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/sign-csr",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.HandleSignTCGCSR(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSignTCGCSR_MissingCommonName(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/sign-csr",
		strings.NewReader(`{"common_name":"","tcg_csr":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleSignTCGCSR(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSignTCGCSR_MissingTCGCSR(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/sign-csr",
		strings.NewReader(`{"common_name":"device1"}`))
	w := httptest.NewRecorder()

	h.HandleSignTCGCSR(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSignTCGCSR_Error(t *testing.T) {
	mock := &mockTCGCAServicer{
		signTCGErr: errors.New("sign failed"),
	}
	h := newTestTCGCAHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/sign-csr",
		strings.NewReader(`{"common_name":"d1","tcg_csr":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleSignTCGCSR(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- HandleEnrollDevice ---

func TestHandleEnrollDevice_Success(t *testing.T) {
	mock := &mockTCGCAServicer{
		enrollResp: &transport.EnrollDeviceResponse{},
	}
	h := newTestTCGCAHandlers(mock)

	body := `{"common_name":"device1","packed_csr":"ZGF0YQ=="}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/enroll",
		strings.NewReader(body))
	w := httptest.NewRecorder()

	h.HandleEnrollDevice(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestHandleEnrollDevice_NotSupported(t *testing.T) {
	h := NewCAHandlers(&mockCAServicer{}, slog.Default())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/enroll",
		strings.NewReader(`{"common_name":"d1","packed_csr":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleEnrollDevice(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleEnrollDevice_InvalidJSON(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/enroll",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	h.HandleEnrollDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleEnrollDevice_MissingCommonName(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/enroll",
		strings.NewReader(`{"common_name":"","packed_csr":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleEnrollDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleEnrollDevice_MissingPackedCSR(t *testing.T) {
	h := newTestTCGCAHandlers(&mockTCGCAServicer{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/enroll",
		strings.NewReader(`{"common_name":"device1"}`))
	w := httptest.NewRecorder()

	h.HandleEnrollDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleEnrollDevice_Error(t *testing.T) {
	mock := &mockTCGCAServicer{
		enrollErr: errors.New("enroll failed"),
	}
	h := newTestTCGCAHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/tcg/enroll",
		strings.NewReader(`{"common_name":"d1","packed_csr":"ZGF0YQ=="}`))
	w := httptest.NewRecorder()

	h.HandleEnrollDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

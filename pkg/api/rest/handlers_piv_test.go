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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
)

// PIV handler tests focus on input validation paths since the handlers
// use package-level xkms functions that require full backend initialization.

func pivRouter(h *HandlerContext) *chi.Mux {
	r := chi.NewRouter()
	r.Get("/api/v1/piv/slots", h.ListPIVSlotsHandler)
	r.Get("/api/v1/piv/slots/{slot}/certificate", h.GetPIVCertificateHandler)
	r.Post("/api/v1/piv/slots/{slot}/certificate", h.StorePIVCertificateHandler)
	r.Delete("/api/v1/piv/slots/{slot}/certificate", h.DeletePIVCertificateHandler)
	r.Post("/api/v1/piv/slots/{slot}/generate", h.GeneratePIVKeyHandler)
	r.Post("/api/v1/piv/slots/{slot}/import", h.ImportPIVCertificateHandler)
	r.Get("/api/v1/piv/slots/{slot}/export", h.ExportPIVCertificateHandler)
	r.Post("/api/v1/piv/slots/{slot}/csr", h.GeneratePIVCSRHandler)
	return r
}

// --- ListPIVSlotsHandler ---

func TestPIV_ListSlots_MissingBackend(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_ListSlots_PIVNotInitialized(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	// xkms is not initialized so PIV will fail.
	xkms.Reset()
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots?backend=test", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Should return an error (PIV not initialized or service not available).
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// --- GetPIVCertificateHandler ---

func TestPIV_GetCertificate_MissingSlot(t *testing.T) {
	h := newTestHandlerContext()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots//certificate?backend=test", nil)
	w := httptest.NewRecorder()

	h.GetPIVCertificateHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_GetCertificate_MissingBackend(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/certificate", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- StorePIVCertificateHandler ---

func TestPIV_StoreCertificate_MissingSlot(t *testing.T) {
	h := newTestHandlerContext()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots//certificate",
		strings.NewReader(`{"backend":"test","certificate":"data","format":"pem"}`))
	w := httptest.NewRecorder()

	h.StorePIVCertificateHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_StoreCertificate_InvalidJSON(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/certificate",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_StoreCertificate_MissingBackend(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/certificate",
		strings.NewReader(`{"backend":"","certificate":"data","format":"pem"}`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- DeletePIVCertificateHandler ---

func TestPIV_DeleteCertificate_MissingSlot(t *testing.T) {
	h := newTestHandlerContext()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/piv/slots//certificate?backend=test", nil)
	w := httptest.NewRecorder()

	h.DeletePIVCertificateHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_DeleteCertificate_MissingBackend(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/piv/slots/9a/certificate", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- GeneratePIVKeyHandler ---

func TestPIV_GenerateKey_MissingSlot(t *testing.T) {
	h := newTestHandlerContext()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots//generate",
		strings.NewReader(`{"backend":"test","algorithm":"ECCP256"}`))
	w := httptest.NewRecorder()

	h.GeneratePIVKeyHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_GenerateKey_InvalidJSON(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/generate",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_GenerateKey_MissingBackend(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/generate",
		strings.NewReader(`{"backend":"","algorithm":"ECCP256"}`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- ImportPIVCertificateHandler ---

func TestPIV_ImportCertificate_MissingSlot(t *testing.T) {
	h := newTestHandlerContext()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots//import",
		strings.NewReader(`{"backend":"test","certificate":"data"}`))
	w := httptest.NewRecorder()

	h.ImportPIVCertificateHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_ImportCertificate_InvalidJSON(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/import",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_ImportCertificate_MissingBackend(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/import",
		strings.NewReader(`{"backend":"","certificate":"data"}`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- ExportPIVCertificateHandler ---

func TestPIV_ExportCertificate_MissingSlot(t *testing.T) {
	h := newTestHandlerContext()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots//export?backend=test", nil)
	w := httptest.NewRecorder()

	h.ExportPIVCertificateHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_ExportCertificate_MissingBackend(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/export", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- GeneratePIVCSRHandler ---

func TestPIV_GenerateCSR_MissingSlot(t *testing.T) {
	h := newTestHandlerContext()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots//csr",
		strings.NewReader(`{"backend":"test","subject":"CN=test"}`))
	w := httptest.NewRecorder()

	h.GeneratePIVCSRHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_GenerateCSR_InvalidJSON(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/csr",
		strings.NewReader(`{bad`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPIV_GenerateCSR_MissingBackend(t *testing.T) {
	h := newTestHandlerContext()
	r := pivRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/csr",
		strings.NewReader(`{"backend":"","subject":"CN=test"}`))
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- handlePIVError ---

func TestHandlePIVError_AllCases(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"PIVNotInitialized", xkms.ErrPIVNotInitialized, http.StatusServiceUnavailable},
		{"PIVBackendNotFound", xkms.ErrPIVBackendNotFound, http.StatusNotFound},
		{"PIVInvalidSlot", xkms.ErrPIVInvalidSlot, http.StatusBadRequest},
		{"PIVInvalidFormat", xkms.ErrPIVInvalidFormat, http.StatusBadRequest},
		{"PIVInvalidAlgorithm", xkms.ErrPIVInvalidAlgorithm, http.StatusBadRequest},
		{"PIVKeyNotFound", xkms.ErrPIVKeyNotFound, http.StatusNotFound},
		{"Unknown", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handlePIVError(w, tt.err)
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

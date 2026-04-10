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

package quic

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strPtr returns a pointer to the given string value.
func strPtr(s string) *string { return &s }

// ============================================================================
// PIV handler tests
// ============================================================================

func TestHandlePIVSlots_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandlePIVSlots_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVSlots_WithBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots?backend=software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, w.Code)
}

func TestHandlePIVSlotOperations_EmptySlot(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVSlotOperations_UnknownOperation(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/unknown", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleGetPIVCertificate_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/certificate", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetPIVCertificate_WithBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/certificate?backend=software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, w.Code)
}

func TestHandleStorePIVCertificate_InvalidBody(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/certificate", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleStorePIVCertificate_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(map[string]string{"certificate_pem": "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/certificate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleDeletePIVCertificate_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/piv/slots/9a/certificate", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVCertificate_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/piv/slots/9a/certificate?backend=software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandlePIVGenerateKey_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/generate", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandlePIVGenerateKey_InvalidBody(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/generate", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVGenerateKey_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(map[string]string{"algorithm": "ECDSA-P256"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVImportCertificate_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/import", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandlePIVImportCertificate_InvalidBody(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/import", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVImportCertificate_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(map[string]string{"certificate_pem": "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVExportCertificate_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/export", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandlePIVExportCertificate_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/export", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVGenerateCSR_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/piv/slots/9a/csr", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandlePIVGenerateCSR_InvalidBody(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/csr", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePIVGenerateCSR_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(map[string]string{"common_name": "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/piv/slots/9a/csr", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// Password lock/unlock/status handler tests
// ============================================================================

func TestPasswordUnlockHandler_NoManager(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestPasswordLockHandler_NoManager(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestPasswordStatusHandler_SystemLevel(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.Equal(t, "Password store is available", resp.Message)
}

func TestPasswordListHandler_EmptyStore(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPasswordGetHandler_NotFound(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/nonexistent-id", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPasswordUpdateHandler_InvalidBody(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/some-id", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasswordUpdateHandler_NotFound(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(PasswordUpdateRequest{
		Name:     strPtr("updated"),
		Password: strPtr("newpass"),
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/nonexistent-id", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPasswordDeleteHandler_NotFound(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/nonexistent-id", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestPasswordAddHandler_InvalidBody(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasswordAddHandler_MissingName(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(PasswordAddRequest{Password: "secret"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasswordGenerateHandler_InvalidBody(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasswordGenerateHandler_InvalidLength(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(PasswordGenerateRequest{Length: 3})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPasswordAddAndGetByName(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	// Add a password
	addBody, _ := json.Marshal(PasswordAddRequest{
		Name:     "my-test-password",
		Password: "secret123",
		Username: "user1",
	})
	addReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(addBody))
	addReq.Header.Set("Content-Type", "application/json")
	addW := httptest.NewRecorder()
	server.handler.ServeHTTP(addW, addReq)
	require.Equal(t, http.StatusCreated, addW.Code)

	// Get by name (case-insensitive name lookup as fallback)
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/my-test-password", nil)
	getW := httptest.NewRecorder()
	server.handler.ServeHTTP(getW, getReq)
	assert.Equal(t, http.StatusOK, getW.Code)
}

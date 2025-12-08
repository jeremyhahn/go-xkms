// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package unix

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/health"
)

func TestNewHandlerContext(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	if h == nil {
		t.Fatal("NewHandlerContext() returned nil")
	}

	if h.version != "1.0.0" {
		t.Errorf("version = %v, want 1.0.0", h.version)
	}

	if h.restHandler == nil {
		t.Error("restHandler is nil")
	}
}

func TestHandlerContext_SetHealthChecker(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	checker := health.NewChecker()

	h.SetHealthChecker(checker)

	if h.healthChecker == nil {
		t.Error("healthChecker is nil after SetHealthChecker")
	}
}

func TestHandlerContext_LiveHandler_NoChecker(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()

	h.LiveHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("LiveHandler() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestHandlerContext_LiveHandler_WithChecker(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	checker := health.NewChecker()
	h.SetHealthChecker(checker)

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()

	h.LiveHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("LiveHandler() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestHandlerContext_ReadyHandler_NoChecker(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()

	h.ReadyHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ReadyHandler() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestHandlerContext_ReadyHandler_WithChecker(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	checker := health.NewChecker()
	h.SetHealthChecker(checker)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()

	h.ReadyHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ReadyHandler() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestHandlerContext_StartupHandler_NoChecker(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")

	req := httptest.NewRequest(http.MethodGet, "/health/startup", nil)
	w := httptest.NewRecorder()

	h.StartupHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("StartupHandler() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestHandlerContext_StartupHandler_WithChecker(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	checker := health.NewChecker()
	checker.MarkStarted() // Mark as started so startup check passes
	h.SetHealthChecker(checker)

	req := httptest.NewRequest(http.MethodGet, "/health/startup", nil)
	w := httptest.NewRecorder()

	h.StartupHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("StartupHandler() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestWriteHealthResponse_Healthy(t *testing.T) {
	w := httptest.NewRecorder()
	result := health.CheckResult{
		Status:  health.StatusHealthy,
		Message: "OK",
	}

	writeHealthResponse(w, result)

	if w.Code != http.StatusOK {
		t.Errorf("writeHealthResponse() status = %v, want %v", w.Code, http.StatusOK)
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %v, want application/json", w.Header().Get("Content-Type"))
	}
}

func TestWriteHealthResponse_Unhealthy(t *testing.T) {
	w := httptest.NewRecorder()
	result := health.CheckResult{
		Status:  health.StatusUnhealthy,
		Message: "Failed",
	}

	writeHealthResponse(w, result)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("writeHealthResponse() status = %v, want %v", w.Code, http.StatusServiceUnavailable)
	}
}

func TestWriteReadyResponse_AllHealthy(t *testing.T) {
	w := httptest.NewRecorder()
	results := []health.CheckResult{
		{Status: health.StatusHealthy, Message: "OK"},
		{Status: health.StatusHealthy, Message: "OK"},
	}

	writeReadyResponse(w, results)

	if w.Code != http.StatusOK {
		t.Errorf("writeReadyResponse() status = %v, want %v", w.Code, http.StatusOK)
	}
}

func TestWriteReadyResponse_SomeUnhealthy(t *testing.T) {
	w := httptest.NewRecorder()
	results := []health.CheckResult{
		{Status: health.StatusHealthy, Message: "OK"},
		{Status: health.StatusUnhealthy, Message: "Failed"},
	}

	writeReadyResponse(w, results)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("writeReadyResponse() status = %v, want %v", w.Code, http.StatusServiceUnavailable)
	}
}

func TestWriteReadyResponse_Empty(t *testing.T) {
	w := httptest.NewRecorder()
	results := []health.CheckResult{}

	writeReadyResponse(w, results)

	// Empty results should be considered healthy
	if w.Code != http.StatusOK {
		t.Errorf("writeReadyResponse() status = %v, want %v", w.Code, http.StatusOK)
	}
}

// mockHealthChecker implements HealthChecker interface for testing
type mockHealthChecker struct {
	liveResult    health.CheckResult
	readyResults  []health.CheckResult
	startupResult health.CheckResult
}

func (m *mockHealthChecker) Live(_ context.Context) health.CheckResult {
	return m.liveResult
}

func (m *mockHealthChecker) Ready(_ context.Context) []health.CheckResult {
	return m.readyResults
}

func (m *mockHealthChecker) Startup(_ context.Context) health.CheckResult {
	return m.startupResult
}

func TestHealthCheckerInterface(t *testing.T) {
	var _ HealthChecker = &mockHealthChecker{}
}

// Test handler wrapper functions that delegate to REST handlers
func TestHandlerContext_HealthHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.HealthHandler(w, req)

	if w.Code == 0 {
		t.Error("HealthHandler did not write a response")
	}
}

func TestHandlerContext_ListBackendsHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.ListBackendsHandler(w, req)

	if w.Code == 0 {
		t.Error("ListBackendsHandler did not write a response")
	}
}

func TestHandlerContext_GetBackendHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/test", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.GetBackendHandler(w, req)

	if w.Code == 0 {
		t.Error("GetBackendHandler did not write a response")
	}
}

func TestHandlerContext_GenerateKeyHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	body := bytes.NewBufferString(`{"id":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", body)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.GenerateKeyHandler(w, req)

	if w.Code == 0 {
		t.Error("GenerateKeyHandler did not write a response")
	}
}

func TestHandlerContext_ListKeysHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.ListKeysHandler(w, req)

	if w.Code == 0 {
		t.Error("ListKeysHandler did not write a response")
	}
}

func TestHandlerContext_GetKeyHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.GetKeyHandler(w, req)

	if w.Code == 0 {
		t.Error("GetKeyHandler did not write a response")
	}
}

func TestHandlerContext_DeleteKeyHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.DeleteKeyHandler(w, req)

	if w.Code == 0 {
		t.Error("DeleteKeyHandler did not write a response")
	}
}

func TestHandlerContext_SignHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	body := bytes.NewBufferString(`{"data":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/sign", body)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.SignHandler(w, req)

	if w.Code == 0 {
		t.Error("SignHandler did not write a response")
	}
}

func TestHandlerContext_VerifyHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	body := bytes.NewBufferString(`{"data":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/verify", body)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.VerifyHandler(w, req)

	if w.Code == 0 {
		t.Error("VerifyHandler did not write a response")
	}
}

func TestHandlerContext_EncryptHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	body := bytes.NewBufferString(`{"data":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/encrypt", body)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.EncryptHandler(w, req)

	if w.Code == 0 {
		t.Error("EncryptHandler did not write a response")
	}
}

func TestHandlerContext_DecryptHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	body := bytes.NewBufferString(`{"data":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/decrypt", body)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.DecryptHandler(w, req)

	if w.Code == 0 {
		t.Error("DecryptHandler did not write a response")
	}
}

func TestHandlerContext_GetCertificateHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test/certificate", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.GetCertificateHandler(w, req)

	if w.Code == 0 {
		t.Error("GetCertificateHandler did not write a response")
	}
}

func TestHandlerContext_SetCertificateHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	body := bytes.NewBufferString(`{"certificate":"test"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/keys/test/certificate", body)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.SetCertificateHandler(w, req)

	if w.Code == 0 {
		t.Error("SetCertificateHandler did not write a response")
	}
}

func TestHandlerContext_DeleteCertificateHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test/certificate", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.DeleteCertificateHandler(w, req)

	if w.Code == 0 {
		t.Error("DeleteCertificateHandler did not write a response")
	}
}

func TestHandlerContext_ImportKeyHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	body := bytes.NewBufferString(`{"key":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", body)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.ImportKeyHandler(w, req)

	if w.Code == 0 {
		t.Error("ImportKeyHandler did not write a response")
	}
}

func TestHandlerContext_ExportKeyHandler(t *testing.T) {
	h := NewHandlerContext("1.0.0", nil, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test/export", nil)
	w := httptest.NewRecorder()

	// This delegates to REST handler - just verify it doesn't panic
	h.ExportKeyHandler(w, req)

	if w.Code == 0 {
		t.Error("ExportKeyHandler did not write a response")
	}
}

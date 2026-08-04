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
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// testHealthChecker implements qrdbsdk.HealthChecker for testing
type testHealthChecker struct {
	liveResult    qrdbsdk.HealthCheckResult
	readyResults  []qrdbsdk.HealthCheckResult
	startupResult qrdbsdk.HealthCheckResult
}

func (m *testHealthChecker) Live(ctx context.Context) qrdbsdk.HealthCheckResult {
	return m.liveResult
}

func (m *testHealthChecker) Ready(ctx context.Context) []qrdbsdk.HealthCheckResult {
	return m.readyResults
}

func (m *testHealthChecker) Startup(ctx context.Context) qrdbsdk.HealthCheckResult {
	return m.startupResult
}

func TestLivenessHandler_NoHealthChecker(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()

	h.LivenessHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusHealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusHealthy, resp.Status)
	}
}

func TestLivenessHandler_Healthy(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: &testHealthChecker{
			liveResult: qrdbsdk.HealthCheckResult{
				Status:  qrdbsdk.HealthCheckStatusHealthy,
				Message: "OK",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()

	h.LivenessHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusHealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusHealthy, resp.Status)
	}
}

func TestLivenessHandler_Unhealthy(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: &testHealthChecker{
			liveResult: qrdbsdk.HealthCheckResult{
				Status:  qrdbsdk.HealthCheckStatusUnhealthy,
				Message: "Service is dead",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()

	h.LivenessHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusUnhealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusUnhealthy, resp.Status)
	}
}

func TestReadinessHandler_NoHealthChecker(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()

	h.ReadinessHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusHealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusHealthy, resp.Status)
	}
}

func TestReadinessHandler_Healthy(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: &testHealthChecker{
			readyResults: []qrdbsdk.HealthCheckResult{
				{Name: "db", Status: qrdbsdk.HealthCheckStatusHealthy, Message: "Connected"},
				{Name: "cache", Status: qrdbsdk.HealthCheckStatusHealthy, Message: "Connected"},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()

	h.ReadinessHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusHealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusHealthy, resp.Status)
	}

	if len(resp.Checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(resp.Checks))
	}
}

func TestReadinessHandler_Degraded(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: &testHealthChecker{
			readyResults: []qrdbsdk.HealthCheckResult{
				{Name: "db", Status: qrdbsdk.HealthCheckStatusHealthy, Message: "Connected"},
				{Name: "cache", Status: qrdbsdk.HealthCheckStatusDegraded, Message: "High latency"},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()

	h.ReadinessHandler(w, req)

	// Degraded should still return 200 OK as service is still serving
	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusDegraded {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusDegraded, resp.Status)
	}

	if resp.Message != "Service is degraded" {
		t.Errorf("expected message 'Service is degraded', got %q", resp.Message)
	}
}

func TestReadinessHandler_Unhealthy(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: &testHealthChecker{
			readyResults: []qrdbsdk.HealthCheckResult{
				{Name: "db", Status: qrdbsdk.HealthCheckStatusUnhealthy, Message: "Connection refused"},
				{Name: "cache", Status: qrdbsdk.HealthCheckStatusHealthy, Message: "Connected"},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()

	h.ReadinessHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusUnhealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusUnhealthy, resp.Status)
	}

	if resp.Message != "One or more checks failed" {
		t.Errorf("expected message 'One or more checks failed', got %q", resp.Message)
	}
}

func TestStartupHandler_NoHealthChecker(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/health/startup", nil)
	w := httptest.NewRecorder()

	h.StartupHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusHealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusHealthy, resp.Status)
	}
}

func TestStartupHandler_Started(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: &testHealthChecker{
			startupResult: qrdbsdk.HealthCheckResult{
				Status:  qrdbsdk.HealthCheckStatusHealthy,
				Message: "Service started",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/health/startup", nil)
	w := httptest.NewRecorder()

	h.StartupHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusHealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusHealthy, resp.Status)
	}
}

func TestStartupHandler_NotStarted(t *testing.T) {
	h := &HandlerContext{
		HealthChecker: &testHealthChecker{
			startupResult: qrdbsdk.HealthCheckResult{
				Status:  qrdbsdk.HealthCheckStatusUnhealthy,
				Message: "Service still starting",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/health/startup", nil)
	w := httptest.NewRecorder()

	h.StartupHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	var resp HealthCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != qrdbsdk.HealthCheckStatusUnhealthy {
		t.Errorf("expected status %s, got %s", qrdbsdk.HealthCheckStatusUnhealthy, resp.Status)
	}
}

func TestHealthCheckResponse_JSON(t *testing.T) {
	resp := HealthCheckResponse{
		Status:  qrdbsdk.HealthCheckStatusHealthy,
		Message: "test message",
		Checks: []qrdbsdk.HealthCheckResult{
			{Name: "test", Status: qrdbsdk.HealthCheckStatusHealthy, Message: "OK"},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded HealthCheckResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Status != resp.Status {
		t.Errorf("Status mismatch: got %v, want %v", decoded.Status, resp.Status)
	}

	if decoded.Message != resp.Message {
		t.Errorf("Message mismatch: got %v, want %v", decoded.Message, resp.Message)
	}

	if len(decoded.Checks) != len(resp.Checks) {
		t.Errorf("Checks length mismatch: got %v, want %v", len(decoded.Checks), len(resp.Checks))
	}
}

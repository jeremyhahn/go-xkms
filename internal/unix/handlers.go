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
	"context"
	"log"
	"net/http"

	"github.com/jeremyhahn/go-keychain/internal/rest"
	"github.com/jeremyhahn/go-keychain/pkg/health"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
)

// HandlerContext wraps the REST handler context for Unix socket use.
// It provides all the same HTTP handlers but configured for local IPC.
type HandlerContext struct {
	restHandler   *rest.HandlerContext
	healthChecker *health.Checker
	version       string
}

// NewHandlerContext creates a new handler context for Unix socket handlers.
// It reuses the REST handlers since they use the same HTTP semantics.
// The backends should already be registered with the keychain service by the main server.
func NewHandlerContext(version string, backends map[string]keychain.KeyStore, defaultBackend string) *HandlerContext {
	// Note: backends are already registered with the keychain service by the main server
	// via keychain.Initialize() during startup. The REST handlers use the global
	// keychain service to look up backends by name.
	_ = backends       // Available but not used directly - REST handlers use keychain service
	_ = defaultBackend // Available but not used directly

	return &HandlerContext{
		restHandler: rest.NewHandlerContext(version),
		version:     version,
	}
}

// SetHealthChecker sets the health checker for the handler context.
func (h *HandlerContext) SetHealthChecker(checker *health.Checker) {
	h.healthChecker = checker
	h.restHandler.SetHealthChecker(checker)
}

// HealthHandler handles GET /health requests.
func (h *HandlerContext) HealthHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.HealthHandler(w, r)
}

// LiveHandler handles GET /health/live requests.
func (h *HandlerContext) LiveHandler(w http.ResponseWriter, r *http.Request) {
	if h.healthChecker != nil {
		result := h.healthChecker.Live(r.Context())
		writeHealthResponse(w, result)
		return
	}
	writeHealthResponse(w, health.CheckResult{
		Status:  health.StatusHealthy,
		Message: "Live",
	})
}

// ReadyHandler handles GET /health/ready requests.
func (h *HandlerContext) ReadyHandler(w http.ResponseWriter, r *http.Request) {
	if h.healthChecker != nil {
		results := h.healthChecker.Ready(r.Context())
		writeReadyResponse(w, results)
		return
	}
	writeHealthResponse(w, health.CheckResult{
		Status:  health.StatusHealthy,
		Message: "Ready",
	})
}

// StartupHandler handles GET /health/startup requests.
func (h *HandlerContext) StartupHandler(w http.ResponseWriter, r *http.Request) {
	if h.healthChecker != nil {
		result := h.healthChecker.Startup(r.Context())
		writeHealthResponse(w, result)
		return
	}
	writeHealthResponse(w, health.CheckResult{
		Status:  health.StatusHealthy,
		Message: "Started",
	})
}

// ListBackendsHandler handles GET /api/v1/backends requests.
func (h *HandlerContext) ListBackendsHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.ListBackendsHandler(w, r)
}

// GetBackendHandler handles GET /api/v1/backends/{id} requests.
func (h *HandlerContext) GetBackendHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.GetBackendHandler(w, r)
}

// GenerateKeyHandler handles POST /api/v1/keys requests.
func (h *HandlerContext) GenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.GenerateKeyHandler(w, r)
}

// ListKeysHandler handles GET /api/v1/keys requests.
func (h *HandlerContext) ListKeysHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.ListKeysHandler(w, r)
}

// GetKeyHandler handles GET /api/v1/keys/{id} requests.
func (h *HandlerContext) GetKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.GetKeyHandler(w, r)
}

// DeleteKeyHandler handles DELETE /api/v1/keys/{id} requests.
func (h *HandlerContext) DeleteKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.DeleteKeyHandler(w, r)
}

// SignHandler handles POST /api/v1/keys/{id}/sign requests.
func (h *HandlerContext) SignHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.SignHandler(w, r)
}

// VerifyHandler handles POST /api/v1/keys/{id}/verify requests.
func (h *HandlerContext) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.VerifyHandler(w, r)
}

// EncryptHandler handles POST /api/v1/keys/{id}/encrypt requests.
func (h *HandlerContext) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.EncryptHandler(w, r)
}

// DecryptHandler handles POST /api/v1/keys/{id}/decrypt requests.
func (h *HandlerContext) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.DecryptHandler(w, r)
}

// GetCertificateHandler handles GET /api/v1/keys/{id}/certificate requests.
func (h *HandlerContext) GetCertificateHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.GetCertHandler(w, r)
}

// SetCertificateHandler handles PUT /api/v1/keys/{id}/certificate requests.
func (h *HandlerContext) SetCertificateHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.SaveCertHandler(w, r)
}

// DeleteCertificateHandler handles DELETE /api/v1/keys/{id}/certificate requests.
func (h *HandlerContext) DeleteCertificateHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.DeleteCertHandler(w, r)
}

// ImportKeyHandler handles POST /api/v1/keys/import requests.
func (h *HandlerContext) ImportKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.ImportKeyHandler(w, r)
}

// ExportKeyHandler handles GET /api/v1/keys/{id}/export requests.
func (h *HandlerContext) ExportKeyHandler(w http.ResponseWriter, r *http.Request) {
	h.restHandler.ExportKeyHandler(w, r)
}

// HealthChecker interface for health checks.
type HealthChecker interface {
	Live(ctx context.Context) health.CheckResult
	Ready(ctx context.Context) []health.CheckResult
	Startup(ctx context.Context) health.CheckResult
}

// writeHealthResponse writes a health check response.
func writeHealthResponse(w http.ResponseWriter, result health.CheckResult) {
	w.Header().Set("Content-Type", "application/json")
	if result.Status == health.StatusHealthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	// Simple JSON response
	resp := `{"status":"` + string(result.Status) + `","message":"` + result.Message + `"}`
	if _, err := w.Write([]byte(resp)); err != nil {
		log.Printf("failed to write health response: %v", err)
	}
}

// writeReadyResponse writes a readiness check response.
func writeReadyResponse(w http.ResponseWriter, results []health.CheckResult) {
	w.Header().Set("Content-Type", "application/json")

	allHealthy := true
	for _, r := range results {
		if r.Status != health.StatusHealthy {
			allHealthy = false
			break
		}
	}

	if allHealthy {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"healthy","message":"All checks passed"}`)); err != nil {
			log.Printf("failed to write ready response: %v", err)
		}
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte(`{"status":"unhealthy","message":"Some checks failed"}`)); err != nil {
			log.Printf("failed to write ready response: %v", err)
		}
	}
}

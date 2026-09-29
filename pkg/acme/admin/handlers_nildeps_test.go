//go:build codec_json

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package admin

// Tests for go-xkms#1075: every admin route that reads the ACME certificate
// authority or storage factory answers RFC 7807's "501 Not Implemented"
// (the same shape ListAuditLogs already uses for a missing audit trail, see
// writeUnavailableIfNotConfigured) rather than panicking, when the admin
// surface is composed with ACME disabled.

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// newNilDepsHandlersRouter builds the real admin router (Handlers +
// PermissionGate + auth middleware, exactly as cmd/xkmsd/admin.go wires it)
// over an AdminService constructed with a nil CA and nil storage factory —
// the shape finalizeAdminModule produces when ACME is disabled.
func newNilDepsHandlersRouter() http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewAdminService(nil, nil, logger, "test-version")
	h := NewHandlers(svc, logger)

	authMiddleware := newTestAuthMiddleware(qrdbsdk.RoleNameAdmin)
	router := mux.NewRouter()
	h.RegisterRoutes(router, authMiddleware, newPermissiveGate())
	return router
}

// assertNotImplementedProblem asserts rec holds the RFC 7807 "not
// implemented" response writeUnavailableIfNotConfigured writes.
func assertNotImplementedProblem(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusNotImplemented, rec.Body.String())
	}
	var problem ProblemDetail
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem detail: %v; body = %s", err, rec.Body.String())
	}
	if problem.Type != "urn:trusted-ca:error:not-implemented" {
		t.Fatalf("problem.Type = %q, want urn:trusted-ca:error:not-implemented", problem.Type)
	}
	if problem.Status != http.StatusNotImplemented {
		t.Fatalf("problem.Status = %d, want %d", problem.Status, http.StatusNotImplemented)
	}
}

func TestHandlers_ListCertificates_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/certificates", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_GetCertificate_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/certificates/123456", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_RevokeCertificate_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	body := `{"reason":"keyCompromise"}`
	req := httptest.NewRequest("POST", "/admin/certificates/123456/revoke", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-admin-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_ListExpiringCertificates_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/certificates/expiring", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_ListAccounts_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/accounts", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_GetAccount_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/accounts/1", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_DisableAccount_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("DELETE", "/admin/accounts/1", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_ListOrders_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/orders", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_GetOrder_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/orders/1?account_id=1", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_GetStatus_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/status", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

func TestHandlers_GetStats_NilDepsNotImplemented(t *testing.T) {
	router := newNilDepsHandlersRouter()
	req := httptest.NewRequest("GET", "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assertNotImplementedProblem(t, rec)
}

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

// Test for go-xkms#1075: CreateTenantIntermediateCA's default (global-parent)
// branch dereferenced the ACME CA with no nil guard, unlike every other s.ca
// access in tenant_service.go. This dispatches a real request — a valid body
// with CommonName and KeyAlgorithm set, so the handler's own field validation
// does not short-circuit before the service call is reached, the way an empty
// body does — through the real router (TenantHandlers + PermissionGate + auth
// middleware, exactly as cmd/xkmsd/admin.go wires it) over a
// TenantAwareAdminService built with a nil CA, and proves the route answers
// 501 rather than panicking.

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

func TestTenantHandlers_CreateTenantIntermediateCA_NilCANotImplemented(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := mustTenantAwareAdminService(t, nil, nil, newTestQRDB(t), logger, "test-version")
	handlers := NewTenantHandlers(svc, logger)

	authMiddleware := newTestAuthMiddleware(qrdbsdk.RoleNameAdmin)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router, authMiddleware, newPermissiveGate())

	body := `{"common_name":"Global Parent Intermediate CA","key_algorithm":"RSA","validity_years":5}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/test-tenant/intermediate-cas", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-admin-key")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CreateTenantIntermediateCA panicked: %v", r)
			}
		}()
		router.ServeHTTP(rec, req)
	}()

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d (Not Implemented); body = %s", rec.Code, http.StatusNotImplemented, rec.Body.String())
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

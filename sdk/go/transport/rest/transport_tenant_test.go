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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// tenantState tracks a single tenant plus the unseal state of its per-tenant
// barrier, reproducing the lifecycle the SDK TenantService client exercises.
type tenantState struct {
	info     transport.TenantInfo
	unsealed bool
}

// tenantFakeServer is a compact, in-memory implementation of the tenant and
// per-tenant-barrier HTTP API exercised by the SDK REST TenantService client.
// It stands in for the former seal.BarrierRegistry-backed handlers (now hosted
// in the go-qrdb node) so these tests can validate the client's request
// serialization and response/error mapping against a real HTTP server without
// depending on any production barrier backend.
type tenantFakeServer struct {
	tenants map[string]*tenantState
}

func newTenantFakeServer() *tenantFakeServer {
	return &tenantFakeServer{tenants: make(map[string]*tenantState)}
}

func (s *tenantFakeServer) createTenant(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req transport.CreateTenantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(t, w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.ID == "" {
			writeErr(t, w, http.StatusBadRequest, "id is required")
			return
		}
		if req.Name == "" {
			writeErr(t, w, http.StatusBadRequest, "name is required")
			return
		}
		if _, ok := s.tenants[req.ID]; ok {
			writeErr(t, w, http.StatusConflict, "tenant already exists")
			return
		}

		now := time.Now().UTC()
		info := transport.TenantInfo{
			ID:            req.ID,
			Name:          req.Name,
			IsolationType: req.IsolationType,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		s.tenants[req.ID] = &tenantState{info: info}

		writeJSON(t, w, http.StatusCreated, transport.CreateTenantResponse{Tenant: info})
	}
}

func (s *tenantFakeServer) getTenant(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts, ok := s.tenants[chi.URLParam(r, "tenantID")]
		if !ok {
			writeErr(t, w, http.StatusNotFound, "tenant not found")
			return
		}
		writeJSON(t, w, http.StatusOK, transport.GetTenantResponse{Tenant: ts.info})
	}
}

func (s *tenantFakeServer) listTenants(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		tenants := make([]transport.TenantInfo, 0, len(s.tenants))
		for _, ts := range s.tenants {
			tenants = append(tenants, ts.info)
		}
		writeJSON(t, w, http.StatusOK, transport.ListTenantsResponse{Tenants: tenants})
	}
}

func (s *tenantFakeServer) deleteTenant(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "tenantID")
		if _, ok := s.tenants[id]; !ok {
			writeErr(t, w, http.StatusNotFound, "tenant not found")
			return
		}
		delete(s.tenants, id)
		writeJSON(t, w, http.StatusNoContent, nil)
	}
}

func (s *tenantFakeServer) barrierInit(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts, ok := s.tenants[chi.URLParam(r, "tenantID")]
		if !ok {
			writeErr(t, w, http.StatusNotFound, "tenant not found")
			return
		}

		var req transport.TenantBarrierInitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(t, w, http.StatusBadRequest, "invalid request body")
			return
		}

		// The software (passphrase) strategy auto-unseals on initialization.
		ts.unsealed = true
		writeJSON(t, w, http.StatusOK, map[string]bool{"initialized": true})
	}
}

func (s *tenantFakeServer) barrierUnseal(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts, ok := s.tenants[chi.URLParam(r, "tenantID")]
		if !ok {
			writeErr(t, w, http.StatusNotFound, "tenant not found")
			return
		}

		var req transport.TenantBarrierUnsealRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(t, w, http.StatusBadRequest, "invalid request body")
			return
		}

		if ts.unsealed {
			writeErr(t, w, http.StatusConflict, "barrier already unsealed")
			return
		}

		ts.unsealed = true
		writeJSON(t, w, http.StatusOK, map[string]bool{"unsealed": true})
	}
}

func (s *tenantFakeServer) barrierStatus(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ts, ok := s.tenants[chi.URLParam(r, "tenantID")]
		if !ok {
			writeErr(t, w, http.StatusNotFound, "tenant not found")
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]bool{"unsealed": ts.unsealed})
	}
}

// router builds the chi router exposing the tenant and per-tenant-barrier HTTP
// API plus the /health endpoint required by Transport.Connect().
func (s *tenantFakeServer) router(t *testing.T) http.Handler {
	r := chi.NewRouter()

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/v1/tenants", func(r chi.Router) {
		r.Post("/", s.createTenant(t))
		r.Get("/", s.listTenants(t))
		r.Get("/{tenantID}", s.getTenant(t))
		r.Delete("/{tenantID}", s.deleteTenant(t))
		r.Get("/{tenantID}/barrier/status", s.barrierStatus(t))
		r.Post("/{tenantID}/barrier/init", s.barrierInit(t))
		r.Post("/{tenantID}/barrier/unseal", s.barrierUnseal(t))
	})

	return r
}

// newTenantTestTransport creates a REST transport connected to an httptest
// server backed by an in-memory fake implementing the tenant HTTP API.
func newTenantTestTransport(t *testing.T) (*Transport, *httptest.Server) {
	t.Helper()

	server := httptest.NewServer(newTenantFakeServer().router(t))
	t.Cleanup(server.Close)

	tr, err := NewWithConfig(&transport.Config{
		Address:    server.URL,
		TLSEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := tr.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}

	return tr, server
}

func TestTransport_CreateTenant_Success(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	resp, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{
		ID:   "acme-corp",
		Name: "Acme Corporation",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_CreateTenant_MissingID(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	_, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{
		Name: "No ID",
	})
	if err == nil {
		t.Fatal("expected error for missing tenant ID")
	}
}

func TestTransport_CreateTenant_MissingName(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	_, err := tr.CreateTenant(context.Background(), &transport.CreateTenantRequest{
		ID: "no-name",
	})
	if err == nil {
		t.Fatal("expected error for missing tenant name")
	}
}

func TestTransport_CreateTenant_Duplicate(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "dup-tenant",
		Name: "Duplicate",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "dup-tenant",
		Name: "Duplicate Again",
	})
	if err == nil {
		t.Fatal("expected error for duplicate tenant")
	}
}

func TestTransport_GetTenant_Success(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "get-tenant",
		Name: "Get Tenant",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.GetTenant(ctx, "get-tenant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_GetTenant_NotFound(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	_, err := tr.GetTenant(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestTransport_ListTenants_Empty(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	resp, err := tr.ListTenants(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_ListTenants_WithTenants(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "list-tenant-1",
		Name: "Tenant One",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "list-tenant-2",
		Name: "Tenant Two",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := tr.ListTenants(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestTransport_DeleteTenant_Success(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "del-tenant",
		Name: "Delete Tenant",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = tr.DeleteTenant(ctx, "del-tenant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it was deleted.
	_, err = tr.GetTenant(ctx, "del-tenant")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestTransport_DeleteTenant_NotFound(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	err := tr.DeleteTenant(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestTransport_TenantBarrierInit_Success(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "init-tenant",
		Name: "Init Tenant",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = tr.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:  "init-tenant",
		Threshold: 2,
		Shares:    3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTransport_TenantBarrierInit_NotFound(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	err := tr.TenantBarrierInit(context.Background(), &transport.TenantBarrierInitRequest{
		TenantID:  "nonexistent",
		Threshold: 2,
		Shares:    3,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestTransport_TenantBarrierUnseal_AlreadyUnsealed(t *testing.T) {
	tr, _ := newTenantTestTransport(t)
	ctx := context.Background()

	_, err := tr.CreateTenant(ctx, &transport.CreateTenantRequest{
		ID:   "unseal-tenant",
		Name: "Unseal Tenant",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the tenant barrier (software strategy auto-unseals)
	err = tr.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID: "unseal-tenant",
	})
	if err != nil {
		t.Fatalf("barrier init failed: %v", err)
	}

	// Unseal on an already-unsealed barrier should return an error
	err = tr.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "unseal-tenant",
		Key:      []byte("test-key"),
	})
	if err == nil {
		t.Fatal("expected error when unsealing already-unsealed barrier")
	}
}

func TestTransport_TenantBarrierUnseal_NotFound(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	err := tr.TenantBarrierUnseal(context.Background(), &transport.TenantBarrierUnsealRequest{
		TenantID: "nonexistent",
		Key:      []byte("test-key"),
	})
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

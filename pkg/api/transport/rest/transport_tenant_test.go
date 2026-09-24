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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	restapi "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newTenantTestTransport creates a REST transport connected to an httptest
// server backed by real tenant handlers with a real barrier registry.
func newTenantTestTransport(t *testing.T) (*Transport, *httptest.Server) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(
		logger,
		base,
		seal.BarrierConfig{
			RootKeyPath:     "core/seal",
			PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
		},
		seal.NewSoftwareStrategy(),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	creds := seal.MustCredentials([]byte("test-password"))
	defer creds.Secret.Destroy()
	if err := barrier.Initialize(ctx, creds); err != nil {
		t.Fatal(err)
	}

	registry, err := seal.NewBarrierRegistry(barrier)
	if err != nil {
		t.Fatal(err)
	}

	// Tenant CRUD and barrier operations route through the XKMS service's
	// composed TenantService (there is no barrier-registry-only fallback);
	// build a real go-qrdb TenantService over the same barrier registry the
	// handlers' tenantSealed() helper reads, so both paths agree.
	tenantSvc, err := seal.NewHardwareTenantService(barrier, registry, logger, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the global XKMS service backed by an in-memory software
	// backend and wire it with the TenantService. The §3.6 TenantBarrierInit
	// invariant (the server never generates a tenant secret) lives in the
	// service layer, so the REST handler delegates to xkms.Get(). Production
	// wires the identical registry to both the service and the handlers
	// (pkg/server/server.go); this mirrors it.
	swBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	if err != nil {
		t.Fatal(err)
	}
	xkms.Reset()
	if err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(xkms.Reset)
	svc, err := xkms.Get()
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTenantService(tenantSvc)

	handlers, err := restapi.NewTenantHandlers(registry, svc)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()

	// Health endpoint required by Connect().
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			t.Logf("failed to encode health response: %v", err)
		}
	})

	r.Route("/api/v1/tenants", func(r chi.Router) {
		r.Post("/", handlers.CreateTenantHandler)
		r.Get("/", handlers.ListTenantsHandler)
		r.Get("/{tenantID}", handlers.GetTenantHandler)
		r.Delete("/{tenantID}", handlers.DeleteTenantHandler)
		r.Get("/{tenantID}/barrier/status", handlers.TenantBarrierStatusHandler)
		r.Post("/{tenantID}/barrier/init", handlers.TenantBarrierInitHandler)
		r.Post("/{tenantID}/barrier/unseal", handlers.TenantBarrierUnsealHandler)
		r.Put("/{tenantID}/entitlements", handlers.UpdateTenantEntitlementsHandler)
		r.Put("/{tenantID}/quotas", handlers.UpdateTenantQuotasHandler)
	})

	server := httptest.NewServer(r)
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

// TestTransport_DeleteTenant_Success is intentionally absent here: a
// prefix-isolated tenant's teardown (go-qrdb's DeleteTenant) needs a
// DatabaseLister / KeyspaceReclaimer / DEKShredder wired via
// tenant.TenantServiceOption to fully reclaim its keyspace, which needs a
// real embedded qrdb node. This in-memory unit test fixture (a bare
// TenantService over a memory-backed store, no node) deliberately does not
// stand that up. The success path is covered against a fake TenantServicer
// in pkg/xkms/servicer_tenant_delegation_test.go (TestDeleteTenant_Delegates);
// this file covers the not-found guard below.

func TestTransport_DeleteTenant_NotFound(t *testing.T) {
	tr, _ := newTenantTestTransport(t)

	err := tr.DeleteTenant(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

// TestTransport_TenantBarrierInit_Success is intentionally absent here:
// initializing a tenant's barrier provisions go-qrdb's pooled per-tenant
// storage (WithVolumePool / WithPerTenantRegistry), which needs real
// Pebble-backed pool infrastructure this in-memory unit test fixture
// deliberately does not stand up. The success path is covered against a
// fake TenantServicer in pkg/xkms/servicer_tenant_delegation_test.go
// (TestTenantBarrierInit_DelegatesWithStrategy); this file covers the
// not-found guard below.

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

// TestTransport_TenantBarrierUnseal_AlreadyUnsealed is intentionally absent
// here for the same reason as TenantBarrierInit's: it depends on a prior
// successful barrier init, which needs go-qrdb's pooled per-tenant storage.
// The idempotent already-unsealed short-circuit is covered against a fake
// TenantServicer in pkg/xkms/servicer_tenant_delegation_test.go
// (TestTenantBarrierUnseal_DelegatesKeyAndShare); this file covers the
// not-found guard below.

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

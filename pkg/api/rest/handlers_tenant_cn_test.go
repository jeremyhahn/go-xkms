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
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// A common name is unique only WITHIN a tenant. These tests build the one
// situation that makes that matter: two tenants each holding a key with the
// same CN in the same backend, so a lookup that scans an unscoped backend
// returns whichever was stored first -- go-xkms#221.

const sharedCN221 = "shared-name.example"

// twoTenantHandlerContext returns a HandlerContext whose backend holds one RSA
// key named sharedCN221 for each of tenant-a and tenant-b.
func twoTenantHandlerContext(t *testing.T) *HandlerContext {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)

	be, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	ks, err := xkms.New(&xkms.BackendConfig{Backend: be, CertStorage: storage.New()})
	require.NoError(t, err)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		scoped, err := svc.LookupTenantBackend("software", tenant)
		require.NoError(t, err)
		_, err = scoped.GenerateRSA(context.Background(), &types.KeyAttributes{
			CN: sharedCN221, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware,
			KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		})
		require.NoError(t, err, "generating for %s", tenant)
	}

	return &HandlerContext{xkmsService: svc}
}

func tenantContext221(tenantID string) context.Context {
	return auth.WithIdentity(context.Background(),
		&auth.Identity{Subject: "svc", TenantID: tenantID})
}

// TestKeyResolution_DoesNotReachAnotherTenantsKey is the regression for
// go-xkms#221 on the REST transport. It exercises the exact pair the key-by-CN
// handlers use -- lookupTenantBackend then findKeyAttributes -- because that
// pair is the whole of the defect: the scan is only as scoped as the backend
// it is handed.
//
// tenant-c holds no key of this name. Before the fix it resolved tenant-a's.
func TestKeyResolution_DoesNotReachAnotherTenantsKey(t *testing.T) {
	h := twoTenantHandlerContext(t)
	ctx := tenantContext221("tenant-c")

	ks, err := h.lookupTenantBackend(ctx, "software")
	require.NoError(t, err)

	attrs, err := h.findKeyAttributes(ctx, ks, sharedCN221)
	require.Error(t, err,
		"a tenant holding no key of this name resolved one anyway: %v", attrs)
}

// TestKeyResolution_ResolvesTheCallersOwnKey is the other half: scoping must
// not break the ordinary case, and it must return the CALLER'S key rather than
// whichever tenant's happened to be stored first.
func TestKeyResolution_ResolvesTheCallersOwnKey(t *testing.T) {
	h := twoTenantHandlerContext(t)

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		ctx := tenantContext221(tenant)

		ks, err := h.lookupTenantBackend(ctx, "software")
		require.NoError(t, err)

		attrs, err := h.findKeyAttributes(ctx, ks, sharedCN221)
		require.NoError(t, err, "%s must resolve its own key", tenant)
		require.Equal(t, tenant, attrs.TenantID,
			"%s resolved a key belonging to %q", tenant, attrs.TenantID)
	}
}

// TestKeyResolution_SystemTenantStillSeesEverything pins the deliberate
// exception: an unauthenticated or system-level caller is NOT tenant-scoped,
// which is tenantScopes' rule rather than something this transport decides.
// Asserting it stops a later "tighten the scope" change from silently breaking
// system-level administration.
func TestKeyResolution_SystemTenantStillSeesEverything(t *testing.T) {
	h := twoTenantHandlerContext(t)
	ctx := context.Background() // no identity at all

	ks, err := h.lookupTenantBackend(ctx, "software")
	require.NoError(t, err)

	keys, err := ks.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 2, "a system-level caller must still see every tenant's keys")
}

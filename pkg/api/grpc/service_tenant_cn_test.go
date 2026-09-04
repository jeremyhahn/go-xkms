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

package grpc

import (
	"context"
	"crypto/x509"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
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

// twoTenantService returns a Service whose backend holds one RSA key named
// sharedCN221 for each of tenant-a and tenant-b.
func twoTenantService(t *testing.T) *Service {
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

	return NewService(nil, nil, svc)
}

// tenantCtx returns a context carrying an authenticated identity for tenantID.
func tenantCtx(tenantID string) context.Context {
	return auth.WithIdentity(context.Background(),
		&auth.Identity{Subject: "svc", TenantID: tenantID})
}

// TestDeleteKey_DoesNotReachAnotherTenantsKey is the regression for go-xkms#221
// on the gRPC transport.
//
// tenant-c holds no key at all. Before the fix, DeleteKey resolved the CN over
// an UNSCOPED backend, matched tenant-a's key, and deleted it -- a caller
// destroying a key it can neither see nor name.
func TestDeleteKey_DoesNotReachAnotherTenantsKey(t *testing.T) {
	s := twoTenantService(t)

	_, err := s.DeleteKey(tenantCtx("tenant-c"), &pb.DeleteKeyRequest{
		KeyId:   sharedCN221,
		Backend: "software",
	})
	require.Error(t, err, "a tenant with no key of this name must not resolve another tenant's key")

	// And both original keys must still be there.
	svc, err2 := xkms.Get()
	require.NoError(t, err2)
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		scoped, err := svc.LookupTenantBackend("software", tenant)
		require.NoError(t, err)
		keys, err := scoped.ListKeys(context.Background())
		require.NoError(t, err)
		require.Len(t, keys, 1, "%s lost its key to another tenant's delete", tenant)
	}
}

// TestDeleteKey_ResolvesTheCallersOwnKey is the other half: scoping must not
// break the ordinary case. tenant-b deletes its own key and tenant-a keeps its.
func TestDeleteKey_ResolvesTheCallersOwnKey(t *testing.T) {
	s := twoTenantService(t)

	_, err := s.DeleteKey(tenantCtx("tenant-b"), &pb.DeleteKeyRequest{
		KeyId:   sharedCN221,
		Backend: "software",
	})
	require.NoError(t, err, "a tenant must be able to delete its own key")

	svc, err := xkms.Get()
	require.NoError(t, err)

	scopedB, err := svc.LookupTenantBackend("software", "tenant-b")
	require.NoError(t, err)
	bKeys, err := scopedB.ListKeys(context.Background())
	require.NoError(t, err)
	require.Empty(t, bKeys, "tenant-b's own key should have been deleted")

	scopedA, err := svc.LookupTenantBackend("software", "tenant-a")
	require.NoError(t, err)
	aKeys, err := scopedA.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, aKeys, 1, "tenant-a's key must be untouched")
}

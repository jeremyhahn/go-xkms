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

package xkms

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// pkcs11StateOp runs one PKCS#11-state RPC against a (tenant, token) and
// reports only its error, so every operation can be driven by the same
// tenant-isolation table.
type pkcs11StateOp func(ctx context.Context, svc *XKMSService, tenantID, token string) error

var pkcs11StateOps = map[string]pkcs11StateOp{
	"Put": func(ctx context.Context, svc *XKMSService, tenantID, token string) error {
		_, err := svc.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{TenantID: tenantID, Token: token, Key: "pkcs11/tokens/0", Value: []byte("v")})
		return err
	},
	"PutIfAbsent": func(ctx context.Context, svc *XKMSService, tenantID, token string) error {
		_, err := svc.PKCS11StatePutIfAbsent(ctx, &transport.PKCS11StatePutIfAbsentRequest{TenantID: tenantID, Token: token, Key: "pkcs11/tokens/0", Value: []byte("v")})
		return err
	},
	"CAS": func(ctx context.Context, svc *XKMSService, tenantID, token string) error {
		_, err := svc.PKCS11StateCAS(ctx, &transport.PKCS11StateCASRequest{TenantID: tenantID, Token: token, Key: "pkcs11/tokens/0", Expected: []byte("v"), New: []byte("w")})
		return err
	},
	"CAD": func(ctx context.Context, svc *XKMSService, tenantID, token string) error {
		_, err := svc.PKCS11StateCAD(ctx, &transport.PKCS11StateCADRequest{TenantID: tenantID, Token: token, Key: "pkcs11/tokens/0", Expected: []byte("v")})
		return err
	},
	"Get": func(ctx context.Context, svc *XKMSService, tenantID, token string) error {
		_, err := svc.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{TenantID: tenantID, Token: token, Key: "pkcs11/tokens/0"})
		return err
	},
	"Delete": func(ctx context.Context, svc *XKMSService, tenantID, token string) error {
		_, err := svc.PKCS11StateDelete(ctx, &transport.PKCS11StateDeleteRequest{TenantID: tenantID, Token: token, Key: "pkcs11/tokens/0"})
		return err
	},
	"List": func(ctx context.Context, svc *XKMSService, tenantID, token string) error {
		_, err := svc.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{TenantID: tenantID, Token: token})
		return err
	},
}

func tenantCtx(tenantID string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "user@" + tenantID, TenantID: tenantID, Roles: []string{"admin"}})
}

// TestPKCS11State_EveryOperationRefusesAForeignTenant is the #1114 exploit:
// a tenant-A caller naming tenant B (or the system tenant) in the body is
// refused on every RPC, before the store is touched.
func TestPKCS11State_EveryOperationRefusesAForeignTenant(t *testing.T) {
	svc := newPKCS11StateService(t)
	ctx := tenantCtx("tenant-a")

	for name, op := range pkcs11StateOps {
		for _, foreign := range []string{"tenant-b", qrdbsdk.SystemTenantID} {
			t.Run(name+"/"+foreign, func(t *testing.T) {
				err := op(ctx, svc, foreign, "tok0")
				require.ErrorIs(t, err, ErrPKCS11StateTenantMismatch)
				assert.True(t, IsPKCS11StateRequestError(err))
			})
		}
	}
}

// TestPKCS11State_EveryOperationAcceptsTheCallersOwnTenant proves a module that
// states its configured tenant, or states none, keeps working.
func TestPKCS11State_EveryOperationAcceptsTheCallersOwnTenant(t *testing.T) {
	svc := newPKCS11StateService(t)
	ctx := tenantCtx("tenant-a")

	for name, op := range pkcs11StateOps {
		for _, supplied := range []string{"", "tenant-a"} {
			t.Run(name+"/"+supplied, func(t *testing.T) {
				require.NoError(t, op(ctx, svc, supplied, "tok0"))
			})
		}
	}
}

// TestPKCS11State_EveryOperationRefusesASlashInTheToken proves a token cannot
// alias another token's namespace through the key separator.
func TestPKCS11State_EveryOperationRefusesASlashInTheToken(t *testing.T) {
	svc := newPKCS11StateService(t)
	ctx := tenantCtx("tenant-a")

	for name, op := range pkcs11StateOps {
		t.Run(name, func(t *testing.T) {
			err := op(ctx, svc, "", "tok0/pkcs11")
			require.ErrorIs(t, err, ErrPKCS11StateTokenSeparator)
			assert.True(t, IsPKCS11StateRequestError(err))
		})
	}
}

// TestPKCS11State_TenantsWithTheSameTokenAreIsolated proves the namespace comes
// from the identity: two tenants using the same token label and key never see
// each other's record, whatever tenant the body leaves out.
func TestPKCS11State_TenantsWithTheSameTokenAreIsolated(t *testing.T) {
	svc := newPKCS11StateService(t)
	ctxA := tenantCtx("tenant-a")
	ctxB := tenantCtx("tenant-b")

	_, err := svc.PKCS11StatePut(ctxA, &transport.PKCS11StatePutRequest{Token: "tok0", Key: "pkcs11/tokens/0", Value: []byte("a-state")})
	require.NoError(t, err)

	got, err := svc.PKCS11StateGet(ctxB, &transport.PKCS11StateGetRequest{Token: "tok0", Key: "pkcs11/tokens/0"})
	require.NoError(t, err)
	assert.False(t, got.Found, "tenant B must not read tenant A's record")

	list, err := svc.PKCS11StateList(ctxB, &transport.PKCS11StateListRequest{Token: "tok0"})
	require.NoError(t, err)
	assert.Empty(t, list.Keys)

	cad, err := svc.PKCS11StateCAD(ctxB, &transport.PKCS11StateCADRequest{Token: "tok0", Key: "pkcs11/tokens/0", Expected: []byte("a-state")})
	require.NoError(t, err)
	assert.False(t, cad.Deleted, "tenant B must not delete tenant A's record")

	cas, err := svc.PKCS11StateCAS(ctxB, &transport.PKCS11StateCASRequest{Token: "tok0", Key: "pkcs11/tokens/0", Expected: []byte("a-state"), New: []byte("b")})
	require.NoError(t, err)
	assert.False(t, cas.Swapped, "tenant B must not swap tenant A's record")

	got, err = svc.PKCS11StateGet(ctxA, &transport.PKCS11StateGetRequest{TenantID: "tenant-a", Token: "tok0", Key: "pkcs11/tokens/0"})
	require.NoError(t, err)
	assert.True(t, got.Found)
	assert.Equal(t, []byte("a-state"), got.Value)
}

// TestPKCS11State_SystemCallerUsesTheSystemNamespace proves the reserved system
// tenant and "" name one namespace, the one system-scope records have always
// used, and that a system caller is confined to it like any other.
func TestPKCS11State_SystemCallerUsesTheSystemNamespace(t *testing.T) {
	svc := newPKCS11StateService(t)
	sysCtx := tenantCtx(qrdbsdk.SystemTenantID)

	_, err := svc.PKCS11StatePut(sysCtx, &transport.PKCS11StatePutRequest{TenantID: qrdbsdk.SystemTenantID, Token: "tok0", Key: "k", Value: []byte("sys")})
	require.NoError(t, err)

	got, err := svc.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.True(t, got.Found, "an identity-less caller shares the system namespace")

	_, err = svc.PKCS11StateGet(sysCtx, &transport.PKCS11StateGetRequest{TenantID: "tenant-a", Token: "tok0", Key: "k"})
	require.ErrorIs(t, err, ErrPKCS11StateTenantMismatch, "the system tenant does not reach into a tenant's namespace")
}

func TestIsPKCS11StateRequestError(t *testing.T) {
	assert.True(t, IsPKCS11StateRequestError(ErrPKCS11StateTokenRequired))
	assert.False(t, IsPKCS11StateRequestError(ErrPKCS11StateStoreUnavailable))
	assert.False(t, IsPKCS11StateRequestError(nil))
}

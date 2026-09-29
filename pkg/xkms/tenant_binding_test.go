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
	"errors"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Tenant binding tests for go-xkms#1112 and #1113. The RBAC gate binds the
// caller's own tenant as the target, so a Tenant Admin's self-scoped
// tenants:* / tenant_barrier:* grants admit a request naming ANY tenant; the
// binding in XKMSService is what confines it. These tests drive the service
// layer directly, with the composed go-qrdb TenantService over an in-memory
// barrier, so no transport check can mask a missing service-layer check.

const bindingPassphrase = "correct horse battery staple"

// newBindingTestService returns an XKMSService composed with go-qrdb's real
// TenantService over an unsealed in-memory barrier, holding two prefix
// tenants: tenant-a and tenant-b.
func newBindingTestService(t *testing.T) *XKMSService {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	barrier, err := seal.NewBarrier(logger, storage.NewMemory(), seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	creds := seal.MustCredentials([]byte(bindingPassphrase))
	defer creds.Secret.Destroy()
	require.NoError(t, barrier.Initialize(ctx, creds))
	if barrier.IsSealed() {
		require.NoError(t, barrier.Unseal(ctx, creds))
	}
	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)
	tenantSvc, err := seal.NewHardwareTenantService(barrier, registry, logger, nil)
	require.NoError(t, err)

	svc := &XKMSService{}
	svc.SetTenantService(tenantSvc)
	for _, id := range []string{"tenant-a", "tenant-b"} {
		_, err := svc.CreateTenant(systemCtx(), &transport.CreateTenantRequest{
			ID: id, Name: id, IsolationType: transport.TenantIsolationType(qrdbsdk.TenantIsolationPrefix),
		})
		require.NoError(t, err)
	}
	return svc
}

// systemCtx carries an identity in the reserved system tenant: the platform
// scope that may address every tenant.
func systemCtx() context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "so@example.com", TenantID: qrdbsdk.SystemTenantID,
	})
}

// requireBindingRefusal asserts err is the binding's refusal and that it is
// indistinguishable from a genuine miss: it matches qrdb's unknown-tenant
// sentinel and carries exactly its message.
func requireBindingRefusal(t *testing.T, err error, op string) {
	t.Helper()
	var bindErr *TenantBindingError
	require.ErrorAs(t, err, &bindErr, op)
	assert.ErrorIs(t, err, qrdbsdk.ErrTenantMissing, op)
	assert.Equal(t, qrdbsdk.ErrTenantMissing.Error(), err.Error(), op)
}

func TestTenantBinding_CrossTenantRefusedAsNotFound(t *testing.T) {
	svc := newBindingTestService(t)
	ctx := tenantCtx("tenant-a")

	_, err := svc.GetTenant(ctx, "tenant-b")
	requireBindingRefusal(t, err, "get")

	requireBindingRefusal(t, svc.DeleteTenant(ctx, "tenant-b"), "delete")

	requireBindingRefusal(t, svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID: "tenant-b", Passphrase: []byte(bindingPassphrase),
	}), "barrier init")

	requireBindingRefusal(t, svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "tenant-b", Key: []byte(bindingPassphrase),
	}), "barrier unseal")

	_, err = svc.TenantBarrierStatus(ctx, "tenant-b")
	requireBindingRefusal(t, err, "barrier status")

	_, err = svc.UpdateTenantEntitlements(ctx, &transport.UpdateTenantEntitlementsRequest{
		TenantID: "tenant-b", Entitlements: transport.TenantEntitlements{AllowDedicatedRaft: true},
	})
	requireBindingRefusal(t, err, "entitlements")

	_, err = svc.UpdateTenantQuotas(ctx, &transport.UpdateTenantQuotasRequest{
		TenantID: "tenant-b", Quotas: transport.TenantQuotas{MaxKeys: 1_000_000},
	})
	requireBindingRefusal(t, err, "quotas")

	// tenant-b is untouched: still present for the platform scope.
	_, err = svc.GetTenant(systemCtx(), "tenant-b")
	require.NoError(t, err)
}

// TestTenantBinding_RefusalMatchesGenuineMiss is the anti-enumeration
// property: probing a foreign tenant and probing an unused ID return equal
// errors, so the probe learns nothing.
func TestTenantBinding_RefusalMatchesGenuineMiss(t *testing.T) {
	svc := newBindingTestService(t)

	_, foreign := svc.GetTenant(tenantCtx("tenant-a"), "tenant-b")
	_, missing := svc.GetTenant(systemCtx(), "no-such-tenant")

	require.Error(t, missing)
	assert.Equal(t, missing.Error(), foreign.Error())
	assert.True(t, errors.Is(missing, qrdbsdk.ErrTenantMissing))
	assert.True(t, errors.Is(foreign, qrdbsdk.ErrTenantMissing))
}

func TestTenantBinding_OwnTenantAllowed(t *testing.T) {
	svc := newBindingTestService(t)
	ctx := tenantCtx("tenant-a")

	got, err := svc.GetTenant(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", got.Tenant.ID)

	status, err := svc.TenantBarrierStatus(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", status.TenantID)

	// Past the binding, go-qrdb answers for itself: a prefix tenant has no
	// dedicated barrier to initialize or unseal, which is not the binding's
	// not-found refusal.
	var bindErr *TenantBindingError
	err = svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID: "tenant-a", Passphrase: []byte(bindingPassphrase),
	})
	assert.False(t, errors.As(err, &bindErr), "own-tenant init must pass the binding: %v", err)
	err = svc.TenantBarrierUnseal(ctx, &transport.TenantBarrierUnsealRequest{
		TenantID: "tenant-a", Key: []byte(bindingPassphrase),
	})
	assert.False(t, errors.As(err, &bindErr), "own-tenant unseal must pass the binding: %v", err)
}

// TestTenantBinding_OwnTenantDeleteDelegates uses the recording fake because
// go-qrdb's tenant teardown needs a DatabaseLister / KeyspaceReclaimer the
// in-memory harness does not compose (see TestDeleteTenant_Delegates).
func TestTenantBinding_OwnTenantDeleteDelegates(t *testing.T) {
	fake := &fakeTenantServicer{}
	svc := &XKMSService{}
	svc.SetTenantService(fake)

	require.NoError(t, svc.DeleteTenant(tenantCtx("tenant-a"), "tenant-a"))
	assert.Equal(t, "tenant-a", fake.deletedID)

	requireBindingRefusal(t, svc.DeleteTenant(tenantCtx("tenant-a"), "tenant-b"), "delete")
	assert.Equal(t, "tenant-a", fake.deletedID, "a refused delete must never reach the tenant service")
}

// TestTenantBinding_PlanChangesArePlatformOnly pins #1113: a Tenant Admin may
// not change even its own tenant's entitlements or quotas; the platform scope
// may change any tenant's.
func TestTenantBinding_PlanChangesArePlatformOnly(t *testing.T) {
	svc := newBindingTestService(t)

	_, err := svc.UpdateTenantEntitlements(tenantCtx("tenant-a"), &transport.UpdateTenantEntitlementsRequest{
		TenantID: "tenant-a", Entitlements: transport.TenantEntitlements{AllowDedicatedRaft: true},
	})
	requireBindingRefusal(t, err, "own entitlements")

	_, err = svc.UpdateTenantQuotas(tenantCtx("tenant-a"), &transport.UpdateTenantQuotasRequest{
		TenantID: "tenant-a", Quotas: transport.TenantQuotas{MaxKeys: 1_000_000},
	})
	requireBindingRefusal(t, err, "own quotas")

	ents, err := svc.UpdateTenantEntitlements(systemCtx(), &transport.UpdateTenantEntitlementsRequest{
		TenantID: "tenant-a", Entitlements: transport.TenantEntitlements{AllowDedicatedRaft: true},
	})
	require.NoError(t, err)
	require.NotNil(t, ents.Tenant.Entitlements)
	assert.True(t, ents.Tenant.Entitlements.AllowDedicatedRaft)

	quotas, err := svc.UpdateTenantQuotas(systemCtx(), &transport.UpdateTenantQuotasRequest{
		TenantID: "tenant-a", Quotas: transport.TenantQuotas{MaxKeys: 42},
	})
	require.NoError(t, err)
	require.NotNil(t, quotas.Tenant.Quotas)
	assert.Equal(t, int64(42), quotas.Tenant.Quotas.MaxKeys)
}

func TestTenantBinding_SystemIdentityReachesEveryTenant(t *testing.T) {
	svc := newBindingTestService(t)

	for _, id := range []string{"tenant-a", "tenant-b"} {
		got, err := svc.GetTenant(systemCtx(), id)
		require.NoError(t, err)
		assert.Equal(t, id, got.Tenant.ID)

		status, err := svc.TenantBarrierStatus(systemCtx(), id)
		require.NoError(t, err)
		assert.Equal(t, id, status.TenantID)
	}
}

func TestTenantBinding_ListTenantsFiltersToCaller(t *testing.T) {
	svc := newBindingTestService(t)

	scoped, err := svc.ListTenants(tenantCtx("tenant-a"))
	require.NoError(t, err)
	require.Len(t, scoped.Tenants, 1)
	assert.Equal(t, "tenant-a", scoped.Tenants[0].ID)

	all, err := svc.ListTenants(systemCtx())
	require.NoError(t, err)
	ids := make([]string, 0, len(all.Tenants))
	for _, ti := range all.Tenants {
		ids = append(ids, ti.ID)
	}
	assert.ElementsMatch(t, []string{"tenant-a", "tenant-b"}, ids)
}

func TestBindTenantTarget_DecisionTable(t *testing.T) {
	tests := []struct {
		name     string
		identity *auth.Identity
		target   string
		allowed  bool
	}{
		{"no identity is the platform scope", nil, "tenant-a", true},
		{"empty tenant is the platform scope", &auth.Identity{Subject: "so"}, "tenant-a", true},
		{"system tenant reaches any tenant", &auth.Identity{TenantID: qrdbsdk.SystemTenantID}, "tenant-a", true},
		{"system tenant reaches the system scope", &auth.Identity{TenantID: qrdbsdk.SystemTenantID}, "", true},
		{"own tenant is allowed", &auth.Identity{TenantID: "tenant-a"}, "tenant-a", true},
		{"another tenant is refused", &auth.Identity{TenantID: "tenant-a"}, "tenant-b", false},
		{"the system scope is refused to a tenant", &auth.Identity{TenantID: "tenant-a"}, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.identity != nil {
				ctx = auth.WithIdentity(ctx, tc.identity)
			}
			err := bindTenantTarget(ctx, "op", tc.target)
			if tc.allowed {
				assert.NoError(t, err)
				return
			}
			var bindErr *TenantBindingError
			require.ErrorAs(t, err, &bindErr)
			assert.Equal(t, "op", bindErr.Op)
			assert.Equal(t, tc.identity.TenantID, bindErr.CallerTenantID)
			assert.Equal(t, tc.target, bindErr.TargetTenantID)
		})
	}
}

func TestRequirePlatformScope(t *testing.T) {
	assert.NoError(t, requirePlatformScope(context.Background(), "op", "tenant-a"))
	assert.NoError(t, requirePlatformScope(systemCtx(), "op", "tenant-a"))

	err := requirePlatformScope(tenantCtx("tenant-a"), "op", "tenant-a")
	var bindErr *TenantBindingError
	require.ErrorAs(t, err, &bindErr)
	assert.Equal(t, "tenant-a", bindErr.CallerTenantID)
}

// TestBarrierEnableEncryption_TenantBinding pins the same binding on the
// caller-supplied migration target: a Tenant Admin may migrate its own
// tenant's barrier, but not another tenant's and not the system barrier.
func TestBarrierEnableEncryption_TenantBinding(t *testing.T) {
	svc := newServiceForMigration(t)
	migrator := &fakeEncryptionMigrator{}
	svc.SetEncryptionMigrator(migrator)
	ctx := tenantCtx("tenant-a")

	_, err := svc.BarrierEnableEncryption(ctx, &transport.BarrierEnableEncryptionRequest{
		TenantID: "tenant-b", Strategy: "passphrase", Passphrase: bindingPassphrase,
	})
	requireBindingRefusal(t, err, "other tenant")

	_, err = svc.BarrierEnableEncryption(ctx, &transport.BarrierEnableEncryptionRequest{
		Strategy: "passphrase", Passphrase: bindingPassphrase,
	})
	requireBindingRefusal(t, err, "system barrier")

	assert.False(t, migrator.wasCalled(), "a refused migration must never be scheduled")

	own := &fakeEncryptionMigrator{done: make(chan struct{})}
	svc.SetEncryptionMigrator(own)
	resp, err := svc.BarrierEnableEncryption(ctx, &transport.BarrierEnableEncryptionRequest{
		TenantID: "tenant-a", Strategy: "passphrase", Passphrase: bindingPassphrase,
	})
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.ScopeTenant), resp.Scope)
	<-own.done
	assert.Equal(t, "tenant-a", own.scope.TenantID)
}

// TestSignCSR_TenantBinding pins the binding on the caller-supplied SPIFFE
// tenant: a tenant-scoped caller may stamp its own tenant (or none), never
// another tenant's.
func TestSignCSR_TenantBinding(t *testing.T) {
	ca := &mockCA{signCSRCert: createSelfSignedCert(t), cert: createSelfSignedCert(t)}
	svc := setupServiceWithCA(t, ca)
	csr := []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----")
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "admin-a", TenantID: "tenant-a", Roles: []string{"admin"},
	})

	_, err := svc.SignCSR(ctx, &transport.SignCSRRequest{CSRPEM: csr, TenantID: "tenant-b"})
	requireBindingRefusal(t, err, "foreign tenant")
	assert.Empty(t, ca.signCSRTenant, "a refused CSR must never reach the CA")

	_, err = svc.SignCSR(ctx, &transport.SignCSRRequest{CSRPEM: csr, TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", ca.signCSRTenant)

	_, err = svc.SignCSR(ctx, &transport.SignCSRRequest{CSRPEM: csr})
	require.NoError(t, err, "naming no tenant stamps no tenant SAN and is not a cross-tenant target")
	assert.Empty(t, ca.signCSRTenant)

	platformAdmin := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "so@example.com", TenantID: qrdbsdk.SystemTenantID, Roles: []string{"admin"},
	})
	_, err = svc.SignCSR(platformAdmin, &transport.SignCSRRequest{CSRPEM: csr, TenantID: "tenant-b"})
	require.NoError(t, err)
	assert.Equal(t, "tenant-b", ca.signCSRTenant)
}

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

package auth

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithIdentity_GetIdentity(t *testing.T) {
	tests := []struct {
		name     string
		identity *Identity
	}{
		{
			name: "valid identity",
			identity: &Identity{
				Subject: "user1",
				Roles:   []string{"admin"},
				Metadata: map[string]string{
					"auth_method": "apikey",
				},
			},
		},
		{
			name: "minimal identity",
			identity: &Identity{
				Subject: "user2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			ctxWithIdentity := WithIdentity(ctx, tt.identity)

			retrieved := GetIdentity(ctxWithIdentity)

			require.NotNil(t, retrieved)
			assert.Equal(t, tt.identity.Subject, retrieved.Subject)
		})
	}
}

func TestGetIdentity_NoIdentity(t *testing.T) {
	ctx := context.Background()

	identity := GetIdentity(ctx)

	assert.Nil(t, identity)
}

func TestGetIdentity_WrongType(t *testing.T) {
	// IdentityContextKey is a constant exposed for tests that need to
	// validate the helper doesn't panic when a non-Identity value is
	// stored under the same key.
	ctx := context.WithValue(context.Background(), IdentityContextKey, "not an identity")

	identity := GetIdentity(ctx)

	assert.Nil(t, identity)
}

func TestNoOpAuthenticator_AuthenticateHTTP(t *testing.T) {
	auth := NewNoOpAuthenticator()

	identity, err := auth.AuthenticateHTTP(nil)

	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "anonymous", identity.Subject)
	assert.NotNil(t, identity.Metadata)
	assert.Equal(t, "none", identity.Metadata["auth_method"])
}

func TestNoOpAuthenticator_AuthenticateGRPC(t *testing.T) {
	auth := NewNoOpAuthenticator()

	identity, err := auth.AuthenticateGRPC(context.Background(), nil)

	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "anonymous", identity.Subject)
	assert.NotNil(t, identity.Metadata)
	assert.Equal(t, "none", identity.Metadata["auth_method"])
}

func TestNoOpAuthenticator_Name(t *testing.T) {
	auth := NewNoOpAuthenticator()

	name := auth.Name()

	assert.Equal(t, "noop", name)
}

func TestIsCrossTenant_NilIdentity(t *testing.T) {
	assert.True(t, IsCrossTenant(nil),
		"a nil identity is platform-internal: no auth context implies system scope")
}

func TestIsCrossTenant_SystemTenant(t *testing.T) {
	id := &Identity{Subject: "platform-admin", TenantID: qrdbsdk.SystemTenantID}
	assert.True(t, IsCrossTenant(id),
		"identities anchored in the system tenant get platform/cross-tenant scope")
}

func TestIsCrossTenant_EmptyTenant(t *testing.T) {
	id := &Identity{Subject: "bootstrap"}
	assert.True(t, IsCrossTenant(id),
		"a bootstrap identity (empty TenantID) is treated as system-scoped pre-tenant-binding")
}

func TestIsCrossTenant_ScopedTenant(t *testing.T) {
	id := &Identity{Subject: "user1", TenantID: "tenant-abc"}
	assert.False(t, IsCrossTenant(id),
		"a tenant-scoped identity is bound to its own tenant only")
}

// TestOwnTenant_ResolvesTheIdentityTenant proves an empty or matching request
// resolves to the identity's tenant, and that a context without an identity is
// the system tenant.
func TestOwnTenant_ResolvesTheIdentityTenant(t *testing.T) {
	ctx := WithIdentity(context.Background(), &Identity{Subject: "u", TenantID: "tenant-a"})
	for _, requested := range []string{"", "tenant-a"} {
		got, err := OwnTenant(ctx, "op", requested)
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", got)
	}

	got, err := OwnTenant(context.Background(), "op", "")
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.SystemTenantID, got)

	got, err = OwnTenant(WithIdentity(context.Background(), &Identity{Subject: "so"}), "op", qrdbsdk.SystemTenantID)
	require.NoError(t, err)
	assert.Equal(t, qrdbsdk.SystemTenantID, got, "an empty identity tenant is the system tenant")
}

// TestOwnTenant_RefusesAnotherTenant proves naming another tenant is refused
// to every caller, the system tenant included, and that a tenant already bound
// to the context cannot widen the identity's reach.
func TestOwnTenant_RefusesAnotherTenant(t *testing.T) {
	tenantCtx := WithIdentity(context.Background(), &Identity{Subject: "u", TenantID: "tenant-a"})
	systemCtx := WithIdentity(context.Background(), &Identity{Subject: "so", TenantID: qrdbsdk.SystemTenantID})
	for name, ctx := range map[string]context.Context{
		"tenant":           tenantCtx,
		"system":           systemCtx,
		"no identity":      context.Background(),
		"foreign ctx bind": qrdbsdk.ContextWithTenant(tenantCtx, "tenant-b"),
	} {
		_, err := OwnTenant(ctx, "op", "tenant-b")
		var denied *qrdbsdk.CrossTenantDeniedError
		require.ErrorAs(t, err, &denied, name)
		assert.Equal(t, "op", denied.Op, name)
		assert.Equal(t, "tenant-b", denied.RequestedTenantID, name)
	}
}

// TestAdmitTenant_SystemReachesEveryTenant proves a cross-tenant caller may
// address any tenant while a tenant-scoped caller is held to its own, and
// that "" names the system tenant rather than the caller's own.
func TestAdmitTenant_SystemReachesEveryTenant(t *testing.T) {
	systemCtx := WithIdentity(context.Background(), &Identity{Subject: "so", TenantID: qrdbsdk.SystemTenantID})
	assert.NoError(t, AdmitTenant(systemCtx, "op", "tenant-b"))
	assert.NoError(t, AdmitTenant(context.Background(), "op", "tenant-b"))

	tenantCtx := WithIdentity(context.Background(), &Identity{Subject: "u", TenantID: "tenant-a"})
	assert.NoError(t, AdmitTenant(tenantCtx, "op", "tenant-a"))

	var denied *qrdbsdk.CrossTenantDeniedError
	require.ErrorAs(t, AdmitTenant(tenantCtx, "op", "tenant-b"), &denied)
	require.ErrorAs(t, AdmitTenant(tenantCtx, "op", ""), &denied)
	assert.Equal(t, qrdbsdk.SystemTenantID, denied.RequestedTenantID)
}

func TestFirstRole(t *testing.T) {
	cases := []struct {
		name string
		id   *Identity
		want string
	}{
		{name: "nil identity", id: nil, want: ""},
		{name: "no roles", id: &Identity{Subject: "u"}, want: ""},
		{name: "single role", id: &Identity{Subject: "u", Roles: []string{"admin"}}, want: "admin"},
		{name: "multiple roles", id: &Identity{Subject: "u", Roles: []string{"so", "user"}}, want: "so"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, FirstRole(tc.id))
		})
	}
}

func TestWithTenantBarrier_GetTenantBarrier(t *testing.T) {
	ctx := context.Background()

	type mockBarrier struct {
		name string
	}
	barrier := &mockBarrier{name: "test-barrier"}

	ctx = WithTenantBarrier(ctx, barrier)
	retrieved := GetTenantBarrier(ctx)

	require.NotNil(t, retrieved)
	got, ok := retrieved.(*mockBarrier)
	require.True(t, ok, "expected *mockBarrier type")
	assert.Equal(t, "test-barrier", got.name)
}

func TestGetTenantBarrier_NotPresent(t *testing.T) {
	ctx := context.Background()

	barrier := GetTenantBarrier(ctx)

	assert.Nil(t, barrier)
}

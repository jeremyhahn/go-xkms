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

package tpmpolicy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xscope "github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestIsReservedObject proves the service's own objects are recognised and a
// caller's key is not, so a key listing hides exactly the infrastructure.
func TestIsReservedObject(t *testing.T) {
	tests := []struct {
		cn   string
		want bool
	}{
		{storageKeyCN, true},
		{authorityCN(1), true},
		{secretsCNPrefix + "acme", true},
		{stateKeyCNPrefix + "acme", true},
		{"signer", false},
		{"tpm-storage", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.cn, func(t *testing.T) {
			assert.Equal(t, tt.want, IsReservedObject(tt.cn))
		})
	}
}

// TestRegistry_ScopesListsOnlyScopeRecords proves Scopes returns each scope
// with a record, and ignores policy and assignment entries.
func TestRegistry_ScopesListsOnlyScopeRecords(t *testing.T) {
	r, _ := newTestRegistry(t)
	ctx := context.Background()

	empty, err := r.Scopes(ctx)
	require.NoError(t, err)
	assert.Empty(t, empty)

	require.NoError(t, r.PutScope(ctx, &Scope{Tenant: "globex", Mode: ModeShared}))
	require.NoError(t, r.PutScope(ctx, &Scope{Tenant: xscope.SystemTenant, Mode: ModeShared}))
	require.NoError(t, r.PutScope(ctx, &Scope{Tenant: "acme", Mode: ModeShared}))
	require.NoError(t, r.CreatePolicy(ctx, "initech", testPolicy("boot")))

	scopes, err := r.Scopes(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"acme", "globex", xscope.SystemTenant}, scopes)
}

// TestRegistry_AssignmentsAreScopedToTheTenant proves Assignments returns a
// tenant's assignments only, and refuses an invalid tenant.
func TestRegistry_AssignmentsAreScopedToTheTenant(t *testing.T) {
	r, _ := newTestRegistry(t)
	ctx := context.Background()
	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/b", Kind: ObjectKey, Policy: "boot"}))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/a", Kind: ObjectKey, Policy: PlatformPolicy}))
	require.NoError(t, r.Assign(ctx, "globex", &Assignment{ObjectID: "key/c", Kind: ObjectKey, Policy: PlatformPolicy}))

	got, err := r.Assignments(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "key/a", got[0].ObjectID)
	assert.Equal(t, "key/b", got[1].ObjectID)
	assert.Equal(t, "boot", got[1].Policy)

	_, err = r.Assignments(ctx, "bad/tenant")
	var invalid *InvalidTenantError
	assert.ErrorAs(t, err, &invalid)
}

// TestService_InventoryReadsTheRegistry proves the service's Scopes and
// Assignments answer from the registry, and Assignments refuses a tenant ID
// that cannot name a scope.
func TestService_InventoryReadsTheRegistry(t *testing.T) {
	svc, registry := newOfflineService(t)
	ctx := context.Background()
	require.NoError(t, registry.PutScope(ctx, &Scope{Tenant: "acme", Mode: ModeShared}))
	require.NoError(t, svc.Assign(ctx, "acme", ObjectKey, "signer", "", nil))

	scopes, err := svc.Scopes(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"acme"}, scopes)

	got, err := svc.Assignments(ctx, "acme")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, PlatformPolicy, got[0].Policy)

	system, err := svc.Assignments(ctx, "")
	require.NoError(t, err)
	assert.Empty(t, system)

	_, err = svc.Assignments(ctx, "a/b")
	var invalid *InvalidTenantError
	assert.ErrorAs(t, err, &invalid)
}

// TestService_KeyStoreSeparatesScopes proves the system scope reads the
// physical key store, a tenant reads its own prefix, and an invalid tenant is
// refused.
func TestService_KeyStoreSeparatesScopes(t *testing.T) {
	cfg := validConfig(t)
	svc, err := NewService(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, svc.Close()) })

	system, err := svc.KeyStore("")
	require.NoError(t, err)
	assert.Same(t, cfg.Keys, system)

	attrs := &types.KeyAttributes{CN: "signer"}
	acme, err := svc.KeyStore("acme")
	require.NoError(t, err)
	require.NoError(t, acme.Save(attrs, []byte("blob"), store.FSEXT_PUBLIC_BLOB, false))
	stored, err := cfg.KeyStorage.Get(context.Background(), "acme"+tenantKeysSuffix+"signer"+store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	assert.Equal(t, []byte("blob"), stored)

	globex, err := svc.KeyStore("globex")
	require.NoError(t, err)
	_, err = globex.Get(attrs, store.FSEXT_PUBLIC_BLOB)
	assert.Error(t, err, "one tenant cannot read another's blobs")

	_, err = svc.KeyStore("a/b")
	var invalid *InvalidTenantError
	assert.ErrorAs(t, err, &invalid)
}

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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

func newTestRegistry(t *testing.T) (*Registry, storage.Backend) {
	t.Helper()
	store := storage.NewMemory()
	r, err := NewRegistry(store)
	require.NoError(t, err)
	return r, store
}

func testPolicy(name string) *Policy {
	return &Policy{
		Name:     name,
		Branches: []Branch{{Conditions: []Condition{{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{7}}}}},
		Index:    0x01500010,
	}
}

// TestRegistry_TracksObjectsAndPoliciesBothWays is the registry's reason to
// exist: a TPM cannot report an object's policy, so the registry answers
// "which policy does this key use" and "which keys use this policy".
func TestRegistry_TracksObjectsAndPoliciesBothWays(t *testing.T) {
	r, _ := newTestRegistry(t)
	ctx := context.Background()

	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/signer-a", Kind: ObjectKey, Policy: "boot"}))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/signer-b", Kind: ObjectKey, Policy: "boot"}))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/other", Kind: ObjectKey, Policy: PlatformPolicy}))

	objects, err := r.ObjectsOf(ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, []string{"key/signer-a", "key/signer-b"}, objects)

	a, err := r.PolicyOf(ctx, "acme", "key/signer-b")
	require.NoError(t, err)
	assert.Equal(t, "boot", a.Policy)
	assert.Equal(t, ObjectKey, a.Kind)

	platform, err := r.ObjectsOf(ctx, "acme", PlatformPolicy)
	require.NoError(t, err)
	assert.Equal(t, []string{"key/other"}, platform)
}

// TestRegistry_RefusesDeletingAnAssignedPolicy proves a policy still bound to
// objects cannot be deleted, and the error names every such object.
func TestRegistry_RefusesDeletingAnAssignedPolicy(t *testing.T) {
	r, _ := newTestRegistry(t)
	ctx := context.Background()
	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/a", Policy: "boot"}))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "sealed/b", Policy: "boot"}))

	err := r.DeletePolicy(ctx, "acme", "boot")
	var inUse *PolicyInUseError
	require.True(t, errors.As(err, &inUse), "got %v", err)
	assert.Equal(t, []string{"key/a", "sealed/b"}, inUse.Objects)

	require.NoError(t, r.Unassign(ctx, "acme", "key/a"))
	require.NoError(t, r.Unassign(ctx, "acme", "sealed/b"))
	require.NoError(t, r.DeletePolicy(ctx, "acme", "boot"))
	_, err = r.Policy(ctx, "acme", "boot")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

// TestRegistry_TenantsAreIsolated proves one tenant's policies and
// assignments are invisible to another, even under the same names.
func TestRegistry_TenantsAreIsolated(t *testing.T) {
	r, _ := newTestRegistry(t)
	ctx := context.Background()
	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/a", Policy: "boot"}))

	_, err := r.Policy(ctx, "globex", "boot")
	assert.ErrorIs(t, err, ErrPolicyNotFound)
	_, err = r.PolicyOf(ctx, "globex", "key/a")
	assert.ErrorIs(t, err, ErrNotAssigned)
	policies, err := r.ListPolicies(ctx, "globex")
	require.NoError(t, err)
	assert.Empty(t, policies)

	require.NoError(t, r.CreatePolicy(ctx, "globex", testPolicy("boot")), "the same name is free in another tenant")
	err = r.Assign(ctx, "globex", &Assignment{ObjectID: "key/a", Policy: "missing"})
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

// TestRegistry_IndexSurvivesAnInterruptedAssign proves an index entry left
// by a write that never reached its object record is dropped, not reported
// and not allowed to block deleting the policy.
func TestRegistry_IndexSurvivesAnInterruptedAssign(t *testing.T) {
	r, store := newTestRegistry(t)
	ctx := context.Background()
	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))

	dangling, err := key("acme", byPolicyPrefix+"boot/key/ghost")
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, dangling, indexMarker))

	objects, err := r.ObjectsOf(ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Empty(t, objects)
	exists, err := store.Exists(ctx, dangling)
	require.NoError(t, err)
	assert.False(t, exists, "the dangling index entry is removed")
	require.NoError(t, r.DeletePolicy(ctx, "acme", "boot"))
}

// TestRegistry_PolicyLifecycle covers create, update, list and the refusals.
func TestRegistry_PolicyLifecycle(t *testing.T) {
	r, _ := newTestRegistry(t)
	ctx := context.Background()

	require.NoError(t, r.CreatePolicy(ctx, "", testPolicy("zeta")))
	require.NoError(t, r.CreatePolicy(ctx, "", testPolicy("alpha")))
	assert.ErrorIs(t, r.CreatePolicy(ctx, "", testPolicy("alpha")), ErrPolicyExists)
	assert.ErrorIs(t, r.CreatePolicy(ctx, "", testPolicy(PlatformPolicy)), ErrReservedPolicy)
	assert.ErrorIs(t, r.DeletePolicy(ctx, "", PlatformPolicy), ErrReservedPolicy)

	updated := testPolicy("alpha")
	updated.Approvals = []*Approval{{Epoch: 2}}
	require.NoError(t, r.UpdatePolicy(ctx, "", updated))
	got, err := r.Policy(ctx, "system", "alpha")
	require.NoError(t, err, "the empty tenant is the system scope")
	assert.Equal(t, uint64(2), got.Approvals[0].Epoch)
	assert.Equal(t, []uint{7}, got.Branches[0].Conditions[0].PCRs)
	assert.ErrorIs(t, r.UpdatePolicy(ctx, "", testPolicy("missing")), ErrPolicyNotFound)

	list, err := r.ListPolicies(ctx, "")
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "alpha", list[0].Name)
	assert.Equal(t, "zeta", list[1].Name)
}

// TestRegistry_ScopeCannotBeRemovedWhilePopulated proves a tenant's scope
// (and so its TPM mode) is fixed while it holds objects or policies.
func TestRegistry_ScopeCannotBeRemovedWhilePopulated(t *testing.T) {
	r, _ := newTestRegistry(t)
	ctx := context.Background()

	_, err := r.Scope(ctx, "acme")
	assert.ErrorIs(t, err, ErrScopeNotFound)
	require.NoError(t, r.PutScope(ctx, &Scope{Tenant: "acme", Mode: ModeShared}))
	s, err := r.Scope(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, ModeShared, s.Mode)

	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/a", Policy: "boot"}))
	var inUse *ScopeInUseError
	require.True(t, errors.As(r.DeleteScope(ctx, "acme"), &inUse))
	assert.Equal(t, []string{"key/a"}, inUse.Objects)
	assert.Equal(t, []string{"boot"}, inUse.Policies)

	require.NoError(t, r.Unassign(ctx, "acme", "key/a"))
	require.NoError(t, r.DeletePolicy(ctx, "acme", "boot"))
	require.NoError(t, r.DeleteScope(ctx, "acme"))
	_, err = r.Scope(ctx, "acme")
	assert.ErrorIs(t, err, ErrScopeNotFound)
}

// TestRegistry_RefusesBadInput covers the argument errors.
func TestRegistry_RefusesBadInput(t *testing.T) {
	_, err := NewRegistry(nil)
	assert.ErrorIs(t, err, ErrNilStore)

	r, _ := newTestRegistry(t)
	ctx := context.Background()
	assert.ErrorIs(t, r.CreatePolicy(ctx, "acme", nil), ErrNilPolicy)
	assert.ErrorIs(t, r.UpdatePolicy(ctx, "acme", nil), ErrNilPolicy)
	assert.ErrorIs(t, r.PutScope(ctx, nil), ErrNilScope)
	assert.ErrorIs(t, r.Assign(ctx, "acme", nil), ErrNilAssignment)

	var nameErr *InvalidNameError
	for _, bad := range []string{"", ".", "..", "a/b", "a\x00b"} {
		assert.True(t, errors.As(r.CreatePolicy(ctx, "acme", testPolicy(bad)), &nameErr), "name %q", bad)
	}
	var tenantErr *InvalidTenantError
	assert.True(t, errors.As(r.CreatePolicy(ctx, "../etc", testPolicy("boot")), &tenantErr))

	require.NoError(t, r.Unassign(ctx, "acme", "key/none"), "unassigning an unassigned object is a no-op")
}

// TestParseMode accepts exactly the three modes.
func TestParseMode(t *testing.T) {
	for _, m := range []Mode{ModeNone, ModeShared, ModeVTPM} {
		got, err := ParseMode(string(m))
		require.NoError(t, err)
		assert.Equal(t, m, got)
	}
	_, err := ParseMode("dedicated")
	var modeErr *InvalidModeError
	assert.True(t, errors.As(err, &modeErr), "the retired name is not an alias")
}

// TestObjectID_Validation accepts "<kind>/<name>" object IDs only.
func TestObjectID_Validation(t *testing.T) {
	assert.Equal(t, "key/ca/root", ObjectID(ObjectKey, "ca/root"))
	for _, ok := range []string{"key/a", "sealed/b", "key/ca/root"} {
		assert.NoError(t, validObjectID(ok), ok)
	}
	var nameErr *InvalidNameError
	for _, bad := range []string{"", "key", "key/", "blob/a", "key/../a", "key//a", "key/a\x00"} {
		assert.True(t, errors.As(validObjectID(bad), &nameErr), "id %q", bad)
	}
}

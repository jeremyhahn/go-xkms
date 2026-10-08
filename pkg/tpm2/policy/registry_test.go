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

package policy

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// newTestRegistry returns a Registry over an in-process go-qrdb memory
// store serving DatabaseName.
func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := NewRegistry(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	return r
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
	r := newTestRegistry(t)
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
	r := newTestRegistry(t)
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
	r := newTestRegistry(t)
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

// TestRegistry_ReassignMovesTheObject proves an object's assignment is the
// one record of its policy: reassigning it moves it, so the policy it left no
// longer lists it and can be deleted.
func TestRegistry_ReassignMovesTheObject(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()
	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))
	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("next")))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/a", Policy: "boot"}))
	require.NoError(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/a", Policy: "next"}))

	objects, err := r.ObjectsOf(ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Empty(t, objects)
	objects, err = r.ObjectsOf(ctx, "acme", "next")
	require.NoError(t, err)
	assert.Equal(t, []string{"key/a"}, objects)
	require.NoError(t, r.DeletePolicy(ctx, "acme", "boot"))
}

// TestRegistry_PersistsThroughTheDAO proves every record round-trips through
// the go-qrdb DAO: a second registry over the same factory reads what the
// first wrote.
func TestRegistry_PersistsThroughTheDAO(t *testing.T) {
	ctx := context.Background()
	factory := testutil.NewMemoryDAOFactory()
	first, err := NewRegistry(factory)
	require.NoError(t, err)
	require.NoError(t, first.PutScope(ctx, &Scope{Tenant: "acme", Mode: ModeVTPM, Epoch: 3}))
	require.NoError(t, first.CreatePolicy(ctx, "acme", testPolicy("boot")))
	require.NoError(t, first.Assign(ctx, "acme", &Assignment{ObjectID: "sealed/s", Kind: ObjectSealed, Policy: "boot"}))

	second, err := NewRegistry(factory)
	require.NoError(t, err)
	s, err := second.Scope(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, ModeVTPM, s.Mode)
	assert.Equal(t, uint64(3), s.Epoch)
	p, err := second.Policy(ctx, "acme", "boot")
	require.NoError(t, err)
	assert.Equal(t, testPolicy("boot"), p)
	a, err := second.PolicyOf(ctx, "acme", "sealed/s")
	require.NoError(t, err)
	assert.Equal(t, ObjectSealed, a.Kind)
	scopes, err := second.Scopes(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"acme"}, scopes)
}

// TestNewRegistry_RefusesAFactoryWithoutTheDatabase proves the registry is
// never built over a factory that does not serve DatabaseName.
func TestNewRegistry_RefusesAFactoryWithoutTheDatabase(t *testing.T) {
	_, err := NewRegistry(nil)
	assert.ErrorIs(t, err, dao.ErrNilFactory)

	_, err = NewRegistry(dao.NewStoreFactory(nil))
	var unavailable *dao.DatabaseUnavailableError
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, DatabaseName, unavailable.Database)
}

// errStoreDown is the failure failingStore reports.
var errStoreDown = errors.New("store down")

// failingStore is a go-qrdb store whose reads fail. Wrapping the memory store
// also hides its atomic writes, so a guarded create fails too.
type failingStore struct{ qrdbsdk.KVStore }

func (failingStore) Get(context.Context, string) ([]byte, error) { return nil, errStoreDown }

func (failingStore) Scan(context.Context, string, func(string, []byte) error) error {
	return errStoreDown
}

func (failingStore) List(context.Context, string) ([]string, error) { return nil, errStoreDown }

// TestRegistry_ReportsStoreFailures proves a store failure is a *StoreError
// naming the operation and carrying the cause, never a not-found answer.
func TestRegistry_ReportsStoreFailures(t *testing.T) {
	ctx := context.Background()
	r, err := NewRegistry(dao.NewStoreFactory(failingStore{qrdbsdk.NewMemoryKVStore()}))
	require.NoError(t, err)

	tests := map[string]struct {
		op  string
		run func() error
	}{
		"scope":         {"get", func() error { _, err := r.Scope(ctx, "acme"); return err }},
		"policy":        {"get", func() error { _, err := r.Policy(ctx, "acme", "boot"); return err }},
		"policy of":     {"get", func() error { _, err := r.PolicyOf(ctx, "acme", "key/a"); return err }},
		"unassign":      {"get", func() error { return r.Unassign(ctx, "acme", "key/a") }},
		"list policies": {"list", func() error { _, err := r.ListPolicies(ctx, "acme"); return err }},
		"scopes":        {"list", func() error { _, err := r.Scopes(ctx); return err }},
		"create policy": {"put", func() error { return r.CreatePolicy(ctx, "acme", testPolicy("boot")) }},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var storeErr *StoreError
			require.ErrorAs(t, tt.run(), &storeErr)
			assert.Equal(t, tt.op, storeErr.Op)
		})
	}
}

// TestRegistry_PolicyLifecycle covers create, update, list and the refusals.
func TestRegistry_PolicyLifecycle(t *testing.T) {
	r := newTestRegistry(t)
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
	r := newTestRegistry(t)
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
	r := newTestRegistry(t)
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

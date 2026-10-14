package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// entityFailingStore fails the chosen operations only on keys of one entity
// type, so a test can let the registry's first step succeed and fail a later
// one.
type entityFailingStore struct {
	qrdbsdk.AtomicKVStore
	entity string
	ops    map[string]bool
}

func (s entityFailingStore) fails(op, key string) bool {
	return s.ops[op] && strings.Contains(key, s.entity)
}

func (s entityFailingStore) Get(ctx context.Context, key string) ([]byte, error) {
	if s.fails("get", key) {
		return nil, errStoreDown
	}
	return s.AtomicKVStore.Get(ctx, key)
}

func (s entityFailingStore) Put(ctx context.Context, key string, value []byte) error {
	if s.fails("put", key) {
		return errStoreDown
	}
	return s.AtomicKVStore.Put(ctx, key, value)
}

func (s entityFailingStore) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if s.fails("put", key) {
		return false, errStoreDown
	}
	return s.AtomicKVStore.PutIfAbsent(ctx, key, value)
}

func (s entityFailingStore) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if s.fails("put", key) {
		return false, errStoreDown
	}
	return s.AtomicKVStore.CompareAndSwap(ctx, key, expected, next)
}

func (s entityFailingStore) Delete(ctx context.Context, key string) error {
	if s.fails("delete", key) {
		return errStoreDown
	}
	return s.AtomicKVStore.Delete(ctx, key)
}

func (s entityFailingStore) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if s.fails("delete", key) {
		return false, errStoreDown
	}
	return s.AtomicKVStore.CompareAndDelete(ctx, key, expected)
}

func (s entityFailingStore) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	if s.fails("list", prefix) {
		return errStoreDown
	}
	return s.AtomicKVStore.Scan(ctx, prefix, fn)
}

func (s entityFailingStore) List(ctx context.Context, prefix string) ([]string, error) {
	if s.fails("list", prefix) {
		return nil, errStoreDown
	}
	return s.AtomicKVStore.List(ctx, prefix)
}

// newEntityFailingRegistry returns a registry over a store whose entity keys
// fail once armed, so a test can seed the registry before the failure.
func newEntityFailingRegistry(t *testing.T, entity string) (*Registry, *entityFailingStore) {
	t.Helper()
	store := &entityFailingStore{AtomicKVStore: qrdbsdk.NewMemoryKVStore(), entity: entity, ops: map[string]bool{}}
	r, err := NewRegistry(dao.NewStoreFactory(store))
	require.NoError(t, err)
	return r, store
}

// arm makes the given operations fail from now on.
func (s *entityFailingStore) arm(ops ...string) {
	for _, op := range ops {
		s.ops[op] = true
	}
}

func requireStoreOp(t *testing.T, err error, op string) {
	t.Helper()
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, op, storeErr.Op)
	assert.ErrorIs(t, err, errStoreDown)
}

func TestRegistry_RefusesAnInvalidTenantOnEveryOperation(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()
	const bad = "../etc"

	ops := map[string]func() error{
		"scope":         func() error { _, err := r.Scope(ctx, bad); return err },
		"put scope":     func() error { return r.PutScope(ctx, &Scope{Tenant: bad}) },
		"delete scope":  func() error { return r.DeleteScope(ctx, bad) },
		"policy":        func() error { _, err := r.Policy(ctx, bad, "boot"); return err },
		"update policy": func() error { return r.UpdatePolicy(ctx, bad, testPolicy("boot")) },
		"list policies": func() error { _, err := r.ListPolicies(ctx, bad); return err },
		"delete policy": func() error { return r.DeletePolicy(ctx, bad, "boot") },
		"assign":        func() error { return r.Assign(ctx, bad, &Assignment{ObjectID: "key/a", Policy: PlatformPolicy}) },
		"unassign":      func() error { return r.Unassign(ctx, bad, "key/a") },
		"policy of":     func() error { _, err := r.PolicyOf(ctx, bad, "key/a"); return err },
		"objects of":    func() error { _, err := r.ObjectsOf(ctx, bad, "boot"); return err },
		"assignments":   func() error { _, err := r.Assignments(ctx, bad); return err },
	}
	for name, run := range ops {
		t.Run(name, func(t *testing.T) {
			var tenantErr *InvalidTenantError
			require.ErrorAs(t, run(), &tenantErr)
			assert.Equal(t, bad, tenantErr.Tenant)
		})
	}
}

func TestRegistry_RefusesInvalidNamesBeforeTouchingTheStore(t *testing.T) {
	r := newTestRegistry(t)
	ctx := context.Background()
	var nameErr *InvalidNameError

	_, err := r.ObjectsOf(ctx, "acme", "a/b")
	require.ErrorAs(t, err, &nameErr)
	_, err = r.PolicyOf(ctx, "acme", "nokind")
	require.ErrorAs(t, err, &nameErr)
	require.ErrorAs(t, r.Unassign(ctx, "acme", "key/../a"), &nameErr)
	require.ErrorAs(t, r.DeletePolicy(ctx, "acme", ".."), &nameErr)
	assert.ErrorIs(t, r.DeletePolicy(ctx, "acme", PlatformPolicy), ErrReservedPolicy)
	assert.ErrorIs(t, r.DeletePolicy(ctx, "acme", "missing"), ErrPolicyNotFound)
}

func TestRegistry_ReportsAssignmentListingFailures(t *testing.T) {
	ctx := context.Background()
	r, store := newEntityFailingRegistry(t, assignmentEntityType)
	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))
	store.arm("list")

	requireStoreOp(t, r.DeleteScope(ctx, "acme"), "list")
	requireStoreOp(t, r.DeletePolicy(ctx, "acme", "boot"), "list")
	_, err := r.ObjectsOf(ctx, "acme", "boot")
	requireStoreOp(t, err, "list")
	_, err = r.Assignments(ctx, "acme")
	requireStoreOp(t, err, "list")

	_, err = r.Policy(ctx, "acme", "boot")
	require.NoError(t, err, "a policy whose assignments cannot be listed is not deleted")
}

func TestRegistry_DeleteScopeReportsAPolicyListingFailure(t *testing.T) {
	ctx := context.Background()
	r, store := newEntityFailingRegistry(t, policyEntityType)
	require.NoError(t, r.PutScope(ctx, &Scope{Tenant: "acme"}))
	store.arm("list")

	requireStoreOp(t, r.DeleteScope(ctx, "acme"), "list")
	_, err := r.Scope(ctx, "acme")
	require.NoError(t, err, "the scope survives a refused delete")
}

func TestRegistry_ReportsWriteAndDeleteFailures(t *testing.T) {
	ctx := context.Background()

	r, store := newEntityFailingRegistry(t, assignmentEntityType)
	store.arm("put")
	requireStoreOp(t, r.Assign(ctx, "acme", &Assignment{ObjectID: "key/a", Policy: PlatformPolicy}), "put")

	r, store = newEntityFailingRegistry(t, policyEntityType)
	require.NoError(t, r.CreatePolicy(ctx, "acme", testPolicy("boot")))
	store.arm("delete")
	requireStoreOp(t, r.DeletePolicy(ctx, "acme", "boot"), "delete")
	_, err := r.Policy(ctx, "acme", "boot")
	assert.False(t, errors.Is(err, ErrPolicyNotFound), "a failed delete leaves the policy in place")
}

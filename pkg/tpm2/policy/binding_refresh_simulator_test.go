//go:build tpm_simulator

package policy

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// bindingWriteFailingStore fails, once armed, every write of one object's
// binding record, so a refresh of the scope's records stops part-way.
type bindingWriteFailingStore struct {
	qrdbsdk.AtomicKVStore
	object string
	armed  atomic.Bool
}

func (s *bindingWriteFailingStore) fails(value []byte) bool {
	return s.armed.Load() &&
		bytes.Contains(value, []byte(s.object)) &&
		bytes.Contains(value, []byte(store.FSEXT_TPM_POLICY))
}

func (s *bindingWriteFailingStore) Put(ctx context.Context, key string, value []byte) error {
	if s.fails(value) {
		return errStoreDown
	}
	return s.AtomicKVStore.Put(ctx, key, value)
}

func (s *bindingWriteFailingStore) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if s.fails(value) {
		return false, errStoreDown
	}
	return s.AtomicKVStore.PutIfAbsent(ctx, key, value)
}

func (s *bindingWriteFailingStore) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if s.fails(next) {
		return false, errStoreDown
	}
	return s.AtomicKVStore.CompareAndSwap(ctx, key, expected, next)
}

// newBindingFailureFixture returns a simulator fixture whose tenant blobs
// fail the writes of object's binding record once armed.
func newBindingFailureFixture(t *testing.T, object string) (*fixture, *bindingWriteFailingStore) {
	t.Helper()
	f := newSimFixture(t)
	kv := &bindingWriteFailingStore{AtomicKVStore: qrdbsdk.NewMemoryKVStore(), object: object}
	blobs, err := store.NewBlobStore(quietLogger, dao.NewStoreFactory(kv))
	require.NoError(t, err)
	f.tenantKeys = blobs
	f.cfg.TenantKeys = blobs
	f.restart()
	return f, kv
}

// storedBindingRecord reads key's binding record straight from the tenant's
// blobs, without opening (and so reconciling) the scope.
func (f *fixture) storedBindingRecord(tenant string, key *types.KeyAttributes) []byte {
	f.t.Helper()
	keys, err := f.tenantKeys.Tenant(tenant)
	require.NoError(f.t, err)
	record, err := keys.Get(key, store.FSEXT_TPM_POLICY)
	require.NoError(f.t, err)
	return record
}

// TestService_ReconcileFinishesAnInterruptedBindingRefresh stops the refresh
// of a scope's binding records part-way, after the first object's record and
// before the second's, and shows the scope's next opening, after a restart or
// in the same process, rewrites every record: the counter stays ahead of the
// scope's epoch, or the rotation stays recorded, until every record is saved.
func TestService_ReconcileFinishesAnInterruptedBindingRefresh(t *testing.T) {
	changes := map[string]func(f *fixture) error{
		"update": func(f *fixture) error {
			_, err := f.svc.UpdatePolicy(f.ctx, "acme", "boot")
			return err
		},
		"rotate": func(f *fixture) error {
			_, err := f.svc.RotateAuthority(f.ctx, "acme")
			return err
		},
	}
	reopens := map[string]func(f *fixture){
		"after a restart":     func(f *fixture) { f.restart() },
		"in the same process": func(*fixture) {},
	}
	for change, apply := range changes {
		for reopen, reopenScope := range reopens {
			t.Run(change+" "+reopen, func(t *testing.T) {
				f, kv := newBindingFailureFixture(t, "signer-b")
				f.createPolicy("acme", "boot")
				first := f.createKey("acme", "signer-a", "boot", nil)
				second := f.createKey("acme", "signer-b", "boot", nil)
				staleFirst := f.storedBindingRecord("acme", first)
				staleSecond := f.storedBindingRecord("acme", second)

				kv.armed.Store(true)
				require.ErrorIs(t, apply(f), errStoreDown, "the second record's write fails")
				assert.NotEqual(t, staleFirst, f.storedBindingRecord("acme", first),
					"the refresh stopped part-way, after the first record")
				assert.Equal(t, staleSecond, f.storedBindingRecord("acme", second))

				kv.armed.Store(false)
				reopenScope(f)

				recordFirst := f.bindingRecord("acme", first)
				recordSecond := f.bindingRecord("acme", second)
				assert.NotEqual(t, staleSecond, recordSecond, "reconcile rewrites the record the failure skipped")
				require.NoError(t, f.signOffline("acme", first, recordFirst))
				require.NoError(t, f.signOffline("acme", second, recordSecond))
				require.Error(t, f.signOffline("acme", second, staleSecond), "the stale record no longer authorizes")

				scope, err := f.registry.Scope(f.ctx, "acme")
				require.NoError(t, err)
				assert.Nil(t, scope.Rotating, "no rotation is left in progress")
			})
		}
	}
}

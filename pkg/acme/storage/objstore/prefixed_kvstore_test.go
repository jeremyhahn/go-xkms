//go:build codec_json

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

package objstore

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"testing"

	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errRecorded is the sentinel the recording store returns so the tests can
// prove prefixedKVStore surfaces inner failures verbatim rather than
// swallowing or re-typing them.
var errRecorded = errors.New("recorded store failure")

// newSharedKV returns a single in-memory KVStore that several tenant-scoped
// wrappers can share, which is the configuration that makes cross-tenant
// leakage possible and therefore the one worth testing.
func newSharedKV(t *testing.T) xkmssdk.QRDBKVStore {
	t.Helper()
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	return kv
}

// TestPrefixedKVStore_AppliesPrefixOnWriteAndRead proves the wrapper actually
// rewrites keys rather than passing them through. Asserting on the inner
// store's view is the point: a regression that dropped the prefix would still
// round-trip successfully through the wrapper's own Get, so a round-trip-only
// test could not catch it — but every tenant's data would then collide.
func TestPrefixedKVStore_AppliesPrefixOnWriteAndRead(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	scoped := newPrefixedKVStore(inner, "acme/tenants/alpha")

	require.NoError(t, scoped.Put(ctx, "accounts/1", []byte("alpha-account")))

	// The inner store must hold the fully-qualified key ...
	raw, err := inner.Get(ctx, "acme/tenants/alpha/accounts/1")
	require.NoError(t, err)
	assert.Equal(t, []byte("alpha-account"), raw)

	// ... and must NOT hold the unprefixed key.
	exists, err := inner.Exists(ctx, "accounts/1")
	require.NoError(t, err)
	assert.False(t, exists, "the unprefixed key leaked into the shared namespace")

	// The wrapper reads back through the same prefix.
	got, err := scoped.Get(ctx, "accounts/1")
	require.NoError(t, err)
	assert.Equal(t, []byte("alpha-account"), got)
}

// TestPrefixedKVStore_ExistsAndDeleteAreTenantScoped covers the Exists and
// Delete seams together with the isolation invariant that matters most: one
// tenant deleting its copy of a shared logical key must not remove another
// tenant's copy.
func TestPrefixedKVStore_ExistsAndDeleteAreTenantScoped(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	alpha := newPrefixedKVStore(inner, "acme/tenants/alpha")
	beta := newPrefixedKVStore(inner, "acme/tenants/beta")

	require.NoError(t, alpha.Put(ctx, "nonces/n1", []byte("alpha")))
	require.NoError(t, beta.Put(ctx, "nonces/n1", []byte("beta")))

	// Same logical key, different values — no collision.
	alphaVal, err := alpha.Get(ctx, "nonces/n1")
	require.NoError(t, err)
	betaVal, err := beta.Get(ctx, "nonces/n1")
	require.NoError(t, err)
	assert.Equal(t, []byte("alpha"), alphaVal)
	assert.Equal(t, []byte("beta"), betaVal)

	for _, s := range []xkmssdk.QRDBKVStore{alpha, beta} {
		exists, err := s.Exists(ctx, "nonces/n1")
		require.NoError(t, err)
		assert.True(t, exists)
	}

	// Deleting alpha's copy must leave beta's intact.
	require.NoError(t, alpha.Delete(ctx, "nonces/n1"))

	alphaExists, err := alpha.Exists(ctx, "nonces/n1")
	require.NoError(t, err)
	assert.False(t, alphaExists, "alpha's key survived its own delete")

	betaExists, err := beta.Exists(ctx, "nonces/n1")
	require.NoError(t, err)
	assert.True(t, betaExists, "deleting alpha's key also removed beta's — tenant isolation is broken")

	betaVal, err = beta.Get(ctx, "nonces/n1")
	require.NoError(t, err)
	assert.Equal(t, []byte("beta"), betaVal)

	// Exists on a key that was never written must report false, not error.
	missing, err := alpha.Exists(ctx, "nonces/never-written")
	require.NoError(t, err)
	assert.False(t, missing)
}

// TestPrefixedKVStore_ScanIsIsolatedAndStripsPrefix covers the Scan seam. Two
// properties matter: a tenant must never observe another tenant's rows, and
// the keys handed to the callback must be relative — a leaked prefix would be
// parsed as part of the entity ID by the DAO layer above.
func TestPrefixedKVStore_ScanIsIsolatedAndStripsPrefix(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	alpha := newPrefixedKVStore(inner, "acme/tenants/alpha")
	beta := newPrefixedKVStore(inner, "acme/tenants/beta")

	require.NoError(t, alpha.Put(ctx, "orders/1", []byte("a1")))
	require.NoError(t, alpha.Put(ctx, "orders/2", []byte("a2")))
	require.NoError(t, alpha.Put(ctx, "accounts/9", []byte("a9")))
	require.NoError(t, beta.Put(ctx, "orders/1", []byte("b1")))
	require.NoError(t, beta.Put(ctx, "orders/3", []byte("b3")))
	// A global (unscoped) row that shares the leading path segment.
	require.NoError(t, inner.Put(ctx, "acme/tenants/alphabet/orders/7", []byte("other-tenant")))

	collect := func(s xkmssdk.QRDBKVStore, prefix string) map[string]string {
		out := map[string]string{}
		require.NoError(t, s.Scan(ctx, prefix, func(key string, value []byte) error {
			out[key] = string(value)
			return nil
		}))
		return out
	}

	alphaOrders := collect(alpha, "orders/")
	assert.Equal(t, map[string]string{"orders/1": "a1", "orders/2": "a2"}, alphaOrders,
		"alpha's scan must return only alpha's orders, with the tenant prefix stripped")

	betaOrders := collect(beta, "orders/")
	assert.Equal(t, map[string]string{"orders/1": "b1", "orders/3": "b3"}, betaOrders)

	// An empty prefix scans the whole tenant namespace and still excludes the
	// similarly-named "alphabet" tenant.
	allAlpha := collect(alpha, "")
	assert.Equal(t, map[string]string{"orders/1": "a1", "orders/2": "a2", "accounts/9": "a9"}, allAlpha)
	for key := range allAlpha {
		assert.NotContains(t, key, "acme/tenants/", "the tenant prefix leaked into a scanned key: %q", key)
	}
}

// TestPrefixedKVStore_ScanPropagatesCallbackError verifies an aborting
// callback stops the scan and its error reaches the caller. Swallowing it
// would turn a partial read into a silently-successful one.
func TestPrefixedKVStore_ScanPropagatesCallbackError(t *testing.T) {
	ctx := context.Background()
	scoped := newPrefixedKVStore(newSharedKV(t), "acme/tenants/alpha")

	for i := 0; i < 5; i++ {
		require.NoError(t, scoped.Put(ctx, "orders/"+strconv.Itoa(i), []byte("v")))
	}

	var seen int
	err := scoped.Scan(ctx, "orders/", func(string, []byte) error {
		seen++
		return errRecorded
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, errRecorded)
	assert.Equal(t, 1, seen, "scan continued past a failing callback")
}

// TestPrefixedKVStore_ListIsIsolatedAndStripsPrefix mirrors the Scan
// guarantees for the List seam, which returns keys only.
func TestPrefixedKVStore_ListIsIsolatedAndStripsPrefix(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)
	alpha := newPrefixedKVStore(inner, "acme/tenants/alpha")
	beta := newPrefixedKVStore(inner, "acme/tenants/beta")

	require.NoError(t, alpha.Put(ctx, "certificates/1", []byte("a")))
	require.NoError(t, alpha.Put(ctx, "certificates/2", []byte("a")))
	require.NoError(t, beta.Put(ctx, "certificates/1", []byte("b")))

	alphaKeys, err := alpha.List(ctx, "certificates/")
	require.NoError(t, err)
	sort.Strings(alphaKeys)
	assert.Equal(t, []string{"certificates/1", "certificates/2"}, alphaKeys)

	betaKeys, err := beta.List(ctx, "certificates/")
	require.NoError(t, err)
	assert.Equal(t, []string{"certificates/1"}, betaKeys)

	// Listing a namespace this tenant never wrote to yields nothing rather
	// than another tenant's rows.
	empty, err := alpha.List(ctx, "eab/")
	require.NoError(t, err)
	assert.Empty(t, empty)
}

// recordingKVStore captures the arguments prefixedKVStore forwards and can
// force each method to fail, so the delegation contract and the error paths
// can both be pinned without a real backend.
type recordingKVStore struct {
	mu sync.Mutex

	listKeys []string
	failList error

	registeredEntity  string
	registeredIndexes []xkmssdk.QRDBEntityIndex
	failRegister      error

	queryIndexName  string
	queryIndexValue []byte
	queryIndexOut   [][]byte
	failQueryIndex  error

	scanIndexName  string
	scanIndexStart []byte
	scanIndexEnd   []byte
	scanIndexOut   map[string][][]byte
	failScanIndex  error

	compoundName   string
	compoundValues [][]byte
	compoundOut    [][]byte
	failCompound   error

	scanCompoundName   string
	scanCompoundPrefix [][]byte
	scanCompoundStart  []byte
	scanCompoundEnd    []byte
	scanCompoundOut    map[string][][]byte
	failScanCompound   error
}

func (r *recordingKVStore) Put(context.Context, string, []byte) error { return nil }
func (r *recordingKVStore) Get(context.Context, string) ([]byte, error) {
	return nil, errRecorded
}
func (r *recordingKVStore) Delete(context.Context, string) error { return nil }
func (r *recordingKVStore) Scan(context.Context, string, func(string, []byte) error) error {
	return nil
}

func (r *recordingKVStore) List(_ context.Context, _ string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failList != nil {
		return nil, r.failList
	}
	return r.listKeys, nil
}

func (r *recordingKVStore) Exists(context.Context, string) (bool, error) { return false, nil }

func (r *recordingKVStore) RegisterEntityIndexes(entityType string, indexes []xkmssdk.QRDBEntityIndex) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registeredEntity = entityType
	r.registeredIndexes = indexes
	return r.failRegister
}

func (r *recordingKVStore) QueryIndex(_ context.Context, indexName string, value []byte) ([][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queryIndexName = indexName
	r.queryIndexValue = value
	return r.queryIndexOut, r.failQueryIndex
}

func (r *recordingKVStore) ScanIndex(_ context.Context, indexName string, start, end []byte) (map[string][][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanIndexName = indexName
	r.scanIndexStart = start
	r.scanIndexEnd = end
	return r.scanIndexOut, r.failScanIndex
}

func (r *recordingKVStore) QueryCompoundIndex(_ context.Context, indexName string, values [][]byte) ([][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.compoundName = indexName
	r.compoundValues = values
	return r.compoundOut, r.failCompound
}

func (r *recordingKVStore) ScanCompoundIndex(_ context.Context, indexName string, prefixValues [][]byte, rangeStart, rangeEnd []byte) (map[string][][]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanCompoundName = indexName
	r.scanCompoundPrefix = prefixValues
	r.scanCompoundStart = rangeStart
	r.scanCompoundEnd = rangeEnd
	return r.scanCompoundOut, r.failScanCompound
}

// TestPrefixedKVStore_IndexOperationsDelegateUnprefixed pins the index
// surface. Index names are intentionally NOT rewritten — unlike primary keys
// they are forwarded verbatim to the inner store, which owns index naming.
// The assertions document that contract so a future change to prefix (or to
// stop prefixing) index names is a deliberate, visible decision.
func TestPrefixedKVStore_IndexOperationsDelegateUnprefixed(t *testing.T) {
	ctx := context.Background()
	rec := &recordingKVStore{
		queryIndexOut:   [][]byte{[]byte("pk-1")},
		scanIndexOut:    map[string][][]byte{"idx": {[]byte("pk-2")}},
		compoundOut:     [][]byte{[]byte("pk-3")},
		scanCompoundOut: map[string][][]byte{"cidx": {[]byte("pk-4")}},
	}
	scoped := newPrefixedKVStore(rec, "acme/tenants/alpha")

	indexes := []xkmssdk.QRDBEntityIndex{{FieldName: "Status", JSONFieldName: "status", Unique: false}}
	require.NoError(t, scoped.RegisterEntityIndexes("account", indexes))
	assert.Equal(t, "account", rec.registeredEntity, "entity type must be forwarded unchanged")
	assert.Equal(t, indexes, rec.registeredIndexes)

	pks, err := scoped.QueryIndex(ctx, "by_status", []byte("valid"))
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("pk-1")}, pks)
	assert.Equal(t, "by_status", rec.queryIndexName)
	assert.Equal(t, []byte("valid"), rec.queryIndexValue)

	scanned, err := scoped.ScanIndex(ctx, "by_expiry", []byte("a"), []byte("z"))
	require.NoError(t, err)
	assert.Equal(t, map[string][][]byte{"idx": {[]byte("pk-2")}}, scanned)
	assert.Equal(t, "by_expiry", rec.scanIndexName)
	assert.Equal(t, []byte("a"), rec.scanIndexStart)
	assert.Equal(t, []byte("z"), rec.scanIndexEnd)

	compound, err := scoped.QueryCompoundIndex(ctx, "by_acct_status", [][]byte{[]byte("1"), []byte("valid")})
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("pk-3")}, compound)
	assert.Equal(t, "by_acct_status", rec.compoundName)
	assert.Equal(t, [][]byte{[]byte("1"), []byte("valid")}, rec.compoundValues)

	scanCompound, err := scoped.ScanCompoundIndex(ctx, "by_acct_expiry", [][]byte{[]byte("1")}, []byte("a"), []byte("z"))
	require.NoError(t, err)
	assert.Equal(t, map[string][][]byte{"cidx": {[]byte("pk-4")}}, scanCompound)
	assert.Equal(t, "by_acct_expiry", rec.scanCompoundName)
	assert.Equal(t, [][]byte{[]byte("1")}, rec.scanCompoundPrefix)
	assert.Equal(t, []byte("a"), rec.scanCompoundStart)
	assert.Equal(t, []byte("z"), rec.scanCompoundEnd)
}

// TestPrefixedKVStore_PropagatesInnerErrors verifies every delegating method
// surfaces the inner store's failure instead of masking it as an empty result,
// which would silently turn a storage outage into "no ACME orders exist".
func TestPrefixedKVStore_PropagatesInnerErrors(t *testing.T) {
	ctx := context.Background()
	rec := &recordingKVStore{
		failList:         errRecorded,
		failRegister:     errRecorded,
		failQueryIndex:   errRecorded,
		failScanIndex:    errRecorded,
		failCompound:     errRecorded,
		failScanCompound: errRecorded,
	}
	scoped := newPrefixedKVStore(rec, "acme/tenants/alpha")

	keys, err := scoped.List(ctx, "orders/")
	assert.ErrorIs(t, err, errRecorded)
	assert.Nil(t, keys, "List must not return a partial slice alongside an error")

	assert.ErrorIs(t, scoped.RegisterEntityIndexes("account", nil), errRecorded)

	_, err = scoped.QueryIndex(ctx, "idx", []byte("v"))
	assert.ErrorIs(t, err, errRecorded)

	_, err = scoped.ScanIndex(ctx, "idx", nil, nil)
	assert.ErrorIs(t, err, errRecorded)

	_, err = scoped.QueryCompoundIndex(ctx, "idx", nil)
	assert.ErrorIs(t, err, errRecorded)

	_, err = scoped.ScanCompoundIndex(ctx, "idx", nil, nil, nil)
	assert.ErrorIs(t, err, errRecorded)

	// Get delegates too; a missing key must surface the inner error.
	_, err = scoped.Get(ctx, "orders/1")
	assert.ErrorIs(t, err, errRecorded)
}

// TestPrefixedKVStore_ConcurrentTenantWritesStayIsolated runs the wrapper the
// way the ACME server does — many goroutines, several tenants, one shared
// store — so the race detector covers the prefixing path and the final state
// proves no tenant clobbered another.
func TestPrefixedKVStore_ConcurrentTenantWritesStayIsolated(t *testing.T) {
	ctx := context.Background()
	inner := newSharedKV(t)

	const (
		tenants = 4
		rows    = 25
	)
	stores := make([]xkmssdk.QRDBKVStore, tenants)
	for i := range stores {
		stores[i] = newPrefixedKVStore(inner, "acme/tenants/t"+strconv.Itoa(i))
	}

	var wg sync.WaitGroup
	for i := range stores {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < rows; j++ {
				key := "orders/" + strconv.Itoa(j)
				val := []byte("t" + strconv.Itoa(idx) + "-o" + strconv.Itoa(j))
				if err := stores[idx].Put(ctx, key, val); err != nil {
					t.Errorf("tenant %d put %s: %v", idx, key, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	for i := range stores {
		keys, err := stores[i].List(ctx, "orders/")
		require.NoError(t, err)
		assert.Len(t, keys, rows, "tenant %d sees %d rows, want %d", i, len(keys), rows)

		for j := 0; j < rows; j++ {
			got, err := stores[i].Get(ctx, "orders/"+strconv.Itoa(j))
			require.NoError(t, err)
			want := "t" + strconv.Itoa(i) + "-o" + strconv.Itoa(j)
			assert.Equal(t, want, string(got), "tenant %d row %d was overwritten by another tenant", i, j)
		}
	}
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package common

import (
	"context"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNonceDAO is a thread-safe mock implementation of GenericDAO[*entities.ACMENonce] for testing.
type mockNonceDAO struct {
	mu     sync.Mutex
	nonces map[uint64]*entities.ACMENonce
}

func newMockNonceDAO() *mockNonceDAO {
	return &mockNonceDAO{
		nonces: make(map[uint64]*entities.ACMENonce),
	}
}

func (m *mockNonceDAO) Save(_ context.Context, nonce *entities.ACMENonce) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonces[nonce.ID] = nonce
	return nil
}

func (m *mockNonceDAO) SaveWithCondition(_ context.Context, _ *entities.ACMENonce, _ qrdbsdk.Condition) error {
	panic("not implemented")
}

func (m *mockNonceDAO) Get(_ context.Context, id uint64) (*entities.ACMENonce, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	nonce, ok := m.nonces[id]
	if !ok {
		return nil, assert.AnError
	}
	return nonce, nil
}

func (m *mockNonceDAO) Delete(_ context.Context, nonce *entities.ACMENonce) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nonces, nonce.ID)
	return nil
}

func (m *mockNonceDAO) Count(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.nonces), nil
}

func (m *mockNonceDAO) Page(_ context.Context, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMENonce], error) {
	panic("not implemented")
}

func (m *mockNonceDAO) ForEachPage(ctx context.Context, query qrdbsdk.PageQuery, fn qrdbsdk.PagerFunc[*entities.ACMENonce]) error {
	m.mu.Lock()
	nonces := make([]*entities.ACMENonce, 0, len(m.nonces))
	for _, n := range m.nonces {
		nonces = append(nonces, n)
	}
	m.mu.Unlock()

	result := qrdbsdk.PageResult[*entities.ACMENonce]{
		Entities: nonces,
		HasMore:  false,
	}
	return fn(result)
}

func (m *mockNonceDAO) EntityType() string {
	return "nonces"
}

func (m *mockNonceDAO) QueryByIndex(_ context.Context, _ string, _ interface{}) ([]*entities.ACMENonce, error) {
	panic("not implemented")
}

func (m *mockNonceDAO) QueryByCompoundIndex(_ context.Context, _ string, _ []interface{}) ([]*entities.ACMENonce, error) {
	panic("not implemented")
}

func (m *mockNonceDAO) ScanByCompoundIndex(_ context.Context, _ string, _ []interface{}, _, _ interface{}) ([]*entities.ACMENonce, error) {
	panic("not implemented")
}

func (m *mockNonceDAO) QueryOneByIndex(_ context.Context, _ string, _ interface{}) (*entities.ACMENonce, error) {
	panic("not implemented")
}

func (m *mockNonceDAO) ScanByIndex(_ context.Context, _ string, _, _ interface{}) ([]*entities.ACMENonce, error) {
	panic("not implemented")
}

func (m *mockNonceDAO) PageByIndex(_ context.Context, _ string, _ interface{}, _ qrdbsdk.PageQuery) (qrdbsdk.PageResult[*entities.ACMENonce], error) {
	panic("not implemented")
}

func (m *mockNonceDAO) CountByIndex(_ context.Context, _ string, _ interface{}) (int, error) {
	panic("not implemented")
}

func (m *mockNonceDAO) Find(_ context.Context) *qrdbsdk.QueryBuilder[*entities.ACMENonce] {
	panic("not implemented")
}

// List is a test helper (not part of GenericDAO) to inspect stored nonces.
func (m *mockNonceDAO) List(_ context.Context, _ string) ([]*entities.ACMENonce, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*entities.ACMENonce, 0, len(m.nonces))
	for _, nonce := range m.nonces {
		result = append(result, nonce)
	}
	return result, nil
}

// Verify interfaces are implemented
var _ NonceStoreInterface = (*NonceStore)(nil)
var _ NonceStoreInterface = (*PersistentNonceStore)(nil)
var _ NonceStoreInterface = (*PersistentNonceStoreWithFallback)(nil)

func TestPersistentNonceStore_AddAndExists(t *testing.T) {
	dao := newMockNonceDAO()
	store := &PersistentNonceStore{
		dao: dao,
		ttl: time.Hour,
	}

	nonce := "test-nonce-12345"

	// Nonce should not exist initially
	assert.False(t, store.Exists(nonce))

	// Add the nonce
	store.Add(nonce)

	// Nonce should now exist
	assert.True(t, store.Exists(nonce))

	// Nonce should be consumed (single use)
	assert.False(t, store.Exists(nonce))
}

func TestPersistentNonceStore_Expiration(t *testing.T) {
	dao := newMockNonceDAO()
	// Use 2-second TTL since Unix timestamps have second precision
	store := &PersistentNonceStore{
		dao: dao,
		ttl: 2 * time.Second,
	}

	nonce := "expiring-nonce"

	// Add nonce and verify it exists immediately
	store.Add(nonce)
	assert.True(t, store.Exists(nonce))

	// Add new nonce and wait for expiration
	nonce2 := "expiring-nonce-2"
	store.Add(nonce2)
	time.Sleep(3 * time.Second)

	// Should be expired now
	assert.False(t, store.Exists(nonce2))
}

func TestPersistentNonceStore_HashCollisionProtection(t *testing.T) {
	dao := newMockNonceDAO()
	store := &PersistentNonceStore{
		dao: dao,
		ttl: time.Hour,
	}

	nonce1 := "nonce-a"
	nonce2 := "nonce-b"

	store.Add(nonce1)

	// Different nonce should not match even if we forced a collision
	// (in practice FNV-1a has very low collision rate)
	assert.True(t, store.Exists(nonce1))
	assert.False(t, store.Exists(nonce2))
}

func TestPersistentNonceStore_ConcurrentAccess(t *testing.T) {
	dao := newMockNonceDAO()
	store := &PersistentNonceStore{
		dao: dao,
		ttl: time.Hour,
	}

	var wg sync.WaitGroup
	const numGoroutines = 100

	// Concurrent adds
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			nonce, _ := GenerateNonce(32)
			store.Add(nonce)
		}(i)
	}
	wg.Wait()

	// All nonces should be stored
	nonces, err := dao.List(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, numGoroutines, len(nonces))
}

func TestPersistentNonceStore_Sweep(t *testing.T) {
	dao := newMockNonceDAO()
	// Use 1-second TTL since Unix timestamps have second precision
	store := &PersistentNonceStore{
		dao: dao,
		ttl: 1 * time.Second,
	}

	// Add multiple nonces
	for i := 0; i < 5; i++ {
		nonce, _ := GenerateNonce(32)
		store.Add(nonce)
	}

	// Verify all stored
	nonces, _ := dao.List(context.Background(), "")
	assert.Equal(t, 5, len(nonces))

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Run sweep
	store.sweep()

	// All should be cleaned up
	nonces, _ = dao.List(context.Background(), "")
	assert.Equal(t, 0, len(nonces))
}

func TestPersistentNonceStore_HashNonce(t *testing.T) {
	store := &PersistentNonceStore{}

	// Same nonce should produce same hash
	nonce := "test-nonce"
	hash1 := store.hashNonce(nonce)
	hash2 := store.hashNonce(nonce)
	assert.Equal(t, hash1, hash2)

	// Different nonces should produce different hashes
	hash3 := store.hashNonce("different-nonce")
	assert.NotEqual(t, hash1, hash3)
}

func TestPersistentNonceStoreWithFallback_MemoryHit(t *testing.T) {
	dao := newMockNonceDAO()
	store := &PersistentNonceStoreWithFallback{
		persistent: &PersistentNonceStore{dao: dao, ttl: time.Hour},
		memory:     NewNonceStore(time.Hour),
	}

	nonce := "fallback-test-nonce"

	// Add to both
	store.Add(nonce)

	// Should find in memory (fast path)
	assert.True(t, store.Exists(nonce))

	// Should be consumed
	assert.False(t, store.Exists(nonce))
}

func TestPersistentNonceStoreWithFallback_PersistentHit(t *testing.T) {
	dao := newMockNonceDAO()
	memory := NewNonceStore(time.Hour)

	store := &PersistentNonceStoreWithFallback{
		persistent: &PersistentNonceStore{dao: dao, ttl: time.Hour},
		memory:     memory,
	}

	nonce := "persistent-only-nonce"

	// Add only to persistent (simulating another server added it)
	store.persistent.Add(nonce)

	// Memory doesn't have it, but persistent does
	assert.True(t, store.Exists(nonce))

	// Should be consumed from persistent
	assert.False(t, store.Exists(nonce))
}

func TestNonceStoreInterface_InMemory(t *testing.T) {
	var store NonceStoreInterface = NewNonceStore(time.Hour)

	nonce := "interface-test"
	store.Add(nonce)
	assert.True(t, store.Exists(nonce))
	assert.False(t, store.Exists(nonce))
}

func TestNonceStoreInterface_Persistent(t *testing.T) {
	dao := newMockNonceDAO()
	var store NonceStoreInterface = &PersistentNonceStore{
		dao: dao,
		ttl: time.Hour,
	}

	nonce := "interface-test-persistent"
	store.Add(nonce)
	assert.True(t, store.Exists(nonce))
	assert.False(t, store.Exists(nonce))
}

func TestPersistentNonceStore_NonExistentNonce(t *testing.T) {
	dao := newMockNonceDAO()
	store := &PersistentNonceStore{
		dao: dao,
		ttl: time.Hour,
	}

	// Non-existent nonce should return false
	assert.False(t, store.Exists("non-existent-nonce"))
}

func TestPersistentNonceStore_MultipleNonces(t *testing.T) {
	dao := newMockNonceDAO()
	store := &PersistentNonceStore{
		dao: dao,
		ttl: time.Hour,
	}

	nonces := []string{"nonce1", "nonce2", "nonce3", "nonce4", "nonce5"}

	// Add all nonces
	for _, n := range nonces {
		store.Add(n)
	}

	// All should exist
	for _, n := range nonces {
		assert.True(t, store.Exists(n), "nonce %s should exist", n)
	}

	// All should be consumed
	for _, n := range nonces {
		assert.False(t, store.Exists(n), "nonce %s should be consumed", n)
	}
}

func TestNewPersistentNonceStore(t *testing.T) {
	dao := newMockNonceDAO()
	store := NewPersistentNonceStore(dao, time.Hour)

	require.NotNil(t, store)
	assert.Equal(t, time.Hour, store.ttl)
	assert.NotNil(t, store.dao)
}

func TestNewPersistentNonceStoreWithFallback(t *testing.T) {
	dao := newMockNonceDAO()
	store := NewPersistentNonceStoreWithFallback(dao, time.Hour)

	require.NotNil(t, store)
	assert.NotNil(t, store.persistent)
	assert.NotNil(t, store.memory)
}

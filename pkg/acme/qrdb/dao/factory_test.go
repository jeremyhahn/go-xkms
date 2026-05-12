//go:build codec_json

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

package dao

import (
	"context"
	"sort"
	"sync"
	"testing"

	dberrors "github.com/jeremyhahn/go-qrdb/pkg/errors"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memoryKVStore is an in-memory implementation of kvstore.KVStore for testing.
type memoryKVStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newTestMemoryKVStore() kvstore.KVStore {
	return &memoryKVStore{
		data: make(map[string][]byte),
	}
}

func (m *memoryKVStore) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	m.data[key] = valueCopy
	return nil
}

func (m *memoryKVStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.data[key]
	if !ok {
		return nil, &dberrors.QRDBError{Code: dberrors.ErrNotFound, Op: "kv.get"}
	}
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	return valueCopy, nil
}

func (m *memoryKVStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

func (m *memoryKVStore) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	m.mu.RLock()
	var keys []string
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	values := make(map[string][]byte, len(keys))
	for _, k := range keys {
		v := m.data[k]
		vc := make([]byte, len(v))
		copy(vc, v)
		values[k] = vc
	}
	m.mu.RUnlock()
	sort.Strings(keys)
	for _, k := range keys {
		if err := fn(k, values[k]); err != nil {
			return err
		}
	}
	return nil
}

func (m *memoryKVStore) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.data {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *memoryKVStore) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[key]
	return ok, nil
}

func (m *memoryKVStore) RegisterEntityIndexes(_ string, _ []kvstore.EntityIndex) error {
	return nil
}

func (m *memoryKVStore) QueryIndex(_ context.Context, _ string, _ []byte) ([][]byte, error) {
	return nil, nil
}

func (m *memoryKVStore) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

func (m *memoryKVStore) QueryCompoundIndex(_ context.Context, _ string, _ [][]byte) ([][]byte, error) {
	return nil, nil
}

func (m *memoryKVStore) ScanCompoundIndex(_ context.Context, _ string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

var _ kvstore.KVStore = (*memoryKVStore)(nil)

func newTestFactory(t *testing.T) *Factory {
	t.Helper()
	kvStore := newTestMemoryKVStore()
	return NewFactory(kvStore)
}

func testContext() context.Context {
	return context.Background()
}

func newTestTenant(id string) *entities.Tenant {
	return &entities.Tenant{
		ID:     id,
		Name:   "Test Tenant " + id,
		Status: "active",
	}
}

func newTestEAB(kid string) *entities.ExternalAccountBinding {
	return &entities.ExternalAccountBinding{
		ID:     kid,
		Status: "valid",
	}
}

func TestFactory_ImplementsInterfaces(t *testing.T) {
	f := newTestFactory(t)
	var _ storage.Factory = f
	var _ storage.TenantAwareFactory = f
}

func TestFactory_AccountDAO(t *testing.T) {
	f := newTestFactory(t)

	dao, err := f.AccountDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_OrderDAO(t *testing.T) {
	f := newTestFactory(t)

	dao, err := f.OrderDAO(1)
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_AuthorizationDAO(t *testing.T) {
	f := newTestFactory(t)

	dao, err := f.AuthorizationDAO(1)
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_ChallengeDAO(t *testing.T) {
	f := newTestFactory(t)

	dao, err := f.ChallengeDAO(1)
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_CertificateDAO(t *testing.T) {
	f := newTestFactory(t)

	dao, err := f.CertificateDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_NonceDAO(t *testing.T) {
	f := newTestFactory(t)

	dao, err := f.NonceDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_ExternalAccountBindingDAO(t *testing.T) {
	f := newTestFactory(t)

	dao, err := f.ExternalAccountBindingDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_TenantDAO(t *testing.T) {
	f := newTestFactory(t)

	dao, err := f.TenantDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_ForTenant(t *testing.T) {
	f := newTestFactory(t)

	scoped, err := f.ForTenant("tenant-1")
	require.NoError(t, err)
	assert.NotNil(t, scoped)
}

func TestFactory_ForTenant_EmptyID(t *testing.T) {
	f := newTestFactory(t)

	_, err := f.ForTenant("")
	require.Error(t, err)
	assert.IsType(t, InvalidIDError{}, err)
}

func TestFactory_GetTenantID_NoTenant(t *testing.T) {
	f := newTestFactory(t)

	assert.Equal(t, "", f.GetTenantID())
}

func TestFactory_GetTenantID_WithTenant(t *testing.T) {
	kvStore := newTestMemoryKVStore()
	f := NewFactoryWithTenant(kvStore, "tenant-1")

	assert.Equal(t, "tenant-1", f.GetTenantID())
}

func TestFactory_ForTenant_ScopedAccountDAO(t *testing.T) {
	f := newTestFactory(t)

	scoped, err := f.ForTenant("tenant-1")
	require.NoError(t, err)

	dao, err := scoped.AccountDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)
}

func TestFactory_TenantScoping_DataIsolation(t *testing.T) {
	kvStore := newTestMemoryKVStore()
	f := NewFactory(kvStore)
	ctx := testContext()

	// Save a tenant to the global scope
	tenantDAO, err := f.TenantDAO()
	require.NoError(t, err)
	require.NoError(t, tenantDAO.Save(ctx, newTestTenant("tenant-1")))

	// Create EAB in global scope
	globalEABDAO, err := f.ExternalAccountBindingDAO()
	require.NoError(t, err)
	require.NoError(t, globalEABDAO.Save(ctx, newTestEAB("global-kid")))

	// Create EAB in tenant scope
	scopedFactory, err := f.ForTenant("tenant-1")
	require.NoError(t, err)
	tenantEABDAO, err := scopedFactory.ExternalAccountBindingDAO()
	require.NoError(t, err)
	require.NoError(t, tenantEABDAO.Save(ctx, newTestEAB("tenant-kid")))

	// Global scope should only see global EAB
	globalCount, err := globalEABDAO.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, globalCount)

	// Tenant scope should only see tenant EAB
	tenantCount, err := tenantEABDAO.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, tenantCount)
}

func TestFactory_Prefix_NoTenant(t *testing.T) {
	f := newTestFactory(t)
	assert.Equal(t, "", f.prefix())
}

func TestFactory_Prefix_WithTenant(t *testing.T) {
	kvStore := newTestMemoryKVStore()
	f := NewFactoryWithTenant(kvStore, "my-tenant")
	assert.Equal(t, "tenants/my-tenant/", f.prefix())
}

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

package objstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-objstore/pkg/common"
	"github.com/stretchr/testify/require"
)

// setupTestStore creates a temporary directory for use as a local objstore backend.
func setupTestStore(t *testing.T) (string, func()) { //nolint:unused // used by factory_test.go under //go:build codec_json
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "acme-test-*")
	require.NoError(t, err)

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	return tmpDir, cleanup
}

// mockStorage is a simple in-memory storage for testing.
type mockStorage struct {
	mu       sync.RWMutex
	data     map[string][]byte
	metadata map[string]*common.Metadata
	policies []common.LifecyclePolicy
	putErr   error
	getErr   error
	delErr   error
	listErr  error
	existErr error
}

// newMockStorage creates a new mock storage instance.
func newMockStorage() *mockStorage {
	return &mockStorage{
		data:     make(map[string][]byte),
		metadata: make(map[string]*common.Metadata),
		policies: make([]common.LifecyclePolicy, 0),
	}
}

// Configure configures the mock storage.
func (m *mockStorage) Configure(config map[string]string) error {
	return nil
}

// AddPolicy adds a lifecycle policy.
func (m *mockStorage) AddPolicy(policy common.LifecyclePolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies = append(m.policies, policy)
	return nil
}

// RemovePolicy removes a lifecycle policy.
func (m *mockStorage) RemovePolicy(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, p := range m.policies {
		if p.ID == id {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return errors.New("policy not found")
}

// GetPolicies returns all lifecycle policies.
func (m *mockStorage) GetPolicies() ([]common.LifecyclePolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policies, nil
}

// Put stores data at the given key.
func (m *mockStorage) Put(key string, reader io.Reader) error {
	return m.PutWithContext(context.Background(), key, reader)
}

// PutWithContext stores data at the given key with context.
func (m *mockStorage) PutWithContext(ctx context.Context, key string, reader io.Reader) error {
	if m.putErr != nil {
		return m.putErr
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = data
	return nil
}

// PutWithMetadata stores data with metadata.
func (m *mockStorage) PutWithMetadata(ctx context.Context, key string, reader io.Reader, metadata *common.Metadata) error {
	if err := m.PutWithContext(ctx, key, reader); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.metadata[key] = metadata
	return nil
}

// Get retrieves data from the given key.
func (m *mockStorage) Get(key string) (io.ReadCloser, error) {
	return m.GetWithContext(context.Background(), key)
}

// GetWithContext retrieves data from the given key with context.
func (m *mockStorage) GetWithContext(ctx context.Context, key string) (io.ReadCloser, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	data, exists := m.data[key]
	if !exists {
		return nil, common.ErrKeyNotFound
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

// GetMetadata retrieves only the metadata for an object.
func (m *mockStorage) GetMetadata(ctx context.Context, key string) (*common.Metadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.data[key]; !exists {
		return nil, common.ErrKeyNotFound
	}

	return m.metadata[key], nil
}

// UpdateMetadata updates the metadata for an existing object.
func (m *mockStorage) UpdateMetadata(ctx context.Context, key string, metadata *common.Metadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.data[key]; !exists {
		return common.ErrKeyNotFound
	}

	m.metadata[key] = metadata
	return nil
}

// GetWithMetadata retrieves data and metadata.
func (m *mockStorage) GetWithMetadata(ctx context.Context, key string) (io.ReadCloser, *common.Metadata, error) {
	reader, err := m.GetWithContext(ctx, key)
	if err != nil {
		return nil, nil, err
	}

	m.mu.RLock()
	metadata := m.metadata[key]
	m.mu.RUnlock()

	return reader, metadata, nil
}

// Delete removes data at the given key.
func (m *mockStorage) Delete(key string) error {
	return m.DeleteWithContext(context.Background(), key)
}

// DeleteWithContext removes data at the given key with context.
func (m *mockStorage) DeleteWithContext(ctx context.Context, key string) error {
	if m.delErr != nil {
		return m.delErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.data[key]; !exists {
		return os.ErrNotExist
	}

	delete(m.data, key)
	delete(m.metadata, key)
	return nil
}

// List returns all keys with the given prefix.
func (m *mockStorage) List(prefix string) ([]string, error) {
	return m.ListWithContext(context.Background(), prefix)
}

// ListWithContext returns all keys with the given prefix with context.
func (m *mockStorage) ListWithContext(ctx context.Context, prefix string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0)
	for key := range m.data {
		if len(prefix) == 0 || hasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// ListWithOptions returns a paginated list of objects with full metadata.
func (m *mockStorage) ListWithOptions(ctx context.Context, opts *common.ListOptions) (*common.ListResult, error) {
	keys, err := m.ListWithContext(ctx, opts.Prefix)
	if err != nil {
		return nil, err
	}

	objects := make([]*common.ObjectInfo, 0)
	for _, key := range keys {
		objects = append(objects, &common.ObjectInfo{
			Key: key,
		})
	}

	result := &common.ListResult{
		Objects:   objects,
		Truncated: false,
	}
	return result, nil
}

// Archive copies an object to another backend for archival.
func (m *mockStorage) Archive(key string, destination common.Archiver) error {
	return nil
}

// Exists checks if a key exists.
func (m *mockStorage) Exists(ctx context.Context, key string) (bool, error) {
	if m.existErr != nil {
		return false, m.existErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.data[key]
	return exists, nil
}

// SetPutError sets an error to be returned by Put operations.
func (m *mockStorage) SetPutError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.putErr = err
}

// SetGetError sets an error to be returned by Get operations.
func (m *mockStorage) SetGetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getErr = err
}

// SetDeleteError sets an error to be returned by Delete operations.
func (m *mockStorage) SetDeleteError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delErr = err
}

// SetListError sets an error to be returned by List operations.
func (m *mockStorage) SetListError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listErr = err
}

// SetExistsError sets an error to be returned by Exists operations.
func (m *mockStorage) SetExistsError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.existErr = err
}

// hasPrefix checks if a string has a given prefix (simple implementation).
func hasPrefix(s, prefix string) bool {
	if len(prefix) > len(s) {
		return false
	}
	return s[:len(prefix)] == prefix
}

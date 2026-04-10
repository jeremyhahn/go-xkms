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

package qrdb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock KVClient
// ---------------------------------------------------------------------------

// mockKVClient is an in-memory KVClient for unit testing.
type mockKVClient struct {
	store map[string][]byte

	// Error injection: when set, the corresponding method returns this
	// error instead of performing the normal operation.
	putErr    error
	getErr    error
	deleteErr error
	listErr   error
	scanErr   error
	existsErr error
}

func newMockKVClient() *mockKVClient {
	return &mockKVClient{store: make(map[string][]byte)}
}

func (m *mockKVClient) Put(_ context.Context, key string, value []byte, _ ...transport.WriteOption) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.store[key] = append([]byte(nil), value...) // Copy to avoid mutations
	return nil
}

func (m *mockKVClient) Get(_ context.Context, key string, _ ...transport.ReadOption) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	val, exists := m.store[key]
	if !exists {
		return nil, &transport.KeyNotFoundError{Key: key}
	}
	return append([]byte(nil), val...), nil // Return copy
}

func (m *mockKVClient) Delete(_ context.Context, key string, _ ...transport.WriteOption) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, exists := m.store[key]; !exists {
		return &transport.KeyNotFoundError{Key: key}
	}
	delete(m.store, key)
	return nil
}

func (m *mockKVClient) List(_ context.Context, prefix string, _ ...transport.ReadOption) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	keys := make([]string, 0) // Initialize as empty slice instead of nil
	for k := range m.store {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (m *mockKVClient) Scan(_ context.Context, prefix string, _ ...transport.ReadOption) (map[string][]byte, error) {
	if m.scanErr != nil {
		return nil, m.scanErr
	}
	results := make(map[string][]byte)
	for k, v := range m.store {
		if strings.HasPrefix(k, prefix) {
			valueCopy := make([]byte, len(v))
			copy(valueCopy, v)
			results[k] = valueCopy
		}
	}
	return results, nil
}

func (m *mockKVClient) Exists(_ context.Context, key string, _ ...transport.ReadOption) (bool, error) {
	if m.existsErr != nil {
		return false, m.existsErr
	}
	_, exists := m.store[key]
	return exists, nil
}

// ---------------------------------------------------------------------------
// Backend Tests
// ---------------------------------------------------------------------------

func TestNewBackend(t *testing.T) {
	client := newMockKVClient()
	backend := NewBackend(client)
	require.NotNil(t, backend)
	require.NoError(t, backend.Close())
}

func TestBackend_Get_Success(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	key := "test-key"
	value := []byte("test-value")

	// Put the value first
	require.NoError(t, client.Put(ctx, key, value))

	// Get it back
	result, err := backend.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, value, result)
}

func TestBackend_Get_NotFound(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	_, err := backend.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestBackend_Get_ClientError(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	client.getErr = errors.New("client error")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	_, err := backend.Get(ctx, "key")
	require.Error(t, err)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "get", backendErr.Op)
}

func TestBackend_Put_Success(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	key := "test-key"
	value := []byte("test-value")

	err := backend.Put(ctx, key, value)
	require.NoError(t, err)

	// Verify it was stored
	stored, _ := client.Get(ctx, key)
	assert.Equal(t, value, stored)
}

func TestBackend_Put_ClientError(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	client.putErr = errors.New("client error")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	err := backend.Put(ctx, "key", []byte("value"))
	require.Error(t, err)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "put", backendErr.Op)
}

func TestBackend_Delete_Success(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	key := "test-key"
	// Put first
	require.NoError(t, client.Put(ctx, key, []byte("value")))

	// Delete
	err := backend.Delete(ctx, key)
	require.NoError(t, err)

	// Verify it's gone
	_, err = client.Get(ctx, key)
	var knf *transport.KeyNotFoundError
	require.True(t, errors.As(err, &knf))
}

func TestBackend_Delete_NotFound(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	// Delete nonexistent key should not error (idempotent)
	err := backend.Delete(ctx, "nonexistent")
	require.NoError(t, err)
}

func TestBackend_Delete_ClientError(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	client.deleteErr = errors.New("client error")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	err := backend.Delete(ctx, "key")
	require.Error(t, err)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "delete", backendErr.Op)
}

func TestBackend_List_Success(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	// Put some keys
	require.NoError(t, client.Put(ctx, "prefix/key1", []byte("value1")))
	require.NoError(t, client.Put(ctx, "prefix/key2", []byte("value2")))
	require.NoError(t, client.Put(ctx, "other/key", []byte("value3")))

	// List with prefix
	keys, err := backend.List(ctx, "prefix/")
	require.NoError(t, err)
	assert.Equal(t, []string{"prefix/key1", "prefix/key2"}, keys)
}

func TestBackend_List_Empty(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	keys, err := backend.List(ctx, "nonexistent/")
	require.NoError(t, err)
	assert.Equal(t, []string{}, keys)
}

func TestBackend_List_ClientError(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	client.listErr = errors.New("client error")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	_, err := backend.List(ctx, "prefix/")
	require.Error(t, err)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "list", backendErr.Op)
}

func TestBackend_Scan_Success(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	// Put some keys
	require.NoError(t, client.Put(ctx, "prefix/key1", []byte("value1")))
	require.NoError(t, client.Put(ctx, "prefix/key2", []byte("value2")))
	require.NoError(t, client.Put(ctx, "other/key", []byte("value3")))

	// Scan with prefix
	pairs := make(map[string][]byte)
	err := backend.Scan(ctx, "prefix/", func(key string, value []byte) error {
		pairs[key] = value
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, len(pairs))
	assert.Equal(t, []byte("value1"), pairs["prefix/key1"])
	assert.Equal(t, []byte("value2"), pairs["prefix/key2"])
}

func TestBackend_Scan_Empty(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	pairs := make(map[string][]byte)
	err := backend.Scan(ctx, "nonexistent/", func(key string, value []byte) error {
		pairs[key] = value
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 0, len(pairs))
}

func TestBackend_Scan_ClientError(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	client.scanErr = errors.New("client error")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	err := backend.Scan(ctx, "prefix/", func(_ string, _ []byte) error { return nil })
	require.Error(t, err)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "scan", backendErr.Op)
}

func TestBackend_Exists_Success(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	key := "test-key"
	// Put first
	require.NoError(t, client.Put(ctx, key, []byte("value")))

	// Check exists
	exists, err := backend.Exists(ctx, key)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestBackend_Exists_NotFound(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	exists, err := backend.Exists(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestBackend_Exists_ClientError(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	client.existsErr = errors.New("client error")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	_, err := backend.Exists(ctx, "key")
	require.Error(t, err)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "exists", backendErr.Op)
}

func TestBackend_Close_WithoutCloser(t *testing.T) {
	client := newMockKVClient()
	backend := NewBackend(client)

	// Should not error even though backend doesn't own the client
	err := backend.Close()
	require.NoError(t, err)
}

func TestBackend_Close_WithCloser(t *testing.T) {
	client := newMockKVClient()
	closerCalled := false
	closer := mockCloser{
		closeFn: func() error {
			closerCalled = true
			return nil
		},
	}
	backend := &Backend{client: client, closer: &closer}

	err := backend.Close()
	require.NoError(t, err)
	assert.True(t, closerCalled)
}

func TestBackend_Close_CloserError(t *testing.T) {
	client := newMockKVClient()
	closer := mockCloser{
		closeFn: func() error {
			return errors.New("close failed")
		},
	}
	backend := &Backend{client: client, closer: &closer}

	err := backend.Close()
	require.Error(t, err)
	assert.Equal(t, "close failed", err.Error())
}

// ---------------------------------------------------------------------------
// SetNotFoundError Tests
// ---------------------------------------------------------------------------

func TestSetNotFoundError_ChangesErrNotFound(t *testing.T) {
	// Save the original so we can restore it after the test.
	original := ErrNotFound
	defer func() { ErrNotFound = original }()

	sentinel := errors.New("custom: not found")
	SetNotFoundError(sentinel)

	assert.Equal(t, sentinel, ErrNotFound,
		"ErrNotFound should be updated to the injected sentinel")
}

func TestSetNotFoundError_GetReturnsNewSentinel(t *testing.T) {
	// Save the original so we can restore it after the test.
	original := ErrNotFound
	defer func() { ErrNotFound = original }()

	customErr := errors.New("injected not-found")
	SetNotFoundError(customErr)

	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	// A missing key must now surface as the injected sentinel.
	_, err := backend.Get(ctx, "missing-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, customErr,
		"Get on a missing key should return the injected ErrNotFound sentinel")
}

// ---------------------------------------------------------------------------
// BackendError Tests
// ---------------------------------------------------------------------------

func TestBackendError_Error_WithKey(t *testing.T) {
	cause := errors.New("disk full")
	e := &BackendError{Op: "put", Key: "ns/mykey", Err: cause}

	got := e.Error()

	assert.Equal(t, "qrdb: put key=ns/mykey: disk full", got)
}

func TestBackendError_Error_WithoutKey(t *testing.T) {
	cause := errors.New("timeout")
	e := &BackendError{Op: "list", Key: "", Err: cause}

	got := e.Error()

	// No "key=" segment when Key is empty.
	assert.Equal(t, "qrdb: list: timeout", got)
}

func TestBackendError_Unwrap_ReturnsUnderlyingError(t *testing.T) {
	cause := errors.New("underlying cause")
	e := &BackendError{Op: "get", Key: "k", Err: cause}

	assert.Equal(t, cause, e.Unwrap(),
		"Unwrap should return the exact underlying error")
}

func TestBackendError_Unwrap_ErrorsIs(t *testing.T) {
	sentinel := errors.New("sentinel")
	e := &BackendError{Op: "scan", Key: "prefix/", Err: fmt.Errorf("wrapped: %w", sentinel)}

	assert.ErrorIs(t, e, sentinel,
		"errors.Is should unwrap through BackendError to reach the sentinel")
}

// ---------------------------------------------------------------------------
// mockCloser is a simple io.Closer for testing
// ---------------------------------------------------------------------------

type mockCloser struct {
	closeFn func() error
}

func (m *mockCloser) Close() error {
	return m.closeFn()
}

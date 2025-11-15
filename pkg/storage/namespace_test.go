// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestKeyPath tests the KeyPath function.
func TestKeyPath(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		expect string
	}{
		{
			name:   "simple ID",
			id:     "key1",
			expect: "keys/key1.key",
		},
		{
			name:   "UUID-style ID",
			id:     "550e8400-e29b-41d4-a716-446655440000",
			expect: "keys/550e8400-e29b-41d4-a716-446655440000.key",
		},
		{
			name:   "alphanumeric ID",
			id:     "test_key_123",
			expect: "keys/test_key_123.key",
		},
		{
			name:   "empty ID",
			id:     "",
			expect: "keys/.key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := KeyPath(tt.id)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestCertPath tests the CertPath function.
func TestCertPath(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		expect string
	}{
		{
			name:   "simple ID",
			id:     "cert1",
			expect: "certs/cert1.pem",
		},
		{
			name:   "UUID-style ID",
			id:     "550e8400-e29b-41d4-a716-446655440000",
			expect: "certs/550e8400-e29b-41d4-a716-446655440000.pem",
		},
		{
			name:   "domain-like ID",
			id:     "example.com",
			expect: "certs/example.com.pem",
		},
		{
			name:   "empty ID",
			id:     "",
			expect: "certs/.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CertPath(tt.id)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// TestCertChainPath tests the CertChainPath function.
func TestCertChainPath(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		expect string
	}{
		{
			name:   "simple ID",
			id:     "chain1",
			expect: "certs/chain1-chain.pem",
		},
		{
			name:   "UUID-style ID",
			id:     "550e8400-e29b-41d4-a716-446655440000",
			expect: "certs/550e8400-e29b-41d4-a716-446655440000-chain.pem",
		},
		{
			name:   "domain-like ID",
			id:     "example.com",
			expect: "certs/example.com-chain.pem",
		},
		{
			name:   "empty ID",
			id:     "",
			expect: "certs/-chain.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CertChainPath(tt.id)
			assert.Equal(t, tt.expect, result)
		})
	}
}

// mockBackend provides a simple in-memory implementation for testing.
type mockBackend struct {
	data map[string][]byte
}

func newMockBackend() *mockBackend {
	return &mockBackend{
		data: make(map[string][]byte),
	}
}

func (m *mockBackend) Get(key string) ([]byte, error) {
	if val, ok := m.data[key]; ok {
		return val, nil
	}
	return nil, ErrNotFound
}

func (m *mockBackend) Put(key string, value []byte, opts *Options) error {
	m.data[key] = value
	return nil
}

func (m *mockBackend) Delete(key string) error {
	if _, exists := m.data[key]; !exists {
		return ErrNotFound
	}
	delete(m.data, key)
	return nil
}

func (m *mockBackend) List(prefix string) ([]string, error) {
	var keys []string
	for k := range m.data {
		if prefix == "" || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *mockBackend) Exists(key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func (m *mockBackend) Close() error {
	return nil
}

// TestListKeys tests the ListKeys function.
func TestListKeys(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() Backend
		expect    []string
	}{
		{
			name: "no keys",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			expect: []string{},
		},
		{
			name: "single key",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(KeyPath("key1"), []byte("data"), nil)
				return b
			},
			expect: []string{"key1"},
		},
		{
			name: "multiple keys",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(KeyPath("key1"), []byte("data1"), nil)
				b.Put(KeyPath("key2"), []byte("data2"), nil)
				b.Put(KeyPath("key3"), []byte("data3"), nil)
				return b
			},
			expect: []string{"key1", "key2", "key3"},
		},
		{
			name: "keys with special characters",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(KeyPath("550e8400-e29b-41d4-a716-446655440000"), []byte("data"), nil)
				b.Put(KeyPath("test_key_123"), []byte("data"), nil)
				return b
			},
			expect: []string{"550e8400-e29b-41d4-a716-446655440000", "test_key_123"},
		},
		{
			name: "ignores non-key entries",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(KeyPath("key1"), []byte("data"), nil)
				b.Put("other/entry", []byte("data"), nil)
				b.Put(CertPath("cert1"), []byte("data"), nil)
				return b
			},
			expect: []string{"key1"},
		},
		{
			name: "ignores malformed keys",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(KeyPath("key1"), []byte("data"), nil)
				b.Put("keys/", []byte("data"), nil)     // Missing suffix
				b.Put("keys/.key", []byte("data"), nil) // Empty ID
				return b
			},
			expect: []string{"key1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			result, err := ListKeys(backend)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expect, result)
		})
	}
}

// TestListCerts tests the ListCerts function.
func TestListCerts(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() Backend
		expect    []string
	}{
		{
			name: "no certs",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			expect: []string{},
		},
		{
			name: "single cert",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertPath("cert1"), []byte("data"), nil)
				return b
			},
			expect: []string{"cert1"},
		},
		{
			name: "multiple certs",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertPath("cert1"), []byte("data1"), nil)
				b.Put(CertPath("cert2"), []byte("data2"), nil)
				b.Put(CertPath("cert3"), []byte("data3"), nil)
				return b
			},
			expect: []string{"cert1", "cert2", "cert3"},
		},
		{
			name: "ignores cert chains",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertPath("cert1"), []byte("data"), nil)
				b.Put(CertChainPath("chain1"), []byte("data"), nil)
				return b
			},
			expect: []string{"cert1"},
		},
		{
			name: "ignores non-cert entries",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertPath("cert1"), []byte("data"), nil)
				b.Put(KeyPath("key1"), []byte("data"), nil)
				b.Put("other/entry", []byte("data"), nil)
				return b
			},
			expect: []string{"cert1"},
		},
		{
			name: "handles certs with special characters",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertPath("example.com"), []byte("data"), nil)
				b.Put(CertPath("550e8400-e29b-41d4-a716-446655440000"), []byte("data"), nil)
				return b
			},
			expect: []string{"example.com", "550e8400-e29b-41d4-a716-446655440000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			result, err := ListCerts(backend)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expect, result)
		})
	}
}

// TestListCertChains tests the ListCertChains function.
func TestListCertChains(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() Backend
		expect    []string
	}{
		{
			name: "no chains",
			setupFunc: func() Backend {
				return newMockBackend()
			},
			expect: []string{},
		},
		{
			name: "single chain",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertChainPath("chain1"), []byte("data"), nil)
				return b
			},
			expect: []string{"chain1"},
		},
		{
			name: "multiple chains",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertChainPath("chain1"), []byte("data1"), nil)
				b.Put(CertChainPath("chain2"), []byte("data2"), nil)
				b.Put(CertChainPath("chain3"), []byte("data3"), nil)
				return b
			},
			expect: []string{"chain1", "chain2", "chain3"},
		},
		{
			name: "ignores individual certs",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertPath("cert1"), []byte("data"), nil)
				b.Put(CertChainPath("chain1"), []byte("data"), nil)
				return b
			},
			expect: []string{"chain1"},
		},
		{
			name: "ignores non-cert entries",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertChainPath("chain1"), []byte("data"), nil)
				b.Put(KeyPath("key1"), []byte("data"), nil)
				b.Put("other/entry", []byte("data"), nil)
				return b
			},
			expect: []string{"chain1"},
		},
		{
			name: "handles chains with special characters",
			setupFunc: func() Backend {
				b := newMockBackend()
				b.Put(CertChainPath("example.com"), []byte("data"), nil)
				b.Put(CertChainPath("550e8400-e29b-41d4-a716-446655440000"), []byte("data"), nil)
				return b
			},
			expect: []string{"example.com", "550e8400-e29b-41d4-a716-446655440000"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.setupFunc()
			result, err := ListCertChains(backend)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expect, result)
		})
	}
}

// TestListKeys_Error tests error handling in ListKeys.
func TestListKeys_Error(t *testing.T) {
	tests := []struct {
		name        string
		backendFunc func() Backend
	}{
		{
			name: "backend returns error",
			backendFunc: func() Backend {
				return &errorMockBackend{
					listErr: ErrClosed,
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.backendFunc()
			_, err := ListKeys(backend)
			assert.Error(t, err)
		})
	}
}

// TestListCerts_Error tests error handling in ListCerts.
func TestListCerts_Error(t *testing.T) {
	tests := []struct {
		name        string
		backendFunc func() Backend
	}{
		{
			name: "backend returns error",
			backendFunc: func() Backend {
				return &errorMockBackend{
					listErr: ErrClosed,
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.backendFunc()
			_, err := ListCerts(backend)
			assert.Error(t, err)
		})
	}
}

// TestListCertChains_Error tests error handling in ListCertChains.
func TestListCertChains_Error(t *testing.T) {
	tests := []struct {
		name        string
		backendFunc func() Backend
	}{
		{
			name: "backend returns error",
			backendFunc: func() Backend {
				return &errorMockBackend{
					listErr: ErrClosed,
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := tt.backendFunc()
			_, err := ListCertChains(backend)
			assert.Error(t, err)
		})
	}
}

// errorMockBackend returns errors on operations.
type errorMockBackend struct {
	getErr    error
	putErr    error
	deleteErr error
	listErr   error
	existsErr error
}

func (e *errorMockBackend) Get(key string) ([]byte, error) {
	if e.getErr != nil {
		return nil, e.getErr
	}
	return nil, ErrNotFound
}

func (e *errorMockBackend) Put(key string, value []byte, opts *Options) error {
	if e.putErr != nil {
		return e.putErr
	}
	return nil
}

func (e *errorMockBackend) Delete(key string) error {
	if e.deleteErr != nil {
		return e.deleteErr
	}
	return ErrNotFound
}

func (e *errorMockBackend) List(prefix string) ([]string, error) {
	if e.listErr != nil {
		return nil, e.listErr
	}
	return nil, nil
}

func (e *errorMockBackend) Exists(key string) (bool, error) {
	if e.existsErr != nil {
		return false, e.existsErr
	}
	return false, nil
}

func (e *errorMockBackend) Close() error {
	return nil
}

// TestPathConsistency tests that paths created with builder functions can be parsed correctly.
func TestPathConsistency(t *testing.T) {
	// Keys
	keyID := "test-key-123"
	keyPath := KeyPath(keyID)
	assert.True(t, len(keyPath) > 0)
	assert.Contains(t, keyPath, keyID)
	assert.True(t, keyPath == "keys/test-key-123.key")

	// Certs
	certID := "test-cert-456"
	certPath := CertPath(certID)
	assert.True(t, len(certPath) > 0)
	assert.Contains(t, certPath, certID)
	assert.True(t, certPath == "certs/test-cert-456.pem")

	// Cert chains
	chainID := "test-chain-789"
	chainPath := CertChainPath(chainID)
	assert.True(t, len(chainPath) > 0)
	assert.Contains(t, chainPath, chainID)
	assert.True(t, chainPath == "certs/test-chain-789-chain.pem")
}

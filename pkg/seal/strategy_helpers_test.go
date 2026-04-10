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

package seal

import (
	"context"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// testLogger returns a slog.Logger for use in tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// mockSymmetricEncrypter implements types.SymmetricEncrypter for testing.
// It is a no-op encryptor used to verify that hardware strategies pass
// through to the hardwareEncryptorWrapper when a hardware encryptor is
// provided.
type mockSymmetricEncrypter struct{}

func (m *mockSymmetricEncrypter) Encrypt(plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, error) {
	return &types.EncryptedData{
		Ciphertext: plaintext,
		Nonce:      []byte("mock-nonce-12"),
		Tag:        []byte("mock-tag-16bytes"),
		Algorithm:  "mock",
	}, nil
}

func (m *mockSymmetricEncrypter) Decrypt(data *types.EncryptedData, opts *types.DecryptOptions) ([]byte, error) {
	return data.Ciphertext, nil
}

// Compile-time check.
var _ types.SymmetricEncrypter = (*mockSymmetricEncrypter)(nil)

// failingStorage is a storage.Backend with configurable errors per method.
// It supports an optional underlying delegate for operations that should
// succeed up to a configurable point. Used to test error paths in strategies
// that depend on storage.
type failingStorage struct {
	listErr   error
	listKeys  []string
	getErr    error
	getData   map[string][]byte
	putErr    error
	putCount  int // incremented on each Put call
	putFailAt int // fail at this Put call count (0 = always fail if putErr set)
	deleteErr error
}

func (f *failingStorage) Get(_ context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if v, ok := f.getData[key]; ok {
		return v, nil
	}
	return nil, storage.ErrNotFound
}

func (f *failingStorage) Put(_ context.Context, key string, value []byte) error {
	f.putCount++
	if f.putErr != nil {
		if f.putFailAt == 0 || f.putCount >= f.putFailAt {
			return f.putErr
		}
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	f.getData[key] = buf
	return nil
}

func (f *failingStorage) Delete(_ context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return nil
}

func (f *failingStorage) List(_ context.Context, prefix string) ([]string, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listKeys, nil
}

func (f *failingStorage) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	if f.getErr != nil {
		return f.getErr
	}
	for k, v := range f.getData {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			if err := fn(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *failingStorage) Exists(_ context.Context, key string) (bool, error) {
	_, ok := f.getData[key]
	return ok, nil
}

func (f *failingStorage) Close() error {
	return nil
}

// Compile-time check.
var _ storage.Backend = (*failingStorage)(nil)

// errBackend is a storage.Backend that returns configurable errors on each
// method. Used to test error propagation in PlatformStore tests.
type errBackend struct {
	putErr    error
	getErr    error
	getVal    []byte
	deleteErr error
	existsErr error
	listErr   error
}

func (e *errBackend) Get(_ context.Context, key string) ([]byte, error) {
	if e.getErr != nil {
		return nil, e.getErr
	}
	if e.getVal != nil {
		return e.getVal, nil
	}
	return nil, storage.ErrNotFound
}

func (e *errBackend) Put(_ context.Context, key string, value []byte) error {
	if e.putErr != nil {
		return e.putErr
	}
	return nil
}

func (e *errBackend) Delete(_ context.Context, key string) error {
	if e.deleteErr != nil {
		return e.deleteErr
	}
	return nil
}

func (e *errBackend) List(_ context.Context, prefix string) ([]string, error) {
	if e.listErr != nil {
		return nil, e.listErr
	}
	return nil, nil
}

func (e *errBackend) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	if e.listErr != nil {
		return e.listErr
	}
	return nil
}

func (e *errBackend) Exists(_ context.Context, key string) (bool, error) {
	if e.existsErr != nil {
		return false, e.existsErr
	}
	return false, nil
}

func (e *errBackend) Close() error { return nil }

// Compile-time check.
var _ storage.Backend = (*errBackend)(nil)

// memoryBackend is a simple in-memory storage.Backend for tests.
type memoryBackend struct {
	data map[string][]byte
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{data: make(map[string][]byte)}
}

func (m *memoryBackend) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := m.data[key]
	if !ok {
		return nil, storage.ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (m *memoryBackend) Put(_ context.Context, key string, value []byte) error {
	buf := make([]byte, len(value))
	copy(buf, value)
	m.data[key] = buf
	return nil
}

func (m *memoryBackend) Delete(_ context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *memoryBackend) List(_ context.Context, prefix string) ([]string, error) {
	var keys []string
	for k := range m.data {
		if len(prefix) == 0 || len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *memoryBackend) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	for k, v := range m.data {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == prefix) {
			if err := fn(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *memoryBackend) Exists(_ context.Context, key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func (m *memoryBackend) Close() error { return nil }

// Compile-time check.
var _ storage.Backend = (*memoryBackend)(nil)

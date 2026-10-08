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

package pinadapter

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorBackend is a configurable mock backend for testing error paths.
type errorBackend struct {
	getErr    error
	putErr    error
	deleteErr error
}

func (e *errorBackend) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, e.getErr
}
func (e *errorBackend) Put(_ context.Context, _ string, _ []byte) error {
	return e.putErr
}
func (e *errorBackend) Delete(_ context.Context, _ string) error { return e.deleteErr }
func (e *errorBackend) List(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (e *errorBackend) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return nil
}
func (e *errorBackend) Exists(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (e *errorBackend) Close() error { return nil }

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNew_NilBackend(t *testing.T) {
	adapter, err := New(nil)
	assert.Nil(t, adapter)
	require.Error(t, err)
	var nilErr NilBackendError
	assert.ErrorAs(t, err, &nilErr)
	assert.Equal(t, "pinadapter: backend cannot be nil", err.Error())
}

func TestNew_ValidBackend(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	require.NotNil(t, adapter)
}

// =============================================================================
// Get Tests
// =============================================================================

func TestGet_NotFoundTranslatedToPinErrNotFound(t *testing.T) {
	// The whole reason this adapter exists: storage.ErrNotFound must be
	// translated to qrdbsdk.ErrPINStorageNotFound so SoftwareBackend treats a missing
	// record as "fresh install" rather than failing initialization.
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)

	_, err = adapter.Get(context.Background(), "missing-key")
	require.Error(t, err)
	assert.ErrorIs(t, err, qrdbsdk.ErrPINStorageNotFound)
	assert.NotErrorIs(t, err, storage.ErrNotFound)
}

func TestGet_ExistingKey(t *testing.T) {
	backend := storage.NewMemory()
	require.NoError(t, backend.Put(context.Background(), "k", []byte("v")))
	adapter, err := New(backend)
	require.NoError(t, err)

	value, err := adapter.Get(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), value)
}

func TestGet_BackendErrorWrappedInGetError(t *testing.T) {
	sentinel := errors.New("disk gone")
	adapter, err := New(&errorBackend{getErr: sentinel})
	require.NoError(t, err)

	_, err = adapter.Get(context.Background(), "any")
	require.Error(t, err)
	var getErr *GetError
	require.ErrorAs(t, err, &getErr)
	assert.Equal(t, "any", getErr.Key)
	assert.ErrorIs(t, err, sentinel)
	assert.NotErrorIs(t, err, qrdbsdk.ErrPINStorageNotFound)
}

// =============================================================================
// Put Tests
// =============================================================================

func TestPut_Success(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)

	require.NoError(t, adapter.Put(context.Background(), "k", []byte("v")))
	value, err := backend.Get(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), value)
}

func TestPut_BackendErrorWrappedInPutError(t *testing.T) {
	sentinel := errors.New("read-only fs")
	adapter, err := New(&errorBackend{putErr: sentinel})
	require.NoError(t, err)

	err = adapter.Put(context.Background(), "k", []byte("v"))
	require.Error(t, err)
	var putErr *PutError
	require.ErrorAs(t, err, &putErr)
	assert.Equal(t, "k", putErr.Key)
	assert.ErrorIs(t, err, sentinel)
}

func TestDelete_RemovesRecord(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)
	require.NoError(t, adapter.Put(context.Background(), "k", []byte("v")))

	require.NoError(t, adapter.Delete(context.Background(), "k"))

	_, err = adapter.Get(context.Background(), "k")
	assert.ErrorIs(t, err, qrdbsdk.ErrPINStorageNotFound)
}

func TestDelete_AbsentKeyIsNotAnError(t *testing.T) {
	adapter, err := New(storage.NewMemory())
	require.NoError(t, err)

	assert.NoError(t, adapter.Delete(context.Background(), "missing"))
}

func TestDelete_BackendErrorWrappedInDeleteError(t *testing.T) {
	sentinel := errors.New("read-only fs")
	adapter, err := New(&errorBackend{deleteErr: sentinel})
	require.NoError(t, err)

	err = adapter.Delete(context.Background(), "k")
	var deleteErr *DeleteError
	require.ErrorAs(t, err, &deleteErr)
	assert.Equal(t, "k", deleteErr.Key)
	assert.ErrorIs(t, err, sentinel)
}

// =============================================================================
// End-to-end with SoftwareBackend
// =============================================================================

// TestAdapter_WithSoftwareBackend_FreshInstall verifies the actual
// integration: qrdbsdk.NewSoftwareBackend with our adapter on an empty store
// must succeed (this is the exact scenario the failing server tests
// exercised — fresh PIN directory, no records yet).
func TestAdapter_WithSoftwareBackend_FreshInstall(t *testing.T) {
	backend := storage.NewMemory()
	adapter, err := New(backend)
	require.NoError(t, err)

	swBackend, err := qrdbsdk.NewSoftwareBackend(adapter, qrdbsdk.DefaultHashConfig())
	require.NoError(t, err)
	require.NotNil(t, swBackend)
}

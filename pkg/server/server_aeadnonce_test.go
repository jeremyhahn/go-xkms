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

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
)

// ============================================================================
// Tests — initializeAEADNonceStore / detachAEADNonceStore
// ============================================================================

// TestInitializeAEADNonceStore_Success proves the happy path: the store is
// built and attached to the process-wide guard, so a claim the guard's
// in-memory tracker has forgotten is still refused through it. detach is
// deferred unconditionally so this test cannot leave the shared guard
// pointed at a backend a later test in this binary never built.
func TestInitializeAEADNonceStore_Success(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
	})

	require.NoError(t, s.initializeAEADNonceStore())
	t.Cleanup(s.detachAEADNonceStore)
	assert.True(t, s.aeadNonceStoreAttached)

	guard, err := aead.SharedAEADNonceGuard()
	require.NoError(t, err)

	key := []byte("aeadnonce-init-success-key")
	nonce := []byte("aeadnonce-init-nonce")
	require.NoError(t, guard.UseContext(context.Background(), key, nonce),
		"the first claim on a fresh pair must be accepted")

	// Forget the in-memory record (what a restart does) without touching the
	// store this test just attached; the persisted claim must still refuse.
	guard.Reset()
	err = guard.UseContext(context.Background(), key, nonce)
	require.Error(t, err, "the attached store must still refuse the pair after the tracker forgets it")
	assert.True(t, errors.Is(err, aead.ErrNonceReuse), "got %v", err)
}

// TestInitializeAEADNonceStore_StorageCreateFails proves that a storage
// backend createStorage cannot build (an unsupported storage.backend) fails
// with a typed *ErrStorageCreate and attaches nothing to the shared guard.
func TestInitializeAEADNonceStore_StorageCreateFails(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "not-a-real-backend"},
	})

	err := s.initializeAEADNonceStore()
	require.Error(t, err)
	assert.False(t, s.aeadNonceStoreAttached)

	var storageErr *ErrStorageCreate
	require.ErrorAs(t, err, &storageErr)
}

// TestDetachAEADNonceStore_RemovesTheAttachedStore proves detach really
// detaches: after it runs, a pair the store held is reachable again, because
// nothing is left consulting it.
func TestDetachAEADNonceStore_RemovesTheAttachedStore(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
	})
	require.NoError(t, s.initializeAEADNonceStore())

	guard, err := aead.SharedAEADNonceGuard()
	require.NoError(t, err)

	key := []byte("aeadnonce-detach-key")
	nonce := []byte("aeadnonce-detach-nonce")
	require.NoError(t, guard.UseContext(context.Background(), key, nonce))

	s.detachAEADNonceStore()
	assert.False(t, s.aeadNonceStoreAttached)

	// The in-memory tracker still holds the pair from the claim above, so it
	// alone would still refuse; clear it to isolate what detach changed.
	guard.Reset()
	require.NoError(t, guard.UseContext(context.Background(), key, nonce),
		"once detached, a pair the removed store held must no longer be consulted")
}

// TestDetachAEADNonceStore_IsIdempotent proves a second detach (the shape
// shutdown()'s any-error-path callers produce) is a no-op rather than a
// panic or a redundant guard mutation.
func TestDetachAEADNonceStore_IsIdempotent(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
	})
	require.NoError(t, s.initializeAEADNonceStore())

	s.detachAEADNonceStore()
	assert.False(t, s.aeadNonceStoreAttached)
	assert.NotPanics(t, s.detachAEADNonceStore)
	assert.False(t, s.aeadNonceStoreAttached)
}

// TestDetachAEADNonceStore_NoopWhenNeverAttached proves a server that never
// successfully attached a store (initializeAEADNonceStore was never called,
// or it failed) can still call detach safely -- shutdown() calls it
// unconditionally on every path.
func TestDetachAEADNonceStore_NoopWhenNeverAttached(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{Backend: "memory"},
	})
	assert.NotPanics(t, s.detachAEADNonceStore)
	assert.False(t, s.aeadNonceStoreAttached)
}

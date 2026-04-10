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

package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

// testLogger returns a no-op logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewAgent_NilConfig(t *testing.T) {
	_, err := NewAgent(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentConnectionFailed)
}

func TestNewAgent_StandaloneMode(t *testing.T) {
	// Create a memory backend for testing
	memBackend := storage.NewMemory()

	// Create local backend directly
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	// Create agent with the local backend
	ag := &Agent{
		backend:      localBackend,
		standalone:   true,
		touchHandler: &NoOpTouchHandler{},
		logger:       testLogger(),
		keyCache:     make(map[string]*cachedKey),
	}

	// Verify standalone mode
	assert.True(t, ag.IsStandalone())

	// List should return empty
	keys, err := ag.List()
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Close
	err = ag.Close()
	assert.NoError(t, err)
}

func TestAgent_LockUnlock(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag := &Agent{
		backend:      localBackend,
		standalone:   true,
		touchHandler: &NoOpTouchHandler{},
		logger:       testLogger(),
		keyCache:     make(map[string]*cachedKey),
	}

	// Initially unlocked
	keys, err := ag.List()
	require.NoError(t, err)
	assert.Empty(t, keys)

	// Lock
	err = ag.Lock(nil)
	require.NoError(t, err)

	// List returns nil when locked (per SSH agent spec)
	keys, err = ag.List()
	require.NoError(t, err)
	assert.Nil(t, keys)

	// Unlock
	err = ag.Unlock(nil)
	require.NoError(t, err)

	// List works again
	keys, err = ag.List()
	require.NoError(t, err)
	assert.Empty(t, keys)

	ag.Close()
}

func TestAgent_UnsupportedOperations(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag := &Agent{
		backend:      localBackend,
		standalone:   true,
		touchHandler: &NoOpTouchHandler{},
		logger:       testLogger(),
		keyCache:     make(map[string]*cachedKey),
	}
	defer ag.Close()

	// Add is not supported
	err = ag.Add(agent.AddedKey{})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentUnsupportedOp)

	// Remove is not supported
	err = ag.Remove(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentUnsupportedOp)

	// RemoveAll is not supported
	err = ag.RemoveAll()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentUnsupportedOp)

	// Extension is not supported
	_, err = ag.Extension("test", nil)
	assert.Error(t, err)
}

func TestAgent_SignWithKeys(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag := &Agent{
		backend:      localBackend,
		standalone:   true,
		touchHandler: &NoOpTouchHandler{},
		logger:       testLogger(),
		keyCache:     make(map[string]*cachedKey),
	}
	defer ag.Close()

	ctx := context.Background()

	// Generate a key
	_, err = localBackend.GenerateKey(ctx, "test-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	// List keys (this populates the cache)
	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	// Get Signers - these have the correct public key reference
	signers, err := ag.Signers()
	require.NoError(t, err)
	require.Len(t, signers, 1)

	// Sign using the signer (this is the normal flow for SSH clients)
	data := []byte("test data to sign")
	sig, err := signers[0].Sign(nil, data)
	require.NoError(t, err)
	require.NotNil(t, sig)
	assert.NotEmpty(t, sig.Blob)
	assert.Equal(t, "ssh-ed25519", sig.Format)
}

func TestAgent_SignKeyNotFound(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag := &Agent{
		backend:      localBackend,
		standalone:   true,
		touchHandler: &NoOpTouchHandler{},
		logger:       testLogger(),
		keyCache:     make(map[string]*cachedKey),
	}
	defer ag.Close()

	// Create a key but don't add it to the backend
	ctx := context.Background()
	keyInfo, err := localBackend.GenerateKey(ctx, "temp-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	// Delete the key
	err = localBackend.DeleteKey(ctx, "temp-key")
	require.NoError(t, err)

	// Try to sign - should fail with key not found
	_, err = ag.Sign(keyInfo.PublicKey, []byte("test"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentKeyNotFound)
}

func TestAgent_SignWhileLocked(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag := &Agent{
		backend:      localBackend,
		standalone:   true,
		touchHandler: &NoOpTouchHandler{},
		logger:       testLogger(),
		keyCache:     make(map[string]*cachedKey),
	}
	defer ag.Close()

	ctx := context.Background()
	keyInfo, err := localBackend.GenerateKey(ctx, "test-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	// Lock the agent
	err = ag.Lock(nil)
	require.NoError(t, err)

	// Try to sign - should fail because locked
	_, err = ag.Sign(keyInfo.PublicKey, []byte("test"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentLocked)
}

func TestDefaultLocalStorePath(t *testing.T) {
	path := DefaultLocalStorePath()
	assert.NotEmpty(t, path)
	assert.Contains(t, path, "xkey")
	assert.Contains(t, path, "ssh/keys")
}

func TestGetConfigDir(t *testing.T) {
	dir := getConfigDir()
	assert.NotEmpty(t, dir)
}

func TestAgentImplementsInterfaces(t *testing.T) {
	// Compile-time check that Agent implements required interfaces
	var _ agent.Agent = (*Agent)(nil)
	var _ agent.ExtendedAgent = (*Agent)(nil)
}

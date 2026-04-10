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
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"
)

func TestNewMultiBackendAgent_NilConfig(t *testing.T) {
	_, err := NewMultiBackendAgent(nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentConnectionFailed)
}

func TestNewMultiBackendAgent_NoBackends(t *testing.T) {
	_, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{},
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentConnectionFailed)
}

func TestNewMultiBackendAgent_InvalidDefaultBackend(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	_, err = NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		DefaultBackend: "nonexistent",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentConnectionFailed)
}

func TestNewMultiBackendAgent_SingleBackend(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	// Default backend should be set automatically
	assert.Equal(t, "software", ag.DefaultBackend())
	assert.Contains(t, ag.Backends(), "software")
}

func TestNewMultiBackendAgent_MultipleBackends(t *testing.T) {
	memBackend1 := storage.NewMemory()
	localBackend1, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend1,
	})
	require.NoError(t, err)

	memBackend2 := storage.NewMemory()
	localBackend2, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend2,
	})
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend1,
			"tpm2":     localBackend2,
		},
		DefaultBackend: "software",
		Logger:         testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	assert.Equal(t, "software", ag.DefaultBackend())
	backends := ag.Backends()
	assert.Len(t, backends, 2)
	assert.Contains(t, backends, "software")
	assert.Contains(t, backends, "tpm2")
}

func TestMultiBackendAgent_ListEmpty(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	keys, err := ag.List()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestMultiBackendAgent_ListSingleBackend(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = localBackend.GenerateKey(ctx, "my-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	// Key from default backend should show simple name
	assert.Equal(t, "my-key", keys[0].Comment)
}

func TestMultiBackendAgent_ListMultipleBackends(t *testing.T) {
	memBackend1 := storage.NewMemory()
	localBackend1, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend1,
	})
	require.NoError(t, err)

	memBackend2 := storage.NewMemory()
	localBackend2, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend2,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Add key to default backend
	_, err = localBackend1.GenerateKey(ctx, "default-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	// Add key to non-default backend
	_, err = localBackend2.GenerateKey(ctx, "tpm-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend1,
			"tpm2":     localBackend2,
		},
		DefaultBackend: "software",
		Logger:         testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	keys, err := ag.List()
	require.NoError(t, err)
	require.Len(t, keys, 2)

	// Find keys by comment
	var defaultKeyComment, tpmKeyComment string
	for _, k := range keys {
		if k.Comment == "default-key" {
			defaultKeyComment = k.Comment
		} else if k.Comment == "tpm2:::tpm-key" {
			tpmKeyComment = k.Comment
		}
	}

	// Default backend key has simple name
	assert.Equal(t, "default-key", defaultKeyComment)
	// Non-default backend key has extended format
	assert.Equal(t, "tpm2:::tpm-key", tpmKeyComment)
}

func TestMultiBackendAgent_SignDefaultBackend(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ctx := context.Background()
	keyInfo, err := localBackend.GenerateKey(ctx, "sign-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	// List to populate cache
	_, err = ag.List()
	require.NoError(t, err)

	// Sign
	data := []byte("test data")
	sig, err := ag.Sign(keyInfo.PublicKey, data)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.NotEmpty(t, sig.Blob)
}

func TestMultiBackendAgent_SignNonDefaultBackend(t *testing.T) {
	memBackend1 := storage.NewMemory()
	localBackend1, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend1,
	})
	require.NoError(t, err)

	memBackend2 := storage.NewMemory()
	localBackend2, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend2,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Add key to non-default backend
	keyInfo, err := localBackend2.GenerateKey(ctx, "tpm-sign-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend1,
			"tpm2":     localBackend2,
		},
		DefaultBackend: "software",
		Logger:         testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	// List to populate cache
	_, err = ag.List()
	require.NoError(t, err)

	// Sign using key from non-default backend
	data := []byte("test data")
	sig, err := ag.Sign(keyInfo.PublicKey, data)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.NotEmpty(t, sig.Blob)
}

func TestMultiBackendAgent_SignKeyNotFound(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ctx := context.Background()
	keyInfo, err := localBackend.GenerateKey(ctx, "temp-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	// Delete the key
	err = localBackend.DeleteKey(ctx, "temp-key")
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	// Try to sign with deleted key
	_, err = ag.Sign(keyInfo.PublicKey, []byte("test"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentKeyNotFound)
}

func TestMultiBackendAgent_LockUnlock(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = localBackend.GenerateKey(ctx, "test-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	// Initially unlocked
	keys, err := ag.List()
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	// Lock
	err = ag.Lock(nil)
	require.NoError(t, err)

	// List returns nil when locked
	keys, err = ag.List()
	require.NoError(t, err)
	assert.Nil(t, keys)

	// Unlock
	err = ag.Unlock(nil)
	require.NoError(t, err)

	// List works again
	keys, err = ag.List()
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

func TestMultiBackendAgent_SignWhileLocked(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ctx := context.Background()
	keyInfo, err := localBackend.GenerateKey(ctx, "test-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	// Lock
	err = ag.Lock(nil)
	require.NoError(t, err)

	// Try to sign while locked
	_, err = ag.Sign(keyInfo.PublicKey, []byte("test"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentLocked)
}

func TestMultiBackendAgent_UnsupportedOperations(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
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

func TestMultiBackendAgent_Signers(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ctx := context.Background()
	_, err = localBackend.GenerateKey(ctx, "signer-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	signers, err := ag.Signers()
	require.NoError(t, err)
	require.Len(t, signers, 1)

	// Verify signer works
	data := []byte("test data")
	sig, err := signers[0].Sign(nil, data)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.NotEmpty(t, sig.Blob)
}

func TestMultiBackendAgent_ResolveKeyID(t *testing.T) {
	memBackend1 := storage.NewMemory()
	localBackend1, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend1,
	})
	require.NoError(t, err)

	memBackend2 := storage.NewMemory()
	localBackend2, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend2,
	})
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend1,
			"tpm2":     localBackend2,
		},
		DefaultBackend: "software",
		Logger:         testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	// Simple key name resolves to default backend
	backend, keyID, err := ag.ResolveKeyID("my-key")
	require.NoError(t, err)
	assert.Equal(t, "software", backend)
	assert.Equal(t, "my-key", keyID)

	// Extended key ID resolves to specified backend
	backend, keyID, err = ag.ResolveKeyID("tpm2:::tpm-key")
	require.NoError(t, err)
	assert.Equal(t, "tpm2", backend)
	assert.Equal(t, "tpm-key", keyID)

	// Invalid backend format returns error (backend is not recognized by ParseKeyID)
	_, _, err = ag.ResolveKeyID("invalid:::key")
	assert.Error(t, err)
	// The error could be about invalid format or backend not configured
	assert.True(t, strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "not configured"),
		"expected error about invalid format or backend not configured, got: %v", err)
}

func TestMultiBackendAgent_Close(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		Logger: testLogger(),
	})
	require.NoError(t, err)

	err = ag.Close()
	assert.NoError(t, err)
}

func TestParseExtendedKeyID(t *testing.T) {
	tests := []struct {
		name        string
		keyID       string
		wantBackend string
		wantKeyname string
		wantErr     bool
	}{
		{
			name:        "simple key name",
			keyID:       "my-key",
			wantBackend: "",
			wantKeyname: "my-key",
			wantErr:     false,
		},
		{
			name:        "extended with backend only",
			keyID:       "tpm2:::tpm-key",
			wantBackend: "tpm2",
			wantKeyname: "tpm-key",
			wantErr:     false,
		},
		{
			name:        "full extended format",
			keyID:       "tpm2:signing:ed25519:my-key",
			wantBackend: "tpm2",
			wantKeyname: "my-key",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, keyname, err := ParseExtendedKeyID(tt.keyID)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantBackend, backend)
			assert.Equal(t, tt.wantKeyname, keyname)
		})
	}
}

func TestFormatExtendedKeyID(t *testing.T) {
	tests := []struct {
		name     string
		backend  string
		keyname  string
		expected string
	}{
		{
			name:     "empty backend",
			backend:  "",
			keyname:  "my-key",
			expected: "my-key",
		},
		{
			name:     "with backend",
			backend:  "tpm2",
			keyname:  "my-key",
			expected: "tpm2:::my-key",
		},
		{
			name:     "uppercase backend normalized",
			backend:  "TPM2",
			keyname:  "my-key",
			expected: "tpm2:::my-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatExtendedKeyID(tt.backend, tt.keyname)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMultiBackendAgent_TouchConfirmation(t *testing.T) {
	memBackend := storage.NewMemory()
	localBackend, err := NewLocalBackend(&LocalBackendConfig{
		Backend: memBackend,
	})
	require.NoError(t, err)

	ctx := context.Background()
	keyInfo, err := localBackend.GenerateKey(ctx, "touch-key", KeyTypeEd25519, nil)
	require.NoError(t, err)

	// Create agent with touch required and no-op handler
	ag, err := NewMultiBackendAgent(&MultiBackendConfig{
		Backends: map[string]KeyBackend{
			"software": localBackend,
		},
		RequireTouch: true,
		TouchHandler: &NoOpTouchHandler{},
		Logger:       testLogger(),
	})
	require.NoError(t, err)
	defer ag.Close()

	// List to populate cache
	_, err = ag.List()
	require.NoError(t, err)

	// Sign should succeed (NoOpTouchHandler allows)
	data := []byte("test data")
	sig, err := ag.Sign(keyInfo.PublicKey, data)
	require.NoError(t, err)
	assert.NotNil(t, sig)
}

func TestMultiBackendAgentImplementsInterfaces(t *testing.T) {
	// Compile-time check that MultiBackendAgent implements required interfaces
	var _ agent.Agent = (*MultiBackendAgent)(nil)
	var _ agent.ExtendedAgent = (*MultiBackendAgent)(nil)
}

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

//go:build azurekv

package azurekv

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseKeyVersion verifies that the version is the last path segment of
// a Key Vault key ID, and that an ID with no segment after its last '/' is
// ErrInvalidKeyID rather than an empty version, which Key Vault would read
// as "the current version" and so silently unpin the key.
func TestParseKeyVersion(t *testing.T) {
	tests := []struct {
		name    string
		kid     azkeys.ID
		want    string
		wantErr bool
	}{
		{name: "versioned ID", kid: "https://vault.vault.azure.net/keys/k1/abc123", want: "abc123"},
		{name: "no slash", kid: "abc123", wantErr: true},
		{name: "trailing slash", kid: "https://vault.vault.azure.net/keys/k1/", wantErr: true},
		{name: "empty", kid: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := parseKeyVersion(tt.kid)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrInvalidKeyID)
				assert.Empty(t, version)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, version)
		})
	}
}

// TestBackend_ListKeys_SkipsUnreadableMetadata verifies that ListKeys leaves
// out a key whose metadata cannot be read or is not JSON, instead of failing
// the whole listing or returning a key with no type or algorithm.
func TestBackend_ListKeys_SkipsUnreadableMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("metadata not JSON", func(t *testing.T) {
		keyStorage := storage.New()
		require.NoError(t, storage.SaveKey(ctx, keyStorage, "corrupt", []byte("not json")))
		b, err := NewBackendWithClient(&Config{
			VaultURL:    "https://test-vault.vault.azure.net/",
			KeyStorage:  keyStorage,
			CertStorage: storage.New(),
		}, NewMockKeyVaultClient())
		require.NoError(t, err)

		keys, err := b.ListKeys(ctx)
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("metadata read fails", func(t *testing.T) {
		keyStorage := &failingStorage{Backend: storage.New()}
		require.NoError(t, storage.SaveKey(ctx, keyStorage, "unreadable", []byte(`{"key_type":"signing"}`)))
		keyStorage.getErr = errVaultUnavailable
		b, err := NewBackendWithClient(&Config{
			VaultURL:    "https://test-vault.vault.azure.net/",
			KeyStorage:  keyStorage,
			CertStorage: storage.New(),
		}, NewMockKeyVaultClient())
		require.NoError(t, err)

		keys, err := b.ListKeys(ctx)
		require.NoError(t, err)
		assert.Empty(t, keys)
	})
}

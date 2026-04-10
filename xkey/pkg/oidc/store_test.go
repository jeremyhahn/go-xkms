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

package oidc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileTokenStore_NewFileTokenStore(t *testing.T) {
	t.Run("creates store with encryption", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "tokens.json")

		store, err := NewFileTokenStore(path, []byte("encryption-key"))
		require.NoError(t, err)
		assert.NotNil(t, store)
		defer store.Close()
	})

	t.Run("creates store without encryption", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "tokens.json")

		store, err := NewFileTokenStore(path, nil)
		require.NoError(t, err)
		assert.NotNil(t, store)
		defer store.Close()
	})

	t.Run("creates nested directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "nested", "dir", "tokens.json")

		store, err := NewFileTokenStore(path, []byte("key"))
		require.NoError(t, err)
		assert.NotNil(t, store)
		defer store.Close()

		// Verify directory was created
		_, err = os.Stat(filepath.Dir(path))
		assert.NoError(t, err)
	})

	t.Run("loads existing tokens", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "tokens.json")
		key := []byte("encryption-key")

		// Create store and save a token
		store1, err := NewFileTokenStore(path, key)
		require.NoError(t, err)

		token := &TokenResponse{
			AccessToken:  "test-access",
			RefreshToken: "test-refresh",
			Expiry:       time.Now().Add(1 * time.Hour),
		}
		err = store1.Save("https://auth.example.com", token)
		require.NoError(t, err)
		store1.Close()

		// Create new store and verify token was loaded
		store2, err := NewFileTokenStore(path, key)
		require.NoError(t, err)
		defer store2.Close()

		loaded, err := store2.Load("https://auth.example.com")
		require.NoError(t, err)
		assert.Equal(t, "test-access", loaded.AccessToken)
	})

	t.Run("handles corrupted file gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "tokens.json")

		// Write invalid JSON to file
		err := os.WriteFile(path, []byte("not valid json"), 0600)
		require.NoError(t, err)

		// Should create store but with empty tokens
		store, err := NewFileTokenStore(path, []byte("key"))
		require.NoError(t, err)
		defer store.Close()

		// Should be empty since load failed
		issuers, err := store.List()
		require.NoError(t, err)
		assert.Empty(t, issuers)
	})

	t.Run("handles empty file gracefully", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "tokens.json")

		// Write empty file
		err := os.WriteFile(path, []byte(""), 0600)
		require.NoError(t, err)

		store, err := NewFileTokenStore(path, []byte("key"))
		require.NoError(t, err)
		defer store.Close()

		issuers, err := store.List()
		require.NoError(t, err)
		assert.Empty(t, issuers)
	})
}

func TestFileTokenStore_Save(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	store, err := NewFileTokenStore(path, []byte("key"))
	require.NoError(t, err)
	defer store.Close()

	t.Run("saves token successfully", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken:  "access-123",
			RefreshToken: "refresh-456",
			ExpiresIn:    3600,
			Expiry:       time.Now().Add(1 * time.Hour),
		}

		err := store.Save("https://auth.example.com", token)
		assert.NoError(t, err)

		// Verify file was created
		_, err = os.Stat(path)
		assert.NoError(t, err)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		token := &TokenResponse{AccessToken: "test"}
		err := store.Save("", token)
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails with nil token", func(t *testing.T) {
		err := store.Save("https://example.com", nil)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore, err := NewFileTokenStore(filepath.Join(tmpDir, "closed.json"), []byte("key"))
		require.NoError(t, err)
		closedStore.Close()

		token := &TokenResponse{AccessToken: "test"}
		err = closedStore.Save("https://example.com", token)
		assert.ErrorIs(t, err, ErrStoreClosed)
	})

	t.Run("normalizes issuer URL", func(t *testing.T) {
		token := &TokenResponse{AccessToken: "test"}

		// Save with trailing slash
		err := store.Save("https://auth.example.com/", token)
		require.NoError(t, err)

		// Load without trailing slash
		loaded, err := store.Load("https://auth.example.com")
		require.NoError(t, err)
		assert.Equal(t, "test", loaded.AccessToken)
	})
}

func TestFileTokenStore_Load(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	store, err := NewFileTokenStore(path, []byte("key"))
	require.NoError(t, err)
	defer store.Close()

	// Save a token first
	token := &TokenResponse{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
	}
	err = store.Save("https://auth.example.com", token)
	require.NoError(t, err)

	t.Run("loads token successfully", func(t *testing.T) {
		loaded, err := store.Load("https://auth.example.com")
		require.NoError(t, err)
		assert.Equal(t, "access-123", loaded.AccessToken)
		assert.Equal(t, "refresh-456", loaded.RefreshToken)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		_, err := store.Load("")
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails when token not found", func(t *testing.T) {
		_, err := store.Load("https://nonexistent.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore, err := NewFileTokenStore(filepath.Join(tmpDir, "closed.json"), []byte("key"))
		require.NoError(t, err)
		closedStore.Close()

		_, err = closedStore.Load("https://example.com")
		assert.ErrorIs(t, err, ErrStoreClosed)
	})

	t.Run("normalizes issuer for lookup", func(t *testing.T) {
		// Load with different case
		loaded, err := store.Load("HTTPS://AUTH.EXAMPLE.COM")
		require.NoError(t, err)
		assert.Equal(t, "access-123", loaded.AccessToken)
	})
}

func TestFileTokenStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	store, err := NewFileTokenStore(path, []byte("key"))
	require.NoError(t, err)
	defer store.Close()

	// Save a token first
	token := &TokenResponse{AccessToken: "test"}
	err = store.Save("https://auth.example.com", token)
	require.NoError(t, err)

	t.Run("deletes token successfully", func(t *testing.T) {
		err := store.Delete("https://auth.example.com")
		assert.NoError(t, err)

		// Verify token is gone
		_, err = store.Load("https://auth.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		err := store.Delete("")
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails when token not found", func(t *testing.T) {
		err := store.Delete("https://nonexistent.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore, err := NewFileTokenStore(filepath.Join(tmpDir, "closed.json"), []byte("key"))
		require.NoError(t, err)
		closedStore.Close()

		err = closedStore.Delete("https://example.com")
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestFileTokenStore_List(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	store, err := NewFileTokenStore(path, []byte("key"))
	require.NoError(t, err)
	defer store.Close()

	t.Run("returns empty list when no tokens", func(t *testing.T) {
		issuers, err := store.List()
		require.NoError(t, err)
		assert.Empty(t, issuers)
	})

	t.Run("lists all issuers", func(t *testing.T) {
		// Save multiple tokens
		store.Save("https://auth1.example.com", &TokenResponse{AccessToken: "1"})
		store.Save("https://auth2.example.com", &TokenResponse{AccessToken: "2"})
		store.Save("https://auth3.example.com", &TokenResponse{AccessToken: "3"})

		issuers, err := store.List()
		require.NoError(t, err)
		assert.Len(t, issuers, 3)
		assert.Contains(t, issuers, "https://auth1.example.com")
		assert.Contains(t, issuers, "https://auth2.example.com")
		assert.Contains(t, issuers, "https://auth3.example.com")
	})

	t.Run("returns sorted list", func(t *testing.T) {
		issuers, err := store.List()
		require.NoError(t, err)

		// Verify sorted
		for i := 1; i < len(issuers); i++ {
			assert.True(t, issuers[i-1] < issuers[i])
		}
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore, err := NewFileTokenStore(filepath.Join(tmpDir, "closed.json"), []byte("key"))
		require.NoError(t, err)
		closedStore.Close()

		_, err = closedStore.List()
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestFileTokenStore_Close(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	store, err := NewFileTokenStore(path, []byte("key"))
	require.NoError(t, err)

	t.Run("closes successfully", func(t *testing.T) {
		err := store.Close()
		assert.NoError(t, err)
	})

	t.Run("idempotent close", func(t *testing.T) {
		err := store.Close()
		assert.NoError(t, err)
	})
}

func TestFileTokenStore_Encryption(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")
	key := []byte("encryption-key-12345")

	t.Run("encrypts tokens at rest", func(t *testing.T) {
		store, err := NewFileTokenStore(path, key)
		require.NoError(t, err)

		token := &TokenResponse{
			AccessToken:  "secret-access-token",
			RefreshToken: "secret-refresh-token",
		}
		err = store.Save("https://auth.example.com", token)
		require.NoError(t, err)
		store.Close()

		// Read raw file and verify tokens are not in plaintext
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "secret-access-token")
		assert.NotContains(t, string(data), "secret-refresh-token")
	})

	t.Run("fails to decrypt with wrong key", func(t *testing.T) {
		// Create store with different key
		store, err := NewFileTokenStore(path, []byte("wrong-key"))
		require.NoError(t, err)
		defer store.Close()

		// Should not find any tokens (decryption failed silently)
		_, err = store.Load("https://auth.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("successfully decrypts with correct key", func(t *testing.T) {
		store, err := NewFileTokenStore(path, key)
		require.NoError(t, err)
		defer store.Close()

		loaded, err := store.Load("https://auth.example.com")
		require.NoError(t, err)
		assert.Equal(t, "secret-access-token", loaded.AccessToken)
		assert.Equal(t, "secret-refresh-token", loaded.RefreshToken)
	})
}

func TestFileTokenStore_NoEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	t.Run("stores tokens without encryption", func(t *testing.T) {
		store, err := NewFileTokenStore(path, nil) // nil key = no encryption
		require.NoError(t, err)

		token := &TokenResponse{
			AccessToken:  "plaintext-access-token",
			RefreshToken: "plaintext-refresh-token",
		}
		err = store.Save("https://auth.example.com", token)
		require.NoError(t, err)
		store.Close()

		// Read raw file - tokens should be in plaintext (base64 encoded JSON)
		data, err := os.ReadFile(path)
		require.NoError(t, err)

		// Parse the file structure
		var storeData struct {
			Tokens map[string]struct {
				Ciphertext []byte `json:"ciphertext"`
				Nonce      []byte `json:"nonce"`
			} `json:"tokens"`
		}
		err = json.Unmarshal(data, &storeData)
		require.NoError(t, err)

		// Nonce should be nil for unencrypted data
		for _, encToken := range storeData.Tokens {
			assert.Nil(t, encToken.Nonce)
		}
	})

	t.Run("loads tokens without encryption", func(t *testing.T) {
		store, err := NewFileTokenStore(path, nil)
		require.NoError(t, err)
		defer store.Close()

		loaded, err := store.Load("https://auth.example.com")
		require.NoError(t, err)
		assert.Equal(t, "plaintext-access-token", loaded.AccessToken)
		assert.Equal(t, "plaintext-refresh-token", loaded.RefreshToken)
	})
}

func TestFileTokenStore_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")
	key := []byte("key")

	t.Run("persists tokens across store instances", func(t *testing.T) {
		// Create first store and save token
		store1, err := NewFileTokenStore(path, key)
		require.NoError(t, err)

		token := &TokenResponse{
			AccessToken:  "persistent-token",
			RefreshToken: "persistent-refresh",
			Expiry:       time.Now().Add(1 * time.Hour),
		}
		err = store1.Save("https://auth.example.com", token)
		require.NoError(t, err)
		store1.Close()

		// Create second store and verify token persists
		store2, err := NewFileTokenStore(path, key)
		require.NoError(t, err)
		defer store2.Close()

		loaded, err := store2.Load("https://auth.example.com")
		require.NoError(t, err)
		assert.Equal(t, "persistent-token", loaded.AccessToken)
		assert.Equal(t, "persistent-refresh", loaded.RefreshToken)
	})
}

func TestFileTokenStore_DecryptToken_NilToken(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	store, err := NewFileTokenStore(path, []byte("key"))
	require.NoError(t, err)
	defer store.Close()

	// Directly test decryptToken with nil
	_, err = store.decryptToken(nil)
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestFileTokenStore_LoadWithInvalidDecryption(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	// Create a file with invalid encrypted data but valid-length nonce (12 bytes for GCM)
	storeData := struct {
		Tokens map[string]struct {
			Ciphertext []byte `json:"ciphertext"`
			Nonce      []byte `json:"nonce"`
		} `json:"tokens"`
	}{
		Tokens: make(map[string]struct {
			Ciphertext []byte `json:"ciphertext"`
			Nonce      []byte `json:"nonce"`
		}),
	}
	// Use a 12-byte nonce (correct size for AES-GCM) with invalid ciphertext
	storeData.Tokens["https://auth.example.com"] = struct {
		Ciphertext []byte `json:"ciphertext"`
		Nonce      []byte `json:"nonce"`
	}{
		Ciphertext: []byte("invalid-ciphertext-data-that-wont-decrypt"),
		Nonce:      []byte("123456789012"), // 12 bytes - correct size for GCM
	}

	data, err := json.Marshal(storeData)
	require.NoError(t, err)
	err = os.WriteFile(path, data, 0600)
	require.NoError(t, err)

	// Create store - should handle decryption failure gracefully
	store, err := NewFileTokenStore(path, []byte("some-key"))
	require.NoError(t, err)
	defer store.Close()

	// Token should not be loadable (decryption failed)
	_, err = store.Load("https://auth.example.com")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

// MemoryTokenStore tests

func TestMemoryTokenStore_NewMemoryTokenStore(t *testing.T) {
	store := NewMemoryTokenStore()
	assert.NotNil(t, store)
	defer store.Close()
}

func TestMemoryTokenStore_Save(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	t.Run("saves token successfully", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken:  "access-123",
			RefreshToken: "refresh-456",
		}

		err := store.Save("https://auth.example.com", token)
		assert.NoError(t, err)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		token := &TokenResponse{AccessToken: "test"}
		err := store.Save("", token)
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails with nil token", func(t *testing.T) {
		err := store.Save("https://example.com", nil)
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore := NewMemoryTokenStore()
		closedStore.Close()

		token := &TokenResponse{AccessToken: "test"}
		err := closedStore.Save("https://example.com", token)
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestMemoryTokenStore_Load(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	// Save a token first
	token := &TokenResponse{
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
	}
	store.Save("https://auth.example.com", token)

	t.Run("loads token successfully", func(t *testing.T) {
		loaded, err := store.Load("https://auth.example.com")
		require.NoError(t, err)
		assert.Equal(t, "access-123", loaded.AccessToken)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		_, err := store.Load("")
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails when token not found", func(t *testing.T) {
		_, err := store.Load("https://nonexistent.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore := NewMemoryTokenStore()
		closedStore.Close()

		_, err := closedStore.Load("https://example.com")
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestMemoryTokenStore_Delete(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	// Save a token first
	store.Save("https://auth.example.com", &TokenResponse{AccessToken: "test"})

	t.Run("deletes token successfully", func(t *testing.T) {
		err := store.Delete("https://auth.example.com")
		assert.NoError(t, err)

		_, err = store.Load("https://auth.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails with empty issuer", func(t *testing.T) {
		err := store.Delete("")
		assert.ErrorIs(t, err, ErrInvalidIssuer)
	})

	t.Run("fails when token not found", func(t *testing.T) {
		err := store.Delete("https://nonexistent.example.com")
		assert.ErrorIs(t, err, ErrTokenNotFound)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore := NewMemoryTokenStore()
		closedStore.Close()

		err := closedStore.Delete("https://example.com")
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestMemoryTokenStore_List(t *testing.T) {
	store := NewMemoryTokenStore()
	defer store.Close()

	t.Run("returns empty list when no tokens", func(t *testing.T) {
		issuers, err := store.List()
		require.NoError(t, err)
		assert.Empty(t, issuers)
	})

	t.Run("lists all issuers", func(t *testing.T) {
		store.Save("https://auth1.example.com", &TokenResponse{AccessToken: "1"})
		store.Save("https://auth2.example.com", &TokenResponse{AccessToken: "2"})

		issuers, err := store.List()
		require.NoError(t, err)
		assert.Len(t, issuers, 2)
	})

	t.Run("fails when store is closed", func(t *testing.T) {
		closedStore := NewMemoryTokenStore()
		closedStore.Close()

		_, err := closedStore.List()
		assert.ErrorIs(t, err, ErrStoreClosed)
	})
}

func TestMemoryTokenStore_Close(t *testing.T) {
	store := NewMemoryTokenStore()

	t.Run("closes successfully", func(t *testing.T) {
		err := store.Close()
		assert.NoError(t, err)
	})

	t.Run("idempotent close", func(t *testing.T) {
		err := store.Close()
		assert.NoError(t, err)
	})
}

func TestNormalizeIssuer(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://auth.example.com", "https://auth.example.com"},
		{"https://auth.example.com/", "https://auth.example.com"},
		{"HTTPS://AUTH.EXAMPLE.COM", "https://auth.example.com"},
		{"HTTPS://AUTH.EXAMPLE.COM/", "https://auth.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeIssuer(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestTokenStoreInterface(t *testing.T) {
	// Verify both implementations satisfy the interface
	var _ TokenStore = (*FileTokenStore)(nil)
	var _ TokenStore = (*MemoryTokenStore)(nil)
}

func TestFileTokenStore_CloseWithNoKey(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	// Create store without encryption key
	store, err := NewFileTokenStore(path, nil)
	require.NoError(t, err)

	// Save a token
	err = store.Save("https://auth.example.com", &TokenResponse{AccessToken: "test"})
	require.NoError(t, err)

	// Close should work correctly
	err = store.Close()
	assert.NoError(t, err)
}

func TestFileTokenStore_OverwriteToken(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	store, err := NewFileTokenStore(path, []byte("key"))
	require.NoError(t, err)
	defer store.Close()

	// Save initial token
	err = store.Save("https://auth.example.com", &TokenResponse{AccessToken: "initial"})
	require.NoError(t, err)

	// Overwrite with new token
	err = store.Save("https://auth.example.com", &TokenResponse{AccessToken: "updated"})
	require.NoError(t, err)

	// Verify updated token
	loaded, err := store.Load("https://auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, "updated", loaded.AccessToken)
}

func TestFileTokenStore_DecryptWithNoEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	// Create store without encryption
	store, err := NewFileTokenStore(path, nil)
	require.NoError(t, err)

	// Test decrypting with nil gcm (no encryption case)
	encToken := &encryptedToken{
		Ciphertext: []byte(`{"access_token":"test"}`),
		Nonce:      nil, // No nonce means plaintext
	}

	result, err := store.decryptToken(encToken)
	require.NoError(t, err)
	assert.Equal(t, "test", result.AccessToken)

	store.Close()
}

func TestFileTokenStore_DecryptInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "tokens.json")

	// Create store without encryption so decryption returns plaintext
	store, err := NewFileTokenStore(path, nil)
	require.NoError(t, err)
	defer store.Close()

	// Test decrypting invalid JSON
	encToken := &encryptedToken{
		Ciphertext: []byte("not valid json"),
		Nonce:      nil, // No nonce means plaintext
	}

	_, err = store.decryptToken(encToken)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

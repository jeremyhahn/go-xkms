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

package virtualfido

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStorageAdapter(t *testing.T) {
	t.Run("creates with nil backend (in-memory)", func(t *testing.T) {
		adapter, err := NewStorageAdapter(nil, "")
		require.NoError(t, err)
		require.NotNil(t, adapter)
		defer func() { _ = adapter.Close() }()
	})

	t.Run("creates with passphrase", func(t *testing.T) {
		adapter, err := NewStorageAdapter(nil, "test-passphrase")
		require.NoError(t, err)
		require.NotNil(t, adapter)
		defer func() { _ = adapter.Close() }()
	})
}

func TestStorageAdapterSaveRetrieveData(t *testing.T) {
	t.Run("save and retrieve without encryption", func(t *testing.T) {
		adapter, err := NewStorageAdapter(nil, "")
		require.NoError(t, err)
		defer func() { _ = adapter.Close() }()

		data := []byte("test data")
		adapter.SaveData(data)

		retrieved := adapter.RetrieveData()
		assert.Equal(t, data, retrieved)
	})

	t.Run("save and retrieve with encryption", func(t *testing.T) {
		adapter, err := NewStorageAdapter(nil, "encryption-key")
		require.NoError(t, err)
		defer func() { _ = adapter.Close() }()

		data := []byte("secret data")
		adapter.SaveData(data)

		retrieved := adapter.RetrieveData()
		assert.Equal(t, data, retrieved)
	})

	t.Run("retrieve returns nil for missing data", func(t *testing.T) {
		adapter, err := NewStorageAdapter(nil, "")
		require.NoError(t, err)
		defer func() { _ = adapter.Close() }()

		retrieved := adapter.RetrieveData()
		assert.Nil(t, retrieved)
	})
}

func TestStorageAdapterPassphrase(t *testing.T) {
	adapter, err := NewStorageAdapter(nil, "my-passphrase")
	require.NoError(t, err)
	defer func() { _ = adapter.Close() }()

	assert.Equal(t, "my-passphrase", adapter.Passphrase())
}

func TestStorageAdapterPIVSlots(t *testing.T) {
	adapter, err := NewStorageAdapter(nil, "test-key")
	require.NoError(t, err)
	defer func() { _ = adapter.Close() }()

	t.Run("save and load PIV slot", func(t *testing.T) {
		slotData := &SlotData{
			Algorithm:   x509.ECDSA,
			CreatedAt:   time.Now(),
			TouchPolicy: TouchPolicyNever,
			PINPolicy:   PINPolicyDefault,
		}

		err := adapter.SavePIVSlot(SlotAuthentication, slotData)
		require.NoError(t, err)

		loaded, err := adapter.LoadPIVSlot(SlotAuthentication)
		require.NoError(t, err)
		require.NotNil(t, loaded)
		assert.Equal(t, x509.ECDSA, loaded.Algorithm)
		assert.Equal(t, TouchPolicyNever, loaded.TouchPolicy)
		assert.Equal(t, PINPolicyDefault, loaded.PINPolicy)
	})

	t.Run("delete PIV slot", func(t *testing.T) {
		slotData := &SlotData{Algorithm: x509.RSA}
		err := adapter.SavePIVSlot(SlotSignature, slotData)
		require.NoError(t, err)

		err = adapter.DeletePIVSlot(SlotSignature)
		require.NoError(t, err)

		_, err = adapter.LoadPIVSlot(SlotSignature)
		assert.Error(t, err)
	})

	t.Run("load non-existent slot returns error", func(t *testing.T) {
		_, err := adapter.LoadPIVSlot(SlotCardAuth)
		assert.Error(t, err)
	})
}

func TestStorageAdapterConfig(t *testing.T) {
	adapter, err := NewStorageAdapter(nil, "config-key")
	require.NoError(t, err)
	defer func() { _ = adapter.Close() }()

	t.Run("save and load config", func(t *testing.T) {
		value := []byte("config-value")
		err := adapter.SaveConfig("test-setting", value)
		require.NoError(t, err)

		loaded, err := adapter.LoadConfig("test-setting")
		require.NoError(t, err)
		assert.Equal(t, value, loaded)
	})

	t.Run("load non-existent config returns error", func(t *testing.T) {
		_, err := adapter.LoadConfig("non-existent")
		assert.Error(t, err)
	})
}

func TestStorageAdapterClose(t *testing.T) {
	adapter, err := NewStorageAdapter(nil, "close-test")
	require.NoError(t, err)

	err = adapter.Close()
	assert.NoError(t, err)

	// Verify encryption key is cleared
	assert.Nil(t, adapter.encryptionKey)
}

func TestMemoryStorage(t *testing.T) {
	storage := newMemoryStorage()

	t.Run("put and get", func(t *testing.T) {
		err := storage.Put("key1", []byte("value1"), nil)
		require.NoError(t, err)

		value, err := storage.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), value)
	})

	t.Run("get non-existent key returns error", func(t *testing.T) {
		_, err := storage.Get("non-existent")
		assert.Error(t, err)
	})

	t.Run("delete", func(t *testing.T) {
		err := storage.Put("key2", []byte("value2"), nil)
		require.NoError(t, err)
		err = storage.Delete("key2")
		assert.NoError(t, err)

		_, err = storage.Get("key2")
		assert.Error(t, err)
	})

	t.Run("list with prefix", func(t *testing.T) {
		err := storage.Put("prefix/a", []byte("1"), nil)
		require.NoError(t, err)
		err = storage.Put("prefix/b", []byte("2"), nil)
		require.NoError(t, err)
		err = storage.Put("other/c", []byte("3"), nil)
		require.NoError(t, err)

		keys, err := storage.List("prefix/")
		require.NoError(t, err)
		assert.Len(t, keys, 2)
	})

	t.Run("exists", func(t *testing.T) {
		err := storage.Put("exists-key", []byte("value"), nil)
		require.NoError(t, err)

		exists, err := storage.Exists("exists-key")
		require.NoError(t, err)
		assert.True(t, exists)

		exists, err = storage.Exists("not-exists")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("close clears data", func(t *testing.T) {
		err := storage.Put("close-key", []byte("value"), nil)
		require.NoError(t, err)
		err = storage.Close()
		require.NoError(t, err)

		_, err = storage.Get("close-key")
		assert.Error(t, err)
	})

	t.Run("values are copied not referenced", func(t *testing.T) {
		original := []byte("original")
		err := storage.Put("copy-key", original, nil)
		require.NoError(t, err)

		// Modify original
		original[0] = 'X'

		// Stored value should be unchanged
		retrieved, _ := storage.Get("copy-key")
		assert.Equal(t, []byte("original"), retrieved)
	})
}

func TestEncryptDecrypt(t *testing.T) {
	adapter, err := NewStorageAdapter(nil, "encrypt-test")
	require.NoError(t, err)
	defer func() { _ = adapter.Close() }()

	t.Run("encrypt and decrypt", func(t *testing.T) {
		plaintext := []byte("secret message for encryption test")

		encrypted, err := adapter.encrypt(plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, encrypted)

		decrypted, err := adapter.decrypt(encrypted)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("decrypt fails with tampered data", func(t *testing.T) {
		plaintext := []byte("secret message")
		encrypted, _ := adapter.encrypt(plaintext)

		// Tamper with ciphertext
		encrypted[len(encrypted)-1] ^= 0xFF

		_, err := adapter.decrypt(encrypted)
		assert.Error(t, err)
	})

	t.Run("decrypt fails with short ciphertext", func(t *testing.T) {
		_, err := adapter.decrypt([]byte{1, 2, 3})
		assert.Error(t, err)
	})
}

func TestEncryptDecryptNoPassphrase(t *testing.T) {
	adapter, err := NewStorageAdapter(nil, "")
	require.NoError(t, err)
	defer func() { _ = adapter.Close() }()

	// Without passphrase, data should pass through unchanged
	data := []byte("unencrypted data")

	encrypted, err := adapter.encrypt(data)
	require.NoError(t, err)
	assert.Equal(t, data, encrypted)

	decrypted, err := adapter.decrypt(data)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger creates a logger for testing
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// =============================================================================
// FSBlobStore Tests
// =============================================================================

func TestFSBlobStore_NewFSBlobStore(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()

	blobStore := NewFSBlobStore(logger, backend)

	assert.NotNil(t, blobStore)
}

func TestFSBlobStore_Write(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	blobStore := NewFSBlobStore(logger, backend)

	t.Run("write blob successfully", func(t *testing.T) {
		err := blobStore.Write("test-blob", []byte("test data"))
		assert.NoError(t, err)

		// Verify we can read it back
		data, err := blobStore.Read("test-blob")
		assert.NoError(t, err)
		assert.Equal(t, []byte("test data"), data)
	})

	t.Run("overwrite existing blob", func(t *testing.T) {
		err := blobStore.Write("overwrite-blob", []byte("original data"))
		require.NoError(t, err)

		err = blobStore.Write("overwrite-blob", []byte("new data"))
		assert.NoError(t, err)

		data, err := blobStore.Read("overwrite-blob")
		assert.NoError(t, err)
		assert.Equal(t, []byte("new data"), data)
	})

	t.Run("write empty data", func(t *testing.T) {
		err := blobStore.Write("empty-blob", []byte{})
		assert.NoError(t, err)

		data, err := blobStore.Read("empty-blob")
		assert.NoError(t, err)
		assert.Empty(t, data)
	})
}

func TestFSBlobStore_Read(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	blobStore := NewFSBlobStore(logger, backend)

	t.Run("read existing blob", func(t *testing.T) {
		err := blobStore.Write("read-test", []byte("read data"))
		require.NoError(t, err)

		data, err := blobStore.Read("read-test")
		assert.NoError(t, err)
		assert.Equal(t, []byte("read data"), data)
	})

	t.Run("read non-existent blob returns error", func(t *testing.T) {
		data, err := blobStore.Read("non-existent")
		assert.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "failed to read blob")
	})
}

func TestFSBlobStore_Delete(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	blobStore := NewFSBlobStore(logger, backend)

	t.Run("delete existing blob", func(t *testing.T) {
		err := blobStore.Write("delete-test", []byte("delete data"))
		require.NoError(t, err)

		err = blobStore.Delete("delete-test")
		assert.NoError(t, err)

		// Verify it's deleted
		_, err = blobStore.Read("delete-test")
		assert.Error(t, err)
	})

	t.Run("delete non-existent blob succeeds (no error for not found)", func(t *testing.T) {
		err := blobStore.Delete("non-existent-delete")
		// Delete returns nil for not found (see implementation)
		assert.NoError(t, err)
	})
}

// =============================================================================
// StorageFactory Tests
// =============================================================================

func TestStorageFactory_NewStorageFactory(t *testing.T) {
	logger := testLogger()

	t.Run("with temp directory (empty baseDir)", func(t *testing.T) {
		factory, err := NewStorageFactory(logger, "")
		require.NoError(t, err)
		require.NotNil(t, factory)

		// Verify interfaces are available
		assert.NotNil(t, factory.BlobStore())
		assert.NotNil(t, factory.KeyBackend())
		assert.NotNil(t, factory.Backend())

		// Clean up
		err = factory.Close()
		assert.NoError(t, err)
	})

	t.Run("with specific directory", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "storage-factory-test-*")
		require.NoError(t, err)
		defer func() { _ = os.RemoveAll(tempDir) }()

		factory, err := NewStorageFactory(logger, tempDir)
		require.NoError(t, err)
		require.NotNil(t, factory)

		// Verify we can use it
		err = factory.BlobStore().Write("test", []byte("data"))
		assert.NoError(t, err)

		err = factory.Close()
		assert.NoError(t, err)
	})
}

func TestStorageFactory_NewMemoryStorageFactory(t *testing.T) {
	logger := testLogger()

	factory, err := NewMemoryStorageFactory(logger)
	require.NoError(t, err)
	require.NotNil(t, factory)

	// Verify all interfaces
	assert.NotNil(t, factory.BlobStore())
	assert.NotNil(t, factory.KeyBackend())
	assert.NotNil(t, factory.Backend())

	// Verify we can use it
	err = factory.BlobStore().Write("memory-test", []byte("memory data"))
	assert.NoError(t, err)

	data, err := factory.BlobStore().Read("memory-test")
	assert.NoError(t, err)
	assert.Equal(t, []byte("memory data"), data)

	err = factory.Close()
	assert.NoError(t, err)
}

func TestStorageFactory_Close(t *testing.T) {
	logger := testLogger()

	t.Run("close with temp directory", func(t *testing.T) {
		factory, err := NewStorageFactory(logger, "")
		require.NoError(t, err)

		err = factory.Close()
		assert.NoError(t, err)
	})

	t.Run("close memory factory", func(t *testing.T) {
		factory, err := NewMemoryStorageFactory(logger)
		require.NoError(t, err)

		err = factory.Close()
		assert.NoError(t, err)
	})

	t.Run("close with nil backend", func(t *testing.T) {
		factory := &StorageFactory{
			logger:  logger,
			backend: nil,
		}

		err := factory.Close()
		assert.NoError(t, err)
	})
}

// =============================================================================
// FileBackend Tests
// =============================================================================

func TestFileBackend_NewFileBackend(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()

	fb := NewFileBackend(logger, backend)
	assert.NotNil(t, fb)
}

func TestFileBackend_Get(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	fb := NewFileBackend(logger, backend)

	attrs := &types.KeyAttributes{
		CN: "test-key",
	}

	t.Run("get existing key", func(t *testing.T) {
		// Save first
		err := fb.Save(attrs, []byte("key data"), types.FSExtBlob, true)
		require.NoError(t, err)

		// Get it back
		data, err := fb.Get(attrs, types.FSExtBlob)
		assert.NoError(t, err)
		assert.Equal(t, []byte("key data"), data)
	})

	t.Run("get non-existent key returns error", func(t *testing.T) {
		nonExistentAttrs := &types.KeyAttributes{
			CN: "non-existent-key",
		}

		data, err := fb.Get(nonExistentAttrs, types.FSExtBlob)
		assert.Error(t, err)
		assert.Nil(t, data)
		assert.Contains(t, err.Error(), "failed to read key")
	})

	t.Run("get with different extensions", func(t *testing.T) {
		extAttrs := &types.KeyAttributes{
			CN: "ext-test-key",
		}

		// Save with private blob extension
		err := fb.Save(extAttrs, []byte("private blob"), types.FSExtension(FSEXT_PRIVATE_BLOB), true)
		require.NoError(t, err)

		// Save with public blob extension
		err = fb.Save(extAttrs, []byte("public blob"), types.FSExtension(FSEXT_PUBLIC_BLOB), true)
		require.NoError(t, err)

		// Get private
		data, err := fb.Get(extAttrs, types.FSExtension(FSEXT_PRIVATE_BLOB))
		assert.NoError(t, err)
		assert.Equal(t, []byte("private blob"), data)

		// Get public
		data, err = fb.Get(extAttrs, types.FSExtension(FSEXT_PUBLIC_BLOB))
		assert.NoError(t, err)
		assert.Equal(t, []byte("public blob"), data)
	})
}

func TestFileBackend_Save(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	fb := NewFileBackend(logger, backend)

	t.Run("save new key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "new-save-key",
		}

		err := fb.Save(attrs, []byte("new key data"), types.FSExtBlob, false)
		assert.NoError(t, err)

		// Verify
		data, err := fb.Get(attrs, types.FSExtBlob)
		assert.NoError(t, err)
		assert.Equal(t, []byte("new key data"), data)
	})

	t.Run("save without overwrite fails if exists", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "no-overwrite-key",
		}

		// First save should succeed
		err := fb.Save(attrs, []byte("original"), types.FSExtBlob, false)
		require.NoError(t, err)

		// Second save without overwrite should fail
		err = fb.Save(attrs, []byte("new"), types.FSExtBlob, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("save with overwrite succeeds if exists", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "overwrite-key",
		}

		// First save
		err := fb.Save(attrs, []byte("original"), types.FSExtBlob, false)
		require.NoError(t, err)

		// Second save with overwrite should succeed
		err = fb.Save(attrs, []byte("overwritten"), types.FSExtBlob, true)
		assert.NoError(t, err)

		// Verify new data
		data, err := fb.Get(attrs, types.FSExtBlob)
		assert.NoError(t, err)
		assert.Equal(t, []byte("overwritten"), data)
	})

	t.Run("save empty data", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "empty-data-key",
		}

		err := fb.Save(attrs, []byte{}, types.FSExtBlob, false)
		assert.NoError(t, err)

		data, err := fb.Get(attrs, types.FSExtBlob)
		assert.NoError(t, err)
		assert.Empty(t, data)
	})
}

func TestFileBackend_Delete(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	fb := NewFileBackend(logger, backend)

	t.Run("delete existing key", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "delete-key",
		}

		// Save all extensions
		err := fb.Save(attrs, []byte("blob"), types.FSExtension(FSEXT_PRIVATE_BLOB), true)
		require.NoError(t, err)
		err = fb.Save(attrs, []byte("pub"), types.FSExtension(FSEXT_PUBLIC_BLOB), true)
		require.NoError(t, err)
		err = fb.Save(attrs, []byte("ctx"), types.FSExtension(FSEXT_TPM_CONTEXT), true)
		require.NoError(t, err)

		// Delete
		err = fb.Delete(attrs)
		assert.NoError(t, err)

		// Verify all deleted
		_, err = fb.Get(attrs, types.FSExtension(FSEXT_PRIVATE_BLOB))
		assert.Error(t, err)
		_, err = fb.Get(attrs, types.FSExtension(FSEXT_PUBLIC_BLOB))
		assert.Error(t, err)
		_, err = fb.Get(attrs, types.FSExtension(FSEXT_TPM_CONTEXT))
		assert.Error(t, err)
	})

	t.Run("delete non-existent key succeeds (partial files)", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "partial-delete-key",
		}

		// Save only private blob
		err := fb.Save(attrs, []byte("blob"), types.FSExtension(FSEXT_PRIVATE_BLOB), true)
		require.NoError(t, err)

		// Delete should succeed even if some files don't exist
		err = fb.Delete(attrs)
		assert.NoError(t, err)
	})

	t.Run("delete completely non-existent key succeeds", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "totally-non-existent-key",
		}

		// Delete should not return error for non-existent keys
		err := fb.Delete(attrs)
		assert.NoError(t, err)
	})
}

// =============================================================================
// SignerStore Tests
// =============================================================================

func TestSignerStore_NewSignerStore(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()

	store := NewSignerStore(logger, backend)
	assert.NotNil(t, store)
}

func TestSignerStore_SaveAndGet_RSA(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("save and get RSA key via PKCS8", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "rsa-key",
			KeyAlgorithm: x509.RSA,
		}

		err = store.Save(attrs, rsaKey)
		assert.NoError(t, err)

		retrieved, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)

		retrievedRSA, ok := retrieved.(*rsa.PrivateKey)
		require.True(t, ok)
		assert.True(t, rsaKey.PublicKey.Equal(&retrievedRSA.PublicKey))
	})

	t.Run("save and get RSA key via PKCS1 fallback", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "rsa-pkcs1-key",
			KeyAlgorithm: x509.RSA,
		}

		// Manually save in PKCS1 format to test fallback
		pkcs1Data := x509.MarshalPKCS1PrivateKey(rsaKey)
		pemBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pkcs1Data,
		}
		pemData := pem.EncodeToMemory(pemBlock)

		// Store directly
		key := attrs.CN + FSEXT_SIGNER
		err = backend.Put(key, pemData, storage.DefaultOptions())
		require.NoError(t, err)

		// Get using store
		retrieved, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)

		retrievedRSA, ok := retrieved.(*rsa.PrivateKey)
		require.True(t, ok)
		assert.True(t, rsaKey.PublicKey.Equal(&retrievedRSA.PublicKey))
	})
}

func TestSignerStore_SaveAndGet_ECDSA(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("save and get ECDSA key via PKCS8", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "ecdsa-key",
			KeyAlgorithm: x509.ECDSA,
		}

		err = store.Save(attrs, ecKey)
		assert.NoError(t, err)

		retrieved, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)

		retrievedEC, ok := retrieved.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.True(t, ecKey.PublicKey.Equal(&retrievedEC.PublicKey))
	})

	t.Run("save and get ECDSA key via EC fallback", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "ecdsa-ec-key",
			KeyAlgorithm: x509.ECDSA,
		}

		// Manually save in EC format to test fallback
		ecData, err := x509.MarshalECPrivateKey(ecKey)
		require.NoError(t, err)
		pemBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecData,
		}
		pemData := pem.EncodeToMemory(pemBlock)

		// Store directly
		key := attrs.CN + FSEXT_SIGNER
		err = backend.Put(key, pemData, storage.DefaultOptions())
		require.NoError(t, err)

		// Get using store
		retrieved, err := store.Get(attrs)
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)

		retrievedEC, ok := retrieved.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.True(t, ecKey.PublicKey.Equal(&retrievedEC.PublicKey))
	})
}

func TestSignerStore_SaveAndGet_Ed25519(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "ed25519-key",
		KeyAlgorithm: x509.Ed25519,
	}

	err = store.Save(attrs, privKey)
	assert.NoError(t, err)

	retrieved, err := store.Get(attrs)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)

	retrievedEd, ok := retrieved.(ed25519.PrivateKey)
	require.True(t, ok)
	assert.True(t, pubKey.Equal(retrievedEd.Public()))
}

func TestSignerStore_Save_ErrorCases(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("save nil signer returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "nil-signer",
			KeyAlgorithm: x509.RSA,
		}

		err := store.Save(attrs, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signer is nil")
	})

	t.Run("save unsupported signer type returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "unsupported-signer",
			KeyAlgorithm: x509.RSA,
		}

		// Pass an unsupported type
		err := store.Save(attrs, "not a signer")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported signer type")
	})
}

func TestSignerStore_Get_ErrorCases(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("get non-existent signer returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-signer",
			KeyAlgorithm: x509.RSA,
		}

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("get with invalid PEM returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "invalid-pem",
			KeyAlgorithm: x509.RSA,
		}

		// Store invalid PEM data
		key := attrs.CN + FSEXT_SIGNER
		err := backend.Put(key, []byte("not valid pem"), storage.DefaultOptions())
		require.NoError(t, err)

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "decode PEM")
	})

	t.Run("get RSA with invalid key data returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "invalid-rsa-data",
			KeyAlgorithm: x509.RSA,
		}

		// Store PEM with invalid key data
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid key data"),
		}
		pemData := pem.EncodeToMemory(pemBlock)
		key := attrs.CN + FSEXT_SIGNER
		err := backend.Put(key, pemData, storage.DefaultOptions())
		require.NoError(t, err)

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "parse RSA")
	})

	t.Run("get ECDSA with invalid key data returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "invalid-ecdsa-data",
			KeyAlgorithm: x509.ECDSA,
		}

		// Store PEM with invalid key data
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid key data"),
		}
		pemData := pem.EncodeToMemory(pemBlock)
		key := attrs.CN + FSEXT_SIGNER
		err := backend.Put(key, pemData, storage.DefaultOptions())
		require.NoError(t, err)

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "parse ECDSA")
	})

	t.Run("get Ed25519 with invalid key data returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "invalid-ed25519-data",
			KeyAlgorithm: x509.Ed25519,
		}

		// Store PEM with invalid key data
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid key data"),
		}
		pemData := pem.EncodeToMemory(pemBlock)
		key := attrs.CN + FSEXT_SIGNER
		err := backend.Put(key, pemData, storage.DefaultOptions())
		require.NoError(t, err)

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "parse Ed25519")
	})

	t.Run("get with unsupported algorithm returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "unsupported-algo",
			KeyAlgorithm: x509.DSA, // DSA is not supported
		}

		// Store valid PEM but with unsupported algorithm type
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		keyData, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		require.NoError(t, err)
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyData,
		}
		pemData := pem.EncodeToMemory(pemBlock)
		key := attrs.CN + FSEXT_SIGNER
		err = backend.Put(key, pemData, storage.DefaultOptions())
		require.NoError(t, err)

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "unsupported key algorithm")
	})

	t.Run("get RSA key marked as ECDSA returns error", func(t *testing.T) {
		// Save an RSA key
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "rsa-as-ecdsa",
			KeyAlgorithm: x509.RSA,
		}

		err = store.Save(attrs, rsaKey)
		require.NoError(t, err)

		// Try to get it as ECDSA
		attrs.KeyAlgorithm = x509.ECDSA
		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
	})

	t.Run("get ECDSA key marked as RSA returns error", func(t *testing.T) {
		// Save an ECDSA key
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "ecdsa-as-rsa",
			KeyAlgorithm: x509.ECDSA,
		}

		err = store.Save(attrs, ecKey)
		require.NoError(t, err)

		// Try to get it as RSA
		attrs.KeyAlgorithm = x509.RSA
		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
	})

	t.Run("get ECDSA key marked as Ed25519 returns error", func(t *testing.T) {
		// Save an ECDSA key
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "ecdsa-as-ed25519",
			KeyAlgorithm: x509.ECDSA,
		}

		err = store.Save(attrs, ecKey)
		require.NoError(t, err)

		// Try to get it as Ed25519
		attrs.KeyAlgorithm = x509.Ed25519
		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
	})
}

func TestSignerStore_Delete(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("delete existing signer", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "delete-signer",
			KeyAlgorithm: x509.RSA,
		}

		err = store.Save(attrs, rsaKey)
		require.NoError(t, err)

		err = store.Delete(attrs)
		assert.NoError(t, err)

		// Verify deleted
		_, err = store.Get(attrs)
		assert.Error(t, err)
	})

	t.Run("delete non-existent signer succeeds", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-delete-signer",
			KeyAlgorithm: x509.RSA,
		}

		err := store.Delete(attrs)
		assert.NoError(t, err)
	})
}

func TestSignerStore_SaveSignature(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("save signature with blob CN", func(t *testing.T) {
		blobCN := "test-blob"
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				CN: "sig-key",
			},
			BlobCN: &blobCN,
		}

		signature := []byte("test signature")
		digest := []byte("test digest")

		err := store.SaveSignature(opts, signature, digest)
		assert.NoError(t, err)

		// Verify stored
		key := "sig-key.test-blob.sig"
		data, err := backend.Get(key)
		assert.NoError(t, err)
		assert.Contains(t, string(data), "digest=")
		assert.Contains(t, string(data), "signature=")
	})

	t.Run("save signature without blob CN", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				CN: "sig-key-no-blob",
			},
		}

		signature := []byte("test signature 2")
		digest := []byte("test digest 2")

		err := store.SaveSignature(opts, signature, digest)
		assert.NoError(t, err)

		// Verify stored
		key := "sig-key-no-blob.sig"
		data, err := backend.Get(key)
		assert.NoError(t, err)
		assert.Contains(t, string(data), "digest=")
		assert.Contains(t, string(data), "signature=")
	})

	t.Run("save signature with empty blob CN", func(t *testing.T) {
		emptyBlobCN := ""
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				CN: "sig-key-empty-blob",
			},
			BlobCN: &emptyBlobCN,
		}

		signature := []byte("test signature 3")
		digest := []byte("test digest 3")

		err := store.SaveSignature(opts, signature, digest)
		assert.NoError(t, err)

		// Verify stored (should use key without blob CN)
		key := "sig-key-empty-blob.sig"
		data, err := backend.Get(key)
		assert.NoError(t, err)
		assert.Contains(t, string(data), "digest=")
	})

	t.Run("save signature with nil opts returns error", func(t *testing.T) {
		err := store.SaveSignature(nil, []byte("sig"), []byte("digest"))
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSignerOpts, err)
	})

	t.Run("save signature with nil key attributes returns error", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: nil,
		}

		err := store.SaveSignature(opts, []byte("sig"), []byte("digest"))
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidSignerOpts, err)
	})
}

// =============================================================================
// Password Tests for uncovered code
// =============================================================================

func TestRequiredPassword_Clear(t *testing.T) {
	// This specifically tests the RequiredPassword.Clear() method
	// which was shown as 0% coverage
	p := &RequiredPassword{}

	// Clear should be a no-op and not panic
	p.Clear()

	// State should be unchanged
	assert.Nil(t, p.Bytes())

	str, err := p.String()
	assert.Error(t, err)
	assert.Equal(t, ErrPasswordRequired, err)
	assert.Equal(t, "", str)
}

// =============================================================================
// Crypto.Signer Interface Tests for Save
// =============================================================================

func TestSignerStore_Save_CryptoSigner(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	// Test the crypto.Signer branch in Save method
	// This tests when the signer is passed as crypto.Signer interface
	// rather than concrete types

	t.Run("save RSA via crypto.Signer interface", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "rsa-signer-interface",
			KeyAlgorithm: x509.RSA,
		}

		// Cast to crypto.Signer explicitly
		var signer crypto.Signer = rsaKey
		err = store.Save(attrs, signer)
		assert.NoError(t, err)

		// Verify we can retrieve it
		retrieved, err := store.Get(attrs)
		assert.NoError(t, err)
		retrievedRSA, ok := retrieved.(*rsa.PrivateKey)
		require.True(t, ok)
		assert.True(t, rsaKey.PublicKey.Equal(&retrievedRSA.PublicKey))
	})

	t.Run("save ECDSA via crypto.Signer interface", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "ecdsa-signer-interface",
			KeyAlgorithm: x509.ECDSA,
		}

		var signer crypto.Signer = ecKey
		err = store.Save(attrs, signer)
		assert.NoError(t, err)

		retrieved, err := store.Get(attrs)
		assert.NoError(t, err)
		retrievedEC, ok := retrieved.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.True(t, ecKey.PublicKey.Equal(&retrievedEC.PublicKey))
	})

	t.Run("save Ed25519 via crypto.Signer interface", func(t *testing.T) {
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		attrs := &types.KeyAttributes{
			CN:           "ed25519-signer-interface",
			KeyAlgorithm: x509.Ed25519,
		}

		var signer crypto.Signer = privKey
		err = store.Save(attrs, signer)
		assert.NoError(t, err)

		retrieved, err := store.Get(attrs)
		assert.NoError(t, err)
		retrievedEd, ok := retrieved.(ed25519.PrivateKey)
		require.True(t, ok)
		assert.True(t, pubKey.Equal(retrievedEd.Public()))
	})
}

// =============================================================================
// Mock Signers for Testing crypto.Signer Error Paths
// =============================================================================

// mockRSASigner is a crypto.Signer that returns RSA public key but fails type assertion
type mockRSASigner struct {
	publicKey *rsa.PublicKey
}

func (m *mockRSASigner) Public() crypto.PublicKey {
	return m.publicKey
}

func (m *mockRSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// mockECDSASigner is a crypto.Signer that returns ECDSA public key but fails type assertion
type mockECDSASigner struct {
	publicKey *ecdsa.PublicKey
}

func (m *mockECDSASigner) Public() crypto.PublicKey {
	return m.publicKey
}

func (m *mockECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// mockEd25519Signer is a crypto.Signer that returns Ed25519 public key but fails type assertion
type mockEd25519Signer struct {
	publicKey ed25519.PublicKey
}

func (m *mockEd25519Signer) Public() crypto.PublicKey {
	return m.publicKey
}

func (m *mockEd25519Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// mockUnknownSigner is a crypto.Signer that returns an unknown public key type
type mockUnknownSigner struct{}

func (m *mockUnknownSigner) Public() crypto.PublicKey {
	return "unknown public key type"
}

func (m *mockUnknownSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func TestSignerStore_Save_CryptoSignerErrorPaths(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("unable to extract RSA private key from crypto.Signer", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		mockSigner := &mockRSASigner{publicKey: &rsaKey.PublicKey}

		attrs := &types.KeyAttributes{
			CN:           "mock-rsa-signer",
			KeyAlgorithm: x509.RSA,
		}

		err = store.Save(attrs, mockSigner)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to extract RSA private key")
	})

	t.Run("unable to extract ECDSA private key from crypto.Signer", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		mockSigner := &mockECDSASigner{publicKey: &ecKey.PublicKey}

		attrs := &types.KeyAttributes{
			CN:           "mock-ecdsa-signer",
			KeyAlgorithm: x509.ECDSA,
		}

		err = store.Save(attrs, mockSigner)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to extract ECDSA private key")
	})

	t.Run("unable to extract Ed25519 private key from crypto.Signer", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		mockSigner := &mockEd25519Signer{publicKey: pubKey}

		attrs := &types.KeyAttributes{
			CN:           "mock-ed25519-signer",
			KeyAlgorithm: x509.Ed25519,
		}

		err = store.Save(attrs, mockSigner)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to extract Ed25519 private key")
	})

	t.Run("unsupported public key type from crypto.Signer", func(t *testing.T) {
		mockSigner := &mockUnknownSigner{}

		attrs := &types.KeyAttributes{
			CN:           "mock-unknown-signer",
			KeyAlgorithm: x509.RSA,
		}

		err := store.Save(attrs, mockSigner)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported public key type")
	})
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestStorageFactory_IntegrationWithSignerStore(t *testing.T) {
	logger := testLogger()

	factory, err := NewMemoryStorageFactory(logger)
	require.NoError(t, err)
	defer func() { _ = factory.Close() }()

	// Create a SignerStore using the factory's backend
	signerStore := NewSignerStore(logger, factory.Backend())

	// Generate and store a key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "integration-test-key",
		KeyAlgorithm: x509.RSA,
	}

	err = signerStore.Save(attrs, rsaKey)
	assert.NoError(t, err)

	// Retrieve and verify
	retrieved, err := signerStore.Get(attrs)
	assert.NoError(t, err)

	retrievedRSA, ok := retrieved.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.True(t, rsaKey.PublicKey.Equal(&retrievedRSA.PublicKey))

	// Use blob store from same factory
	err = factory.BlobStore().Write("test-blob", []byte("blob data"))
	assert.NoError(t, err)

	blobData, err := factory.BlobStore().Read("test-blob")
	assert.NoError(t, err)
	assert.Equal(t, []byte("blob data"), blobData)
}

func TestFileBackend_IntegrationWithStorageFactory(t *testing.T) {
	logger := testLogger()

	factory, err := NewMemoryStorageFactory(logger)
	require.NoError(t, err)
	defer func() { _ = factory.Close() }()

	keyBackend := factory.KeyBackend()

	attrs := &types.KeyAttributes{
		CN: "file-backend-integration",
	}

	// Save key data
	err = keyBackend.Save(attrs, []byte("key content"), types.FSExtension(FSEXT_PRIVATE_BLOB), false)
	assert.NoError(t, err)

	// Retrieve
	data, err := keyBackend.Get(attrs, types.FSExtension(FSEXT_PRIVATE_BLOB))
	assert.NoError(t, err)
	assert.Equal(t, []byte("key content"), data)

	// Delete
	err = keyBackend.Delete(attrs)
	assert.NoError(t, err)

	// Verify deleted
	_, err = keyBackend.Get(attrs, types.FSExtension(FSEXT_PRIVATE_BLOB))
	assert.Error(t, err)
}

// =============================================================================
// Error Backend for Testing Error Paths
// =============================================================================

// errorBackend is a mock backend that returns errors for testing
type errorBackend struct {
	getError    error
	putError    error
	deleteError error
	existsError error
}

func (e *errorBackend) Get(key string) ([]byte, error) {
	if e.getError != nil {
		return nil, e.getError
	}
	return nil, storage.ErrNotFound
}

func (e *errorBackend) Put(key string, value []byte, opts *storage.Options) error {
	return e.putError
}

func (e *errorBackend) Delete(key string) error {
	return e.deleteError
}

func (e *errorBackend) List(prefix string) ([]string, error) {
	return nil, nil
}

func (e *errorBackend) Exists(key string) (bool, error) {
	return false, e.existsError
}

func (e *errorBackend) Close() error {
	return nil
}

func TestFSBlobStore_WriteError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{putError: errors.New("write failed")}
	blobStore := NewFSBlobStore(logger, backend)

	err := blobStore.Write("test", []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write blob")
}

func TestFSBlobStore_DeleteError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{deleteError: errors.New("delete failed")}
	blobStore := NewFSBlobStore(logger, backend)

	err := blobStore.Delete("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete blob")
}

func TestFileBackend_SaveExistsError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{existsError: errors.New("exists check failed")}
	fb := NewFileBackend(logger, backend)

	attrs := &types.KeyAttributes{
		CN: "exists-error-key",
	}

	err := fb.Save(attrs, []byte("data"), types.FSExtBlob, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check key existence")
}

func TestFileBackend_SavePutError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{putError: errors.New("put failed")}
	fb := NewFileBackend(logger, backend)

	attrs := &types.KeyAttributes{
		CN: "put-error-key",
	}

	err := fb.Save(attrs, []byte("data"), types.FSExtBlob, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write key")
}

func TestFileBackend_DeleteError(t *testing.T) {
	logger := testLogger()
	// Use a custom error that is not ErrNotFound and not os not exist error
	backend := &errorBackend{deleteError: errors.New("custom delete error")}
	fb := NewFileBackend(logger, backend)

	attrs := &types.KeyAttributes{
		CN: "delete-error-key",
	}

	err := fb.Delete(attrs)
	assert.Error(t, err)
}

func TestSignerStore_SavePutError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{putError: errors.New("put failed")}
	store := NewSignerStore(logger, backend)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "save-error-key",
		KeyAlgorithm: x509.RSA,
	}

	err = store.Save(attrs, rsaKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save signer")
}

func TestSignerStore_SaveSignaturePutError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{putError: errors.New("put failed")}
	store := NewSignerStore(logger, backend)

	opts := &SignerOpts{
		KeyAttributes: &types.KeyAttributes{
			CN: "sig-error-key",
		},
	}

	err := store.SaveSignature(opts, []byte("sig"), []byte("digest"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save signature")
}

func TestSignerStore_DeleteError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{deleteError: errors.New("delete failed")}
	store := NewSignerStore(logger, backend)

	attrs := &types.KeyAttributes{
		CN:           "delete-error-signer",
		KeyAlgorithm: x509.RSA,
	}

	err := store.Delete(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete signer")
}

func TestSignerStore_GetError(t *testing.T) {
	logger := testLogger()
	// Return a non-ErrNotFound error
	backend := &errorBackend{getError: errors.New("get failed")}
	store := NewSignerStore(logger, backend)

	attrs := &types.KeyAttributes{
		CN:           "get-error-signer",
		KeyAlgorithm: x509.RSA,
	}

	signer, err := store.Get(attrs)
	assert.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "failed to get signer")
}

// =============================================================================
// Additional Edge Cases
// =============================================================================

func TestSignerStore_NilLogger(t *testing.T) {
	backend := storage.NewMemory()
	store := NewSignerStore(nil, backend)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "nil-logger-key",
		KeyAlgorithm: x509.RSA,
	}

	// Save should work with nil logger
	err = store.Save(attrs, rsaKey)
	assert.NoError(t, err)

	// Get should work with nil logger
	retrieved, err := store.Get(attrs)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)

	// Delete should work with nil logger
	err = store.Delete(attrs)
	assert.NoError(t, err)
}

func TestSignerStore_DeleteWithNilLoggerNotFound(t *testing.T) {
	backend := storage.NewMemory()
	store := NewSignerStore(nil, backend)

	attrs := &types.KeyAttributes{
		CN:           "nil-logger-not-found",
		KeyAlgorithm: x509.RSA,
	}

	// Delete non-existent with nil logger - tests the logger nil check path
	err := store.Delete(attrs)
	assert.NoError(t, err)
}

func TestFileBackend_NilLogger(t *testing.T) {
	backend := storage.NewMemory()
	fb := NewFileBackend(nil, backend)

	attrs := &types.KeyAttributes{
		CN: "nil-logger-file-backend",
	}

	// All operations should work with nil logger
	err := fb.Save(attrs, []byte("data"), types.FSExtBlob, true)
	assert.NoError(t, err)

	data, err := fb.Get(attrs, types.FSExtBlob)
	assert.NoError(t, err)
	assert.Equal(t, []byte("data"), data)

	err = fb.Delete(attrs)
	assert.NoError(t, err)
}

func TestFSBlobStore_NilLogger(t *testing.T) {
	backend := storage.NewMemory()
	blobStore := NewFSBlobStore(nil, backend)

	err := blobStore.Write("nil-logger-blob", []byte("data"))
	assert.NoError(t, err)

	data, err := blobStore.Read("nil-logger-blob")
	assert.NoError(t, err)
	assert.Equal(t, []byte("data"), data)

	err = blobStore.Delete("nil-logger-blob")
	assert.NoError(t, err)
}

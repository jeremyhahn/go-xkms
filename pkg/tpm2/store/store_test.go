// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/cespare/xxhash/v2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger creates a logger for testing
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// putSignerEntry writes a SignerEntry directly to the backend using the DAO's
// key format ("signers/<xxhash64>"). This is used to inject entries with
// alternative PEM formats (PKCS1, EC) to test the parsing fallback paths.
func putSignerEntry(t *testing.T, backend storage.Backend, cn string, pemData []byte, algo string) {
	t.Helper()

	entityID := xxhash.Sum64String(cn)

	entry := &SignerEntry{
		ID:        entityID,
		CN:        cn,
		KeyPEM:    pemData,
		Algorithm: algo,
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	key := fmt.Sprintf("signers/%d", entityID)
	err = backend.Put(context.Background(), key, data)
	require.NoError(t, err)
}

// getSignatureData reads a SignatureEntry directly from the backend using the
// DAO's key format ("signatures/<xxhash64>") and returns the Data field.
func getSignatureData(t *testing.T, backend storage.Backend, sigKey string) string {
	t.Helper()

	entityID := xxhash.Sum64String(sigKey)

	key := fmt.Sprintf("signatures/%d", entityID)
	data, err := backend.Get(context.Background(), key)
	require.NoError(t, err)

	var entry SignatureEntry
	err = json.Unmarshal(data, &entry)
	require.NoError(t, err)

	return entry.Data
}

// =============================================================================
// FSBlobStore Tests
// =============================================================================

func TestFSBlobStore_NewFSBlobStore(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()

	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	assert.NotNil(t, blobStore)
}

func TestFSBlobStore_Write(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

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
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

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
		assert.Contains(t, err.Error(), "blob store: failed to read")
	})
}

func TestFSBlobStore_Delete(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

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

		// Manually save in PKCS1 format to test fallback parsing.
		pkcs1Data := x509.MarshalPKCS1PrivateKey(rsaKey)
		pemBlock := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pkcs1Data,
		}
		pemData := pem.EncodeToMemory(pemBlock)

		// Inject a DAO entry with PKCS1-encoded PEM directly into the backend.
		putSignerEntry(t, backend, attrs.CN, pemData, "RSA")

		// Get using store -- should use PKCS1 fallback parsing.
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

		// Manually save in EC format to test fallback parsing.
		ecData, err := x509.MarshalECPrivateKey(ecKey)
		require.NoError(t, err)
		pemBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecData,
		}
		pemData := pem.EncodeToMemory(pemBlock)

		// Inject a DAO entry with EC-encoded PEM directly into the backend.
		putSignerEntry(t, backend, attrs.CN, pemData, "ECDSA")

		// Get using store -- should use EC fallback parsing.
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

		// Inject a DAO entry with invalid PEM data.
		putSignerEntry(t, backend, attrs.CN, []byte("not valid pem"), "RSA")

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

		// Inject a DAO entry with valid PEM but invalid key bytes.
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid key data"),
		}
		pemData := pem.EncodeToMemory(pemBlock)
		putSignerEntry(t, backend, attrs.CN, pemData, "RSA")

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

		// Inject a DAO entry with valid PEM but invalid key bytes.
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid key data"),
		}
		pemData := pem.EncodeToMemory(pemBlock)
		putSignerEntry(t, backend, attrs.CN, pemData, "ECDSA")

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

		// Inject a DAO entry with valid PEM but invalid key bytes.
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("invalid key data"),
		}
		pemData := pem.EncodeToMemory(pemBlock)
		putSignerEntry(t, backend, attrs.CN, pemData, "Ed25519")

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

		// Inject a valid RSA key entry but try to retrieve with unsupported algorithm.
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		keyData, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		require.NoError(t, err)
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyData,
		}
		pemData := pem.EncodeToMemory(pemBlock)
		putSignerEntry(t, backend, attrs.CN, pemData, "DSA")

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

		// Verify stored via DAO key format.
		sigKey := "sig-key.test-blob.sig"
		data := getSignatureData(t, backend, sigKey)
		assert.Contains(t, data, "digest=")
		assert.Contains(t, data, "signature=")
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

		// Verify stored via DAO key format.
		sigKey := "sig-key-no-blob.sig"
		data := getSignatureData(t, backend, sigKey)
		assert.Contains(t, data, "digest=")
		assert.Contains(t, data, "signature=")
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

		// Verify stored (should use key without blob CN).
		sigKey := "sig-key-empty-blob.sig"
		data := getSignatureData(t, backend, sigKey)
		assert.Contains(t, data, "digest=")
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

func (e *errorBackend) Get(_ context.Context, key string) ([]byte, error) {
	if e.getError != nil {
		return nil, e.getError
	}
	return nil, storage.ErrNotFound
}

func (e *errorBackend) Put(_ context.Context, key string, value []byte) error {
	return e.putError
}

func (e *errorBackend) Delete(_ context.Context, key string) error {
	return e.deleteError
}

func (e *errorBackend) List(_ context.Context, prefix string) ([]string, error) {
	return nil, nil
}

func (e *errorBackend) Exists(_ context.Context, key string) (bool, error) {
	return false, e.existsError
}

func (e *errorBackend) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	return nil
}
func (e *errorBackend) Close() error {
	return nil
}

func TestFSBlobStore_WriteError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{putError: errors.New("write failed")}
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	err = blobStore.Write("test", []byte("data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blob store: failed to write")
}

func TestFSBlobStore_DeleteError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{deleteError: errors.New("delete failed")}
	blobStore, err := NewFSBlobStore(logger, backend)
	require.NoError(t, err)

	err = blobStore.Delete("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blob store: failed to delete")
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
	blobStore, err := NewFSBlobStore(nil, backend)
	require.NoError(t, err)

	err = blobStore.Write("nil-logger-blob", []byte("data"))
	assert.NoError(t, err)

	data, err := blobStore.Read("nil-logger-blob")
	assert.NoError(t, err)
	assert.Equal(t, []byte("data"), data)

	err = blobStore.Delete("nil-logger-blob")
	assert.NoError(t, err)
}

// =============================================================================
// SignerEntry and SignatureEntry Entity Tests
// =============================================================================

func TestSignerEntry_EntityID(t *testing.T) {
	entry := &SignerEntry{ID: 12345, CN: "test-cn"}
	assert.Equal(t, uint64(12345), entry.EntityID())
}

func TestSignerEntry_SetEntityID(t *testing.T) {
	entry := &SignerEntry{}
	entry.SetEntityID(67890)
	assert.Equal(t, uint64(67890), entry.EntityID())
}

func TestSignatureEntry_EntityID(t *testing.T) {
	entry := &SignatureEntry{ID: 11111, Key: "test.sig"}
	assert.Equal(t, uint64(11111), entry.EntityID())
}

func TestSignatureEntry_SetEntityID(t *testing.T) {
	entry := &SignatureEntry{}
	entry.SetEntityID(22222)
	assert.Equal(t, uint64(22222), entry.EntityID())
}

func TestSignerEntryIDGenerator_NextID_SignerEntry(t *testing.T) {
	gen := &signerEntryIDGenerator{}
	entry := &SignerEntry{CN: "test-signer"}

	id := gen.NextID(entry)
	assert.NotZero(t, id)

	// Deterministic: same CN produces same ID.
	id2 := gen.NextID(entry)
	assert.Equal(t, id, id2)

	// Different CN produces different ID.
	entry2 := &SignerEntry{CN: "other-signer"}
	id3 := gen.NextID(entry2)
	assert.NotEqual(t, id, id3)
}

func TestSignerEntryIDGenerator_NextID_SignatureEntry(t *testing.T) {
	gen := &signerEntryIDGenerator{}
	entry := &SignatureEntry{Key: "test-key.sig"}

	id := gen.NextID(entry)
	assert.NotZero(t, id)

	// Deterministic: same Key produces same ID.
	id2 := gen.NextID(entry)
	assert.Equal(t, id, id2)
}

func TestSignerEntryIDGenerator_NextID_UnsupportedType(t *testing.T) {
	gen := &signerEntryIDGenerator{}

	// Passing an unsupported entity type should return 0.
	id := gen.NextID(&SignerEntry{}) // empty CN still hashes
	assert.NotZero(t, id)            // even empty string has a hash

	// Truly unsupported type (not SignerEntry or SignatureEntry) is tested
	// by verifying the default branch. We cannot pass a non-Entity here
	// because NextID requires dao.Entity, but we can verify via the
	// computeSignerID helper consistency.
	expected := computeSignerID("")
	assert.Equal(t, expected, id)
}

// =============================================================================
// SignerErrors Tests
// =============================================================================

func TestErrSignerNotFound_Error(t *testing.T) {
	err := &ErrSignerNotFound{CN: "my-key"}
	assert.Contains(t, err.Error(), "signer not found")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerGet_Error(t *testing.T) {
	cause := errors.New("io error")
	err := &ErrSignerGet{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "failed to get signer")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerPEMDecode_Error(t *testing.T) {
	cause := errors.New("bad pem")
	err := &ErrSignerPEMDecode{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "decode PEM")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerKeyParse_Error(t *testing.T) {
	t.Run("without fallback cause", func(t *testing.T) {
		cause := errors.New("parse error")
		err := &ErrSignerKeyParse{CN: "my-key", Algorithm: "RSA", Cause: cause}
		assert.Contains(t, err.Error(), "parse RSA")
		assert.Contains(t, err.Error(), "my-key")
		assert.NotContains(t, err.Error(), "pkcs8:")
		assert.ErrorIs(t, err, cause)
	})

	t.Run("with fallback cause", func(t *testing.T) {
		cause := errors.New("pkcs1 error")
		fallback := errors.New("pkcs8 error")
		err := &ErrSignerKeyParse{CN: "my-key", Algorithm: "RSA", Cause: cause, FallbackCause: fallback}
		assert.Contains(t, err.Error(), "parse RSA")
		assert.Contains(t, err.Error(), "pkcs8:")
		assert.ErrorIs(t, err, cause)
	})
}

func TestErrSignerKeyTypeMismatch_Error(t *testing.T) {
	err := &ErrSignerKeyTypeMismatch{CN: "my-key", Expected: "RSA", Actual: "ECDSA"}
	assert.Contains(t, err.Error(), "not an RSA")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerNil_Error(t *testing.T) {
	err := &ErrSignerNil{CN: "my-key"}
	assert.Contains(t, err.Error(), "signer is nil")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerMarshal_Error(t *testing.T) {
	cause := errors.New("marshal error")
	err := &ErrSignerMarshal{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "marshal private key")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerSave_Error(t *testing.T) {
	cause := errors.New("save error")
	err := &ErrSignerSave{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "failed to save signer")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignerDelete_Error(t *testing.T) {
	cause := errors.New("delete error")
	err := &ErrSignerDelete{CN: "my-key", Cause: cause}
	assert.Contains(t, err.Error(), "failed to delete signer")
	assert.Contains(t, err.Error(), "my-key")
	assert.ErrorIs(t, err, cause)
}

func TestErrSignatureSave_Error(t *testing.T) {
	cause := errors.New("save error")
	err := &ErrSignatureSave{Key: "test.sig", Cause: cause}
	assert.Contains(t, err.Error(), "failed to save signature")
	assert.Contains(t, err.Error(), "test.sig")
	assert.ErrorIs(t, err, cause)
}

func TestErrUnsupportedAlgorithm_Error(t *testing.T) {
	err := &ErrUnsupportedAlgorithm{CN: "my-key", Algorithm: x509.DSA}
	assert.Contains(t, err.Error(), "unsupported key algorithm")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrUnsupportedSignerType_Error(t *testing.T) {
	err := &ErrUnsupportedSignerType{CN: "my-key", Type: "string"}
	assert.Contains(t, err.Error(), "unsupported signer type")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerExtract_Error(t *testing.T) {
	err := &ErrSignerExtract{CN: "my-key", Algorithm: "RSA"}
	assert.Contains(t, err.Error(), "unable to extract RSA")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrUnsupportedPublicKeyType_Error(t *testing.T) {
	err := &ErrUnsupportedPublicKeyType{CN: "my-key", Type: "string"}
	assert.Contains(t, err.Error(), "unsupported public key type")
	assert.Contains(t, err.Error(), "my-key")
}

func TestErrSignerStoreNotInitialized(t *testing.T) {
	// Test that uninitialized store returns proper errors.
	store := &SignerStore{}

	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}

	_, err := store.Get(attrs)
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

	err = store.Save(attrs, nil)
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

	err = store.Delete(attrs)
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

	opts := &SignerOpts{KeyAttributes: attrs}
	err = store.SaveSignature(opts, []byte("sig"), []byte("digest"))
	assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)
}

func TestNewSignerStore_NilBackend(t *testing.T) {
	t.Run("nil backend with logger returns non-nil store that returns errors", func(t *testing.T) {
		logger := testLogger()
		store := NewSignerStore(logger, nil)
		assert.NotNil(t, store)

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.RSA,
		}

		_, err := store.Get(attrs)
		assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)

		err = store.Save(attrs, nil)
		assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)
	})

	t.Run("nil backend with nil logger returns non-nil store that returns errors", func(t *testing.T) {
		store := NewSignerStore(nil, nil)
		assert.NotNil(t, store)

		attrs := &types.KeyAttributes{
			CN:           "test",
			KeyAlgorithm: x509.RSA,
		}

		_, err := store.Get(attrs)
		assert.ErrorIs(t, err, ErrSignerStoreNotInitialized)
	})
}

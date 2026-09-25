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
	"testing"

	"github.com/cespare/xxhash/v2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger creates a logger for testing.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// errorBackend is a mock storage.Backend that returns errors for testing.
// A near-identical fake lives in pkg/tpm2/store's own test suite -- kept
// separate rather than shared, since sharing it would need a new exported
// test-utility package for ~30 lines used by two packages.
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

// PutIfAbsent mirrors errorBackend.Put: it returns putError, otherwise
// reports the value as stored.
func (e *errorBackend) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if e.putError != nil {
		return false, e.putError
	}
	return true, nil
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

// putSignatureEntry writes a SignatureEntry directly to the backend using the
// DAO's key format ("signatures/<xxhash64>"), with an arbitrary Data payload.
// This is used to inject a malformed record to test GetSignature's parse
// error path, which SaveSignature itself can never produce.
func putSignatureEntry(t *testing.T, backend storage.Backend, sigKey, data string) {
	t.Helper()

	entityID := xxhash.Sum64String(sigKey)

	entry := &SignatureEntry{
		ID:   entityID,
		Key:  sigKey,
		Data: data,
	}

	encoded, err := json.Marshal(entry)
	require.NoError(t, err)

	key := fmt.Sprintf("signatures/%d", entityID)
	err = backend.Put(context.Background(), key, encoded)
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
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				CN: "sig-key",
			},
			BlobCN: "test-blob",
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
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{
				CN: "sig-key-empty-blob",
			},
			BlobCN: "",
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

func TestSignerStore_GetSignature(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("round-trips a signature saved with a blob CN", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{CN: "roundtrip-key"},
			BlobCN:        "test-blob",
		}

		wantSignature := []byte("a signature")
		wantDigest := []byte("a digest")

		require.NoError(t, store.SaveSignature(opts, wantSignature, wantDigest))

		gotDigest, gotSignature, err := store.GetSignature(opts)
		require.NoError(t, err)
		assert.Equal(t, wantDigest, gotDigest)
		assert.Equal(t, wantSignature, gotSignature)
	})

	t.Run("round-trips a signature saved without a blob CN", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{CN: "roundtrip-key-no-blob"},
		}

		wantSignature := []byte("another signature")
		wantDigest := []byte("another digest")

		require.NoError(t, store.SaveSignature(opts, wantSignature, wantDigest))

		gotDigest, gotSignature, err := store.GetSignature(opts)
		require.NoError(t, err)
		assert.Equal(t, wantDigest, gotDigest)
		assert.Equal(t, wantSignature, gotSignature)
	})

	t.Run("no record returns ErrSignatureNotFound", func(t *testing.T) {
		opts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{CN: "never-signed"},
		}

		digest, signature, err := store.GetSignature(opts)
		require.Error(t, err)
		assert.Nil(t, digest)
		assert.Nil(t, signature)
		var notFound *ErrSignatureNotFound
		assert.ErrorAs(t, err, &notFound)
	})

	t.Run("nil opts returns error", func(t *testing.T) {
		_, _, err := store.GetSignature(nil)
		assert.Equal(t, ErrInvalidSignerOpts, err)
	})

	t.Run("nil key attributes returns error", func(t *testing.T) {
		_, _, err := store.GetSignature(&SignerOpts{})
		assert.Equal(t, ErrInvalidSignerOpts, err)
	})
}

func TestSignerStore_GetSignature_GetError(t *testing.T) {
	logger := testLogger()
	backend := &errorBackend{getError: errors.New("get failed")}
	store := NewSignerStore(logger, backend)

	opts := &SignerOpts{KeyAttributes: &types.KeyAttributes{CN: "get-error-sig"}}

	digest, signature, err := store.GetSignature(opts)
	require.Error(t, err)
	assert.Nil(t, digest)
	assert.Nil(t, signature)
	var getErr *ErrSignatureGet
	assert.ErrorAs(t, err, &getErr)
	assert.Contains(t, err.Error(), "failed to get signature")
}

func TestSignerStore_GetSignature_MalformedRecord(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	opts := &SignerOpts{KeyAttributes: &types.KeyAttributes{CN: "malformed-sig"}}
	putSignatureEntry(t, backend, "malformed-sig.sig", "not a valid record")

	digest, signature, err := store.GetSignature(opts)
	require.Error(t, err)
	assert.Nil(t, digest)
	assert.Nil(t, signature)
	var parseErr *ErrSignatureParse
	assert.ErrorAs(t, err, &parseErr)
	assert.ErrorIs(t, err, ErrMalformedSignatureData)
}

func TestSignerStore_Checksum(t *testing.T) {
	logger := testLogger()
	backend := storage.NewMemory()
	store := NewSignerStore(logger, backend)

	t.Run("returns the persisted digest for BlobCN", func(t *testing.T) {
		saveOpts := &SignerOpts{
			KeyAttributes: &types.KeyAttributes{CN: "checksum-key"},
			BlobCN:        "checksum-blob",
		}
		wantDigest := []byte("checksum digest")
		require.NoError(t, store.SaveSignature(saveOpts, []byte("sig"), wantDigest))

		checksum, err := store.Checksum(&types.VerifyOpts{
			KeyAttributes: saveOpts.KeyAttributes,
			BlobCN:        saveOpts.BlobCN,
		})
		require.NoError(t, err)
		assert.Equal(t, wantDigest, checksum)
	})

	t.Run("no record returns a typed error, not a pass", func(t *testing.T) {
		checksum, err := store.Checksum(&types.VerifyOpts{
			KeyAttributes: &types.KeyAttributes{CN: "checksum-key"},
			BlobCN:        "never-signed-blob",
		})
		require.Error(t, err)
		assert.Nil(t, checksum)
		var notFound *ErrSignatureNotFound
		assert.ErrorAs(t, err, &notFound)
	})

	t.Run("nil opts returns error", func(t *testing.T) {
		_, err := store.Checksum(nil)
		assert.Equal(t, ErrInvalidSignerOpts, err)
	})

	t.Run("nil key attributes returns error", func(t *testing.T) {
		_, err := store.Checksum(&types.VerifyOpts{})
		assert.Equal(t, ErrInvalidSignerOpts, err)
	})
}

// Compile-time check that SignerStore satisfies types.ChecksumProvider, so it
// can be used directly as a types.SimpleVerifier's checksum source.
var _ types.ChecksumProvider = (*SignerStore)(nil)

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

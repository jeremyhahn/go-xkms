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
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger creates a logger for testing.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestStore returns a SignerStore over an in-memory go-qrdb store.
func newTestStore(t *testing.T, logger *slog.Logger) *SignerStore {
	t.Helper()
	store, err := NewSignerStore(logger, dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore()))
	require.NoError(t, err)
	return store
}

// failingKV is an in-memory KVStore whose reads, writes or deletes fail with
// the configured error, so the store's error wrapping can be observed.
type failingKV struct {
	qrdbsdk.KVStore
	getErr    error
	putErr    error
	deleteErr error
}

func (f failingKV) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.KVStore.Get(ctx, key)
}

func (f failingKV) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.KVStore.Put(ctx, key, value)
}

func (f failingKV) Delete(ctx context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.KVStore.Delete(ctx, key)
}

// newFailingStore returns a SignerStore over kv, backed by a fresh in-memory
// store.
func newFailingStore(t *testing.T, kv failingKV) *SignerStore {
	t.Helper()
	if kv.KVStore == nil {
		kv.KVStore = qrdbsdk.NewMemoryKVStore()
	}
	store, err := NewSignerStore(testLogger(), dao.NewStoreFactory(kv))
	require.NoError(t, err)
	return store
}

// putSignerEntry saves a SignerEntry through the store's DAO, bypassing Save,
// to inject entries with alternative PEM formats (PKCS1, EC) and test the
// parsing fallback paths.
func putSignerEntry(t *testing.T, store *SignerStore, cn string, pemData []byte, algo string) {
	t.Helper()
	entry := &SignerEntry{CN: cn, KeyPEM: pemData, Algorithm: algo}
	require.NoError(t, store.dao.Save(context.Background(), entry))
}

// putSignatureEntry saves a SignatureEntry with an arbitrary Data payload
// through the store's DAO, to inject a malformed record SaveSignature itself
// can never produce.
func putSignatureEntry(t *testing.T, store *SignerStore, sigKey, data string) {
	t.Helper()
	entry := &SignatureEntry{Key: sigKey, Data: data}
	require.NoError(t, store.sigDAO.Save(context.Background(), entry))
}

// getSignatureData reads the Data field of the SignatureEntry stored under
// sigKey through the store's DAO.
func getSignatureData(t *testing.T, store *SignerStore, sigKey string) string {
	t.Helper()
	entry, err := store.sigDAO.GetByNaturalKey(context.Background(), sigKey)
	require.NoError(t, err)
	return entry.Data
}

// =============================================================================
// SignerStore Tests
// =============================================================================

// A signer saved through one store reads back through a second store over the
// same go-qrdb store: the records persist, keyed by CN.
func TestSignerStore_PersistsAcrossStores(t *testing.T) {
	daos := dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore())
	first, err := NewSignerStore(testLogger(), daos)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "persisted", KeyAlgorithm: x509.ECDSA}
	require.NoError(t, first.Save(attrs, key))
	require.NoError(t, first.SaveSignature(&SignerOpts{KeyAttributes: attrs}, []byte("sig"), []byte("digest")))

	second, err := NewSignerStore(testLogger(), daos)
	require.NoError(t, err)
	got, err := second.Get(attrs)
	require.NoError(t, err)
	assert.True(t, key.Equal(got))
	digest, signature, err := second.GetSignature(&SignerOpts{KeyAttributes: attrs})
	require.NoError(t, err)
	assert.Equal(t, []byte("digest"), digest)
	assert.Equal(t, []byte("sig"), signature)
}

// Without a DAO factory, or with one that serves no store, there is no store.
func TestNewSignerStore_Refusals(t *testing.T) {
	store, err := NewSignerStore(testLogger(), nil)
	assert.ErrorIs(t, err, ErrNilDAOFactory)
	assert.Nil(t, store)

	store, err = NewSignerStore(testLogger(), dao.NewStoreFactory(nil))
	var openErr *StoreOpenError
	require.ErrorAs(t, err, &openErr)
	assert.Contains(t, err.Error(), DatabaseName)
	var unavailable *dao.DatabaseUnavailableError
	assert.ErrorAs(t, err, &unavailable, "the cause must stay reachable")
	assert.Nil(t, store)
}

func TestSignerStore_SaveAndGet_RSA(t *testing.T) {
	logger := testLogger()
	store := newTestStore(t, logger)

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
		putSignerEntry(t, store, attrs.CN, pemData, "RSA")

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
	store := newTestStore(t, logger)

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
		putSignerEntry(t, store, attrs.CN, pemData, "ECDSA")

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
	store := newTestStore(t, logger)

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
	store := newTestStore(t, logger)

	t.Run("save nil signer returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "nil-signer",
			KeyAlgorithm: x509.RSA,
		}

		err := store.Save(attrs, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signer is nil")
		assert.Contains(t, err.Error(), attrs.CN)
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
		assert.Contains(t, err.Error(), attrs.CN)
	})
}

func TestSignerStore_Get_ErrorCases(t *testing.T) {
	logger := testLogger()
	store := newTestStore(t, logger)

	t.Run("get non-existent signer returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "non-existent-signer",
			KeyAlgorithm: x509.RSA,
		}

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		var notFound *ErrSignerNotFound
		assert.ErrorAs(t, err, &notFound)
		assert.Contains(t, err.Error(), "signer not found")
		assert.Contains(t, err.Error(), attrs.CN)
	})

	t.Run("get with invalid PEM returns error", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:           "invalid-pem",
			KeyAlgorithm: x509.RSA,
		}

		// Inject a DAO entry with invalid PEM data.
		putSignerEntry(t, store, attrs.CN, []byte("not valid pem"), "RSA")

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		var pemErr *ErrSignerPEMDecode
		require.ErrorAs(t, err, &pemErr)
		assert.Contains(t, err.Error(), "decode PEM")
		assert.Contains(t, err.Error(), attrs.CN)
		assert.NotNil(t, errors.Unwrap(pemErr), "the cause must stay reachable")
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
		putSignerEntry(t, store, attrs.CN, pemData, "RSA")

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		var parseErr *ErrSignerKeyParse
		require.ErrorAs(t, err, &parseErr)
		assert.Contains(t, err.Error(), "parse RSA")
		assert.Contains(t, err.Error(), attrs.CN)
		assert.Contains(t, err.Error(), "pkcs8:", "both parse failures are reported")
		assert.NotNil(t, errors.Unwrap(parseErr), "the cause must stay reachable")
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
		putSignerEntry(t, store, attrs.CN, pemData, "ECDSA")

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
		putSignerEntry(t, store, attrs.CN, pemData, "Ed25519")

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "parse Ed25519")
		assert.NotContains(t, err.Error(), "pkcs8:", "Ed25519 has no fallback parse")
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
		putSignerEntry(t, store, attrs.CN, pemData, "DSA")

		signer, err := store.Get(attrs)
		assert.Error(t, err)
		assert.Nil(t, signer)
		assert.Contains(t, err.Error(), "unsupported key algorithm")
		assert.Contains(t, err.Error(), attrs.CN)
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
		var mismatch *ErrSignerKeyTypeMismatch
		assert.ErrorAs(t, err, &mismatch)
		assert.Contains(t, err.Error(), "not an ECDSA private key")
		assert.Contains(t, err.Error(), attrs.CN)
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
		var mismatch *ErrSignerKeyTypeMismatch
		assert.ErrorAs(t, err, &mismatch)
		assert.Contains(t, err.Error(), "not an RSA private key")
		assert.Contains(t, err.Error(), attrs.CN)
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
		var mismatch *ErrSignerKeyTypeMismatch
		assert.ErrorAs(t, err, &mismatch)
		assert.Contains(t, err.Error(), "not an Ed25519 private key")
		assert.Contains(t, err.Error(), attrs.CN)
	})
}

func TestSignerStore_Delete(t *testing.T) {
	logger := testLogger()
	store := newTestStore(t, logger)

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
	store := newTestStore(t, logger)

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
		data := getSignatureData(t, store, sigKey)
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
		data := getSignatureData(t, store, sigKey)
		assert.Contains(t, data, "digest=")
		assert.Contains(t, data, "signature=")
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
	store := newTestStore(t, logger)

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
	store := newFailingStore(t, failingKV{getErr: errors.New("get failed")})

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
	store := newTestStore(t, logger)

	opts := &SignerOpts{KeyAttributes: &types.KeyAttributes{CN: "malformed-sig"}}
	putSignatureEntry(t, store, "malformed-sig.sig", "not a valid record")

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
	store := newTestStore(t, logger)

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
	store := newTestStore(t, logger)

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
	store := newTestStore(t, logger)

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
		assert.Contains(t, err.Error(), attrs.CN)
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
		assert.Contains(t, err.Error(), attrs.CN)
	})
}

func TestSignerStore_SavePutError(t *testing.T) {
	store := newFailingStore(t, failingKV{putErr: errors.New("put failed")})

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "save-error-key",
		KeyAlgorithm: x509.RSA,
	}

	err = store.Save(attrs, rsaKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save signer")
	assert.Contains(t, err.Error(), attrs.CN)
	assert.NotNil(t, errors.Unwrap(err), "the cause must stay reachable")
}

func TestSignerStore_SaveSignaturePutError(t *testing.T) {
	store := newFailingStore(t, failingKV{putErr: errors.New("put failed")})

	opts := &SignerOpts{
		KeyAttributes: &types.KeyAttributes{
			CN: "sig-error-key",
		},
	}

	err := store.SaveSignature(opts, []byte("sig"), []byte("digest"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save signature")
	assert.Contains(t, err.Error(), "sig-error-key.sig")
	assert.NotNil(t, errors.Unwrap(err), "the cause must stay reachable")
}

func TestSignerStore_DeleteError(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:           "delete-error-signer",
		KeyAlgorithm: x509.RSA,
	}

	// Seed the signer through a store with full KV support, then delete it
	// through one whose Delete fails over the same data.
	mem := qrdbsdk.NewMemoryKVStore()
	seed, err := NewSignerStore(testLogger(), dao.NewStoreFactory(mem))
	require.NoError(t, err)
	putSignerEntry(t, seed, attrs.CN, []byte("pem"), "RSA")

	cause := errors.New("delete failed")
	store := newFailingStore(t, failingKV{KVStore: mem, deleteErr: cause})

	err = store.Delete(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete signer")
	assert.Contains(t, err.Error(), attrs.CN)
	assert.ErrorIs(t, err, cause)
}

func TestSignerStore_GetError(t *testing.T) {
	// Return a non-ErrNotFound error
	cause := errors.New("get failed")
	store := newFailingStore(t, failingKV{getErr: cause})

	attrs := &types.KeyAttributes{
		CN:           "get-error-signer",
		KeyAlgorithm: x509.RSA,
	}

	signer, err := store.Get(attrs)
	assert.Error(t, err)
	assert.Nil(t, signer)
	assert.Contains(t, err.Error(), "failed to get signer")
	assert.Contains(t, err.Error(), attrs.CN)
	assert.ErrorIs(t, err, cause)
}

// =============================================================================
// Additional Edge Cases
// =============================================================================
func TestSignerStore_NilLogger(t *testing.T) {
	store := newTestStore(t, nil)

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

	// Deleting it again takes the not-found branch, also with nil logger
	err = store.Delete(attrs)
	assert.NoError(t, err)
}

//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package frost

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// mustKeyStore builds a KeyStore over daos, failing the test on error.
func mustKeyStore(t *testing.T, daos *qrdbsdk.DAOFactory, secretBackend types.SealingKeyProvider, attrs *types.KeyAttributes) *KeyStore {
	t.Helper()
	ks, err := NewKeyStore(daos, secretBackend, attrs)
	require.NoError(t, err)
	return ks
}

// testKeyPackage returns a 2-of-2 package for participant 1 and its metadata.
func testKeyPackage(keyID string) (*KeyPackage, *KeyMetadata) {
	pkg := &KeyPackage{
		ParticipantID:  1,
		SecretShare:    &SecretKeyShare{Value: []byte{1, 2, 3, 4, 5}},
		GroupPublicKey: []byte{10, 20, 30, 40, 50},
		VerificationShares: map[uint32][]byte{
			1: {100, 101, 102},
			2: {200, 201, 202},
		},
		MinSigners: 2,
		MaxSigners: 2,
		Algorithm:  types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{
		KeyID:         keyID,
		Algorithm:     types.FrostAlgorithmEd25519,
		Threshold:     2,
		Total:         2,
		ParticipantID: 1,
		CreatedAt:     1234567890,
	}
	return pkg, metadata
}

// storeTestKey stores testKeyPackage(keyID) through ks.
func storeTestKey(t *testing.T, ks *KeyStore, keyID string) {
	t.Helper()
	pkg, metadata := testKeyPackage(keyID)
	require.NoError(t, ks.StoreKeyPackage(context.Background(), keyID, pkg, metadata))
}

func requireStoreError(t *testing.T, err error, op string) {
	t.Helper()
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, op, storeErr.Op)
	assert.ErrorIs(t, err, errInjected)
}

func TestNewKeyStore(t *testing.T) {
	secretBackend := newMockSecretBackend()

	ks, err := NewKeyStore(testutil.NewMemoryDAOFactory(), secretBackend, nil)
	require.NoError(t, err)
	assert.NotNil(t, ks.keys)
	assert.NotNil(t, ks.shares)
	assert.NotNil(t, ks.secrets)
	assert.Equal(t, secretBackend, ks.secretBackend)
}

func TestNewKeyStore_NilFactory(t *testing.T) {
	ks, err := NewKeyStore(nil, newMockSecretBackend(), nil)
	assert.Nil(t, ks)
	assert.ErrorIs(t, err, ErrNilDAOFactory)
}

func TestKeyStore_StoreAndLoadKeyPackage(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	pkg, metadata := testKeyPackage("test-key")

	require.NoError(t, ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata))

	loadedPkg, loadedMeta, err := ks.LoadKeyPackage(context.Background(), "test-key", 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), loadedPkg.ParticipantID)
	assert.Equal(t, pkg.SecretShare.Value, loadedPkg.SecretShare.Value)
	assert.Equal(t, pkg.GroupPublicKey, loadedPkg.GroupPublicKey)
	assert.Equal(t, pkg.VerificationShares, loadedPkg.VerificationShares)
	assert.Equal(t, uint32(2), loadedPkg.MinSigners)
	assert.Equal(t, uint32(2), loadedPkg.MaxSigners)
	assert.Equal(t, types.FrostAlgorithmEd25519, loadedPkg.Algorithm)
	assert.Equal(t, *metadata, *loadedMeta)
}

// TestKeyStore_StoreKeyPackage_SecretShareStoredSealed proves the secret
// share entity holds only the secret backend's sealed envelope.
func TestKeyStore_StoreKeyPackage_SecretShareStoredSealed(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")

	secret, err := ks.secrets.GetByNaturalKey(context.Background(), shareName("test-key", 1))
	require.NoError(t, err)
	assert.Equal(t, "test-key", secret.KeyID)
	assert.Equal(t, uint32(1), secret.Index)
	assert.Equal(t, types.BackendTypeSoftware, secret.Sealed.Backend)
	assert.Equal(t, append([]byte("mock-sealed:"), 1, 2, 3, 4, 5), secret.Sealed.Ciphertext)
}

func TestKeyStore_StoreKeyPackage_CannotSeal(t *testing.T) {
	secretBackend := newMockSecretBackend()
	secretBackend.canSeal = false
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), secretBackend, nil)
	pkg, metadata := testKeyPackage("test-key")

	err := ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata)
	var configErr *ConfigError
	require.ErrorAs(t, err, &configErr)
	assert.Equal(t, "SecretBackend", configErr.Field)
}

func TestKeyStore_StoreKeyPackage_SealFailure_StoresNothing(t *testing.T) {
	secretBackend := newMockSecretBackend()
	secretBackend.sealErr = errMockSealed
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), secretBackend, nil)
	pkg, metadata := testKeyPackage("test-key")

	err := ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata)
	var wrapped *errs.Wrapped
	require.ErrorAs(t, err, &wrapped)
	assert.ErrorIs(t, err, errMockSealed)

	exists, err := ks.KeyExists(context.Background(), "test-key")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestKeyStore_StoreKeyPackage_SaveKeyFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	kv.failOn(failPut, keyEntityType)
	pkg, metadata := testKeyPackage("test-key")

	err := ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata)
	requireStoreError(t, err, "save key")
}

func TestKeyStore_StoreKeyPackage_SaveVerificationShareFailure_CleansUp(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	kv.failOn(failPut, shareEntityType)
	pkg, metadata := testKeyPackage("test-key")

	err := ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata)
	requireStoreError(t, err, "save verification share")

	exists, err := ks.KeyExists(context.Background(), "test-key")
	require.NoError(t, err)
	assert.False(t, exists, "a failed store must not leave the key behind")
}

func TestKeyStore_StoreKeyPackage_SaveSecretShareFailure_CleansUp(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	kv.failOn(failPut, secretShareEntityType)
	pkg, metadata := testKeyPackage("test-key")

	err := ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata)
	requireStoreError(t, err, "save secret share")

	exists, err := ks.KeyExists(context.Background(), "test-key")
	require.NoError(t, err)
	assert.False(t, exists, "a failed store must not leave the key behind")
	for index := uint32(1); index <= 2; index++ {
		_, err := ks.shares.GetByNaturalKey(context.Background(), shareName("test-key", index))
		assert.True(t, qrdbsdk.IsDAONotFound(err), "verification share %d must be cleaned up", index)
	}
}

func TestKeyStore_LoadKeyPackage_UseMetadataParticipantID(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	pkg, metadata := testKeyPackage("test-key")
	pkg.ParticipantID = 2
	metadata.ParticipantID = 2
	require.NoError(t, ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata))

	loadedPkg, _, err := ks.LoadKeyPackage(context.Background(), "test-key", 0)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), loadedPkg.ParticipantID)
	assert.Equal(t, pkg.SecretShare.Value, loadedPkg.SecretShare.Value)
}

func TestKeyStore_LoadKeyPackage_NotFound(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)

	pkg, meta, err := ks.LoadKeyPackage(context.Background(), "nonexistent", 1)
	assert.Nil(t, pkg)
	assert.Nil(t, meta)
	var notFound *KeyNotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "nonexistent", notFound.KeyID)
}

func TestKeyStore_LoadKeyPackage_CannotSeal(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	storeTestKey(t, mustKeyStore(t, daos, newMockSecretBackend(), nil), "test-key")

	noSeal := newMockSecretBackend()
	noSeal.canSeal = false
	_, _, err := mustKeyStore(t, daos, noSeal, nil).LoadKeyPackage(context.Background(), "test-key", 1)
	var configErr *ConfigError
	require.ErrorAs(t, err, &configErr)
	assert.Equal(t, "SecretBackend", configErr.Field)
}

func TestKeyStore_LoadKeyPackage_LoadSecretShareFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")
	kv.failOn(failGet, secretShareEntityType)

	_, _, err := ks.LoadKeyPackage(context.Background(), "test-key", 1)
	requireStoreError(t, err, "load secret share")
}

func TestKeyStore_LoadKeyPackage_MissingSecretShare(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")
	require.NoError(t, deleteByName(context.Background(), ks.secrets, shareName("test-key", 1)))

	_, _, err := ks.LoadKeyPackage(context.Background(), "test-key", 1)
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "load secret share", storeErr.Op)
	assert.True(t, qrdbsdk.IsDAONotFound(err))
}

func TestKeyStore_LoadKeyPackage_UnsealFailure(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	storeTestKey(t, mustKeyStore(t, daos, newMockSecretBackend(), nil), "test-key")

	failing := newMockSecretBackend()
	failing.unsealErr = errMockSealed
	_, _, err := mustKeyStore(t, daos, failing, nil).LoadKeyPackage(context.Background(), "test-key", 1)
	var wrapped *errs.Wrapped
	require.ErrorAs(t, err, &wrapped)
	assert.ErrorIs(t, err, errMockSealed)
}

func TestKeyStore_LoadPublicKeyPackage(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	pkg, _ := testKeyPackage("test-key")
	storeTestKey(t, ks, "test-key")

	public, meta, err := ks.LoadPublicKeyPackage(context.Background(), "test-key")
	require.NoError(t, err)
	assert.Equal(t, pkg.GroupPublicKey, public.GroupPublicKey)
	assert.Equal(t, pkg.VerificationShares, public.VerificationShares)
	assert.Equal(t, uint32(2), public.MinSigners)
	assert.Equal(t, uint32(2), public.MaxSigners)
	assert.Equal(t, "test-key", meta.KeyID)
}

func TestKeyStore_LoadPublicKeyPackage_NotFound(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)

	_, _, err := ks.LoadPublicKeyPackage(context.Background(), "nonexistent")
	var notFound *KeyNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

func TestKeyStore_LoadPublicKeyPackage_LoadKeyFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")
	kv.failOn(failGet, keyEntityType)

	_, _, err := ks.LoadPublicKeyPackage(context.Background(), "test-key")
	requireStoreError(t, err, "load key")
}

func TestKeyStore_LoadPublicKeyPackage_LoadShareFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")
	kv.failOn(failGet, shareEntityType)

	_, _, err := ks.LoadPublicKeyPackage(context.Background(), "test-key")
	requireStoreError(t, err, "load verification share")
}

// TestKeyStore_LoadPublicKeyPackage_ThresholdSharesSuffice proves a key
// stored with only threshold verification shares (as go-frost may return)
// still loads.
func TestKeyStore_LoadPublicKeyPackage_ThresholdSharesSuffice(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	pkg, metadata := testKeyPackage("test-key")
	metadata.Total = 3
	require.NoError(t, ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata))

	public, _, err := ks.LoadPublicKeyPackage(context.Background(), "test-key")
	require.NoError(t, err)
	assert.Len(t, public.VerificationShares, 2)
}

func TestKeyStore_LoadPublicKeyPackage_InsufficientVerificationShares(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	pkg, metadata := testKeyPackage("test-key")
	delete(pkg.VerificationShares, 2)
	require.NoError(t, ks.StoreKeyPackage(context.Background(), "test-key", pkg, metadata))

	_, _, err := ks.LoadPublicKeyPackage(context.Background(), "test-key")
	var msg *errs.Message
	require.ErrorAs(t, err, &msg)
	assert.Contains(t, err.Error(), "insufficient verification shares")
}

func TestKeyStore_DeleteKey(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")
	storeTestKey(t, ks, "other-key")

	require.NoError(t, ks.DeleteKey(context.Background(), "test-key"))

	exists, err := ks.KeyExists(context.Background(), "test-key")
	require.NoError(t, err)
	assert.False(t, exists)
	_, err = ks.secrets.GetByNaturalKey(context.Background(), shareName("test-key", 1))
	assert.True(t, qrdbsdk.IsDAONotFound(err), "the sealed secret share must be deleted")
	for index := uint32(1); index <= 2; index++ {
		_, err := ks.shares.GetByNaturalKey(context.Background(), shareName("test-key", index))
		assert.True(t, qrdbsdk.IsDAONotFound(err), "verification share %d must be deleted", index)
	}

	_, _, err = ks.LoadKeyPackage(context.Background(), "other-key", 1)
	assert.NoError(t, err, "deleting one key must not touch another")
}

func TestKeyStore_DeleteKey_NotFound(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)

	err := ks.DeleteKey(context.Background(), "nonexistent")
	var notFound *KeyNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

// TestKeyStore_DeleteKey_SecretShareFailure_LeavesKeyForRetry proves the key
// record outlives a failed secret-share delete, so a retry can find and
// finish the deletion.
func TestKeyStore_DeleteKey_SecretShareFailure_LeavesKeyForRetry(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")
	kv.failOn(failDelete, secretShareEntityType)

	err := ks.DeleteKey(context.Background(), "test-key")
	requireStoreError(t, err, "delete secret share")

	exists, err := ks.KeyExists(context.Background(), "test-key")
	require.NoError(t, err)
	assert.True(t, exists)

	kv.failOn("", "")
	require.NoError(t, ks.DeleteKey(context.Background(), "test-key"))
	exists, err = ks.KeyExists(context.Background(), "test-key")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestKeyStore_DeleteKey_VerificationShareFailure_LeavesKeyForRetry(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")
	kv.failOn(failDelete, shareEntityType)

	err := ks.DeleteKey(context.Background(), "test-key")
	requireStoreError(t, err, "delete verification share")

	exists, err := ks.KeyExists(context.Background(), "test-key")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestKeyStore_DeleteKey_KeyRecordFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")
	kv.failOn(failDelete, keyEntityType)

	err := ks.DeleteKey(context.Background(), "test-key")
	requireStoreError(t, err, "delete key")
}

func TestKeyStore_KeyExists(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	storeTestKey(t, ks, "test-key")

	exists, err := ks.KeyExists(context.Background(), "test-key")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = ks.KeyExists(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestKeyStore_KeyExists_StoreFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	kv.failOn(failGet, keyEntityType)

	exists, err := ks.KeyExists(context.Background(), "test-key")
	assert.False(t, exists)
	requireStoreError(t, err, "load key")
}

func TestKeyStore_ListKeys(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)

	keys, err := ks.ListKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)

	storeTestKey(t, ks, "key-a")
	storeTestKey(t, ks, "key-b")

	keys, err = ks.ListKeys(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"key-a", "key-b"}, keys)
}

func TestKeyStore_ListKeys_StoreFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "key-a")
	kv.failOn(failScan, keyEntityType)

	keys, err := ks.ListKeys(context.Background())
	assert.Nil(t, keys)
	requireStoreError(t, err, "list")
}

func TestKeyStore_ListKeysWithMetadata(t *testing.T) {
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), newMockSecretBackend(), nil)
	storeTestKey(t, ks, "key-a")
	storeTestKey(t, ks, "key-b")

	metadata, err := ks.ListKeysWithMetadata(context.Background())
	require.NoError(t, err)
	require.Len(t, metadata, 2)
	keyIDs := []string{metadata[0].KeyID, metadata[1].KeyID}
	assert.ElementsMatch(t, []string{"key-a", "key-b"}, keyIDs)
	assert.Equal(t, 2, metadata[0].Threshold)
	assert.Equal(t, types.FrostAlgorithmEd25519, metadata[1].Algorithm)
}

func TestKeyStore_ListKeysWithMetadata_StoreFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	ks := mustKeyStore(t, daos, newMockSecretBackend(), nil)
	storeTestKey(t, ks, "key-a")
	kv.failOn(failScan, keyEntityType)

	metadata, err := ks.ListKeysWithMetadata(context.Background())
	assert.Nil(t, metadata)
	requireStoreError(t, err, "list")
}

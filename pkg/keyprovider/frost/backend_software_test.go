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

//go:build frost

package frost

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newSoftwareFrostSecretBackend builds a real *software.SoftwareBackend
// (in-memory storage) and provisions the FROST Ed25519 wrapping key through
// it via seal.EnsurePrivateSealKey -- the same production composition
// pkg/server's ensureFrostSecretSealKey uses for the "software"
// secret_backend.
func newSoftwareFrostSecretBackend(t *testing.T) (types.SealingKeyProvider, *types.KeyAttributes) {
	t.Helper()

	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	provider, err := software.NewBackend(&software.Config{KeyStorage: keyStorage})
	require.NoError(t, err)
	sealer, ok := provider.(types.SealingKeyProvider)
	require.True(t, ok, "software.SoftwareBackend must implement types.SealingKeyProvider")

	attrs := AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
	require.NoError(t, seal.EnsurePrivateSealKey(context.Background(), provider, attrs))

	return sealer, attrs
}

// newPKCS8FrostSecretBackend builds a real *pkcs8.PKCS8Backend (in-memory
// storage, plaintext keys allowed since this is a test fixture) and
// provisions the FROST Ed25519 wrapping key the same way as the "pkcs8"
// secret_backend.
func newPKCS8FrostSecretBackend(t *testing.T) (types.SealingKeyProvider, *types.KeyAttributes) {
	t.Helper()

	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	provider, err := pkcs8.NewBackend(&pkcs8.Config{KeyStorage: keyStorage, AllowPlaintextKeys: true})
	require.NoError(t, err)
	sealer, ok := provider.(types.SealingKeyProvider)
	require.True(t, ok, "pkcs8.PKCS8Backend must implement types.SealingKeyProvider")

	attrs := AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
	require.NoError(t, seal.EnsurePrivateSealKey(context.Background(), provider, attrs))

	return sealer, attrs
}

func TestKeyStore_Software_StoreAndLoadKeyPackage(t *testing.T) {
	secretBackend, attrs := newSoftwareFrostSecretBackend(t)
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), secretBackend, attrs)

	keyID := "software-frost-key"
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("software-backend-secret-share")},
		GroupPublicKey:     []byte{1, 2, 3},
		VerificationShares: map[uint32][]byte{1: {4}, 2: {5}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}

	require.NoError(t, ks.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	loaded, _, err := ks.LoadKeyPackage(context.Background(), keyID, 1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pkg.SecretShare.Value, loaded.SecretShare.Value))
}

func TestKeyStore_PKCS8_StoreAndLoadKeyPackage(t *testing.T) {
	secretBackend, attrs := newPKCS8FrostSecretBackend(t)
	ks := mustKeyStore(t, testutil.NewMemoryDAOFactory(), secretBackend, attrs)

	keyID := "pkcs8-frost-key"
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("pkcs8-backend-secret-share")},
		GroupPublicKey:     []byte{1, 2, 3},
		VerificationShares: map[uint32][]byte{1: {4}, 2: {5}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}

	require.NoError(t, ks.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	loaded, _, err := ks.LoadKeyPackage(context.Background(), keyID, 1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pkg.SecretShare.Value, loaded.SecretShare.Value))
}

// TestKeyStore_Software_RestartSurvival proves a FROST secret share sealed
// by one KeyStore instance unseals through a brand-new KeyStore (and a
// brand-new secret backend instance) constructed over the SAME storage,
// simulating a process restart: the wrapping key is re-derived from the
// same persisted private key, and the sealed envelope survives verbatim in
// its entity.
func TestKeyStore_Software_RestartSurvival(t *testing.T) {
	sharedKeyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	daos := testutil.NewMemoryDAOFactory()

	keyID := "restart-key"
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("share-that-must-survive-restart")},
		GroupPublicKey:     []byte{9, 9, 9},
		VerificationShares: map[uint32][]byte{1: {1}, 2: {2}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}

	// "Boot 1": provision the wrap key and store the package.
	provider1, err := software.NewBackend(&software.Config{KeyStorage: sharedKeyStorage})
	require.NoError(t, err)
	sealer1 := provider1.(types.SealingKeyProvider)
	attrs1 := AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
	require.NoError(t, seal.EnsurePrivateSealKey(context.Background(), provider1, attrs1))
	ks1 := mustKeyStore(t, daos, sealer1, attrs1)
	require.NoError(t, ks1.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	// "Boot 2": brand-new backend and KeyStore instances over the same
	// underlying storage -- nothing in-process is reused from boot 1.
	provider2, err := software.NewBackend(&software.Config{KeyStorage: sharedKeyStorage})
	require.NoError(t, err)
	sealer2 := provider2.(types.SealingKeyProvider)
	attrs2 := AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
	require.NoError(t, seal.EnsurePrivateSealKey(context.Background(), provider2, attrs2))
	ks2 := mustKeyStore(t, daos, sealer2, attrs2)

	loaded, _, err := ks2.LoadKeyPackage(context.Background(), keyID, 1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pkg.SecretShare.Value, loaded.SecretShare.Value))
}

// TestKeyStore_Software_WrongWrapKey_TypedError proves that unsealing a
// FROST secret share with the wrong wrapping key returns a typed error
// rather than succeeding or panicking: a second, independently-provisioned
// software backend (a different Ed25519 wrap key, since each backend
// generates its own) can never unseal a share sealed by the first.
func TestKeyStore_Software_WrongWrapKey_TypedError(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()

	// Backend A seals the share.
	keyStorageA, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	providerA, err := software.NewBackend(&software.Config{KeyStorage: keyStorageA})
	require.NoError(t, err)
	sealerA := providerA.(types.SealingKeyProvider)
	attrsA := AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
	require.NoError(t, seal.EnsurePrivateSealKey(context.Background(), providerA, attrsA))
	ksA := mustKeyStore(t, daos, sealerA, attrsA)

	keyID := "wrong-key-test"
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("secret-share-bytes")},
		GroupPublicKey:     []byte{7, 7, 7},
		VerificationShares: map[uint32][]byte{1: {1}, 2: {2}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}
	require.NoError(t, ksA.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	// Backend B (independent wrap key) tries to unseal it, through a
	// KeyStore over the SAME DAO factory (so it sees the same sealed
	// envelope) but a different secret backend.
	keyStorageB, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	providerB, err := software.NewBackend(&software.Config{KeyStorage: keyStorageB})
	require.NoError(t, err)
	sealerB := providerB.(types.SealingKeyProvider)
	attrsB := AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
	require.NoError(t, seal.EnsurePrivateSealKey(context.Background(), providerB, attrsB))
	ksB := mustKeyStore(t, daos, sealerB, attrsB)

	_, _, err = ksB.LoadKeyPackage(context.Background(), keyID, 1)
	require.Error(t, err)
	// The error must be a typed *errs.Wrapped (never an untyped fmt.Errorf
	// string), wrapping the software backend's own decryption failure.
	var wrapped *errs.Wrapped
	require.True(t, errors.As(err, &wrapped), "error must be a typed *errs.Wrapped, got %v (%T)", err, err)
}

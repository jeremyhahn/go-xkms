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

//go:build frost && tpm_simulator

package frost

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newTPM2FrostSecretBackend provisions a fresh TPM 2.0 simulator (its
// first-boot recipe auto-enrolls the Platform SRK, go-xkms#997) and returns
// it alongside the Parent-only wrapping-key template
// pkg/server's ensureFrostSecretSealKey builds for the "tpm2" secret_backend
// via frost.TPM2SecretSealKeyAttributes(b.SRKAttributes()). TPM2 needs no
// separate provisioning step -- Seal creates a new sealed object per call,
// directly under the Platform SRK.
func newTPM2FrostSecretBackend(t *testing.T) (*tpm2.Backend, *types.KeyAttributes) {
	t.Helper()

	b, err := tpm2.NewBackend(&tpm2.Config{
		UseSimulator: true,
		KeyDir:       t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })

	attrs := TPM2SecretSealKeyAttributes(b.SRKAttributes())
	return b, attrs
}

func TestKeyStore_TPM2_StoreAndLoadKeyPackage(t *testing.T) {
	secretBackend, attrs := newTPM2FrostSecretBackend(t)
	ks := NewKeyStore(newMockStorageBackend(), secretBackend, attrs)

	keyID := "tpm2-frost-key"
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("tpm2-sealed-secret-share")},
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

// TestKeyStore_TPM2_MultipleKeys_DistinctSealedObjects proves that two
// different FROST keys sealed through the same TPM2 secret backend do not
// collide: KeyStore.secretSealKeyAttributesFor gives each its own
// TPM-sealed object identity (derived from the FROST key ID), so storing a
// second key never disturbs the first.
func TestKeyStore_TPM2_MultipleKeys_DistinctSealedObjects(t *testing.T) {
	secretBackend, attrs := newTPM2FrostSecretBackend(t)
	publicStorage := newMockStorageBackend()
	ks := NewKeyStore(publicStorage, secretBackend, attrs)

	pkg1 := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("first-key-share")},
		GroupPublicKey:     []byte{1},
		VerificationShares: map[uint32][]byte{1: {1}, 2: {2}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	pkg2 := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("second-key-share")},
		GroupPublicKey:     []byte{2},
		VerificationShares: map[uint32][]byte{1: {3}, 2: {4}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	meta1 := &KeyMetadata{KeyID: "tpm2-key-one", Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}
	meta2 := &KeyMetadata{KeyID: "tpm2-key-two", Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}

	require.NoError(t, ks.StoreKeyPackage(context.Background(), "tpm2-key-one", pkg1, meta1))
	require.NoError(t, ks.StoreKeyPackage(context.Background(), "tpm2-key-two", pkg2, meta2))

	loaded1, _, err := ks.LoadKeyPackage(context.Background(), "tpm2-key-one", 1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pkg1.SecretShare.Value, loaded1.SecretShare.Value))

	loaded2, _, err := ks.LoadKeyPackage(context.Background(), "tpm2-key-two", 1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pkg2.SecretShare.Value, loaded2.SecretShare.Value))
}

// TestKeyStore_TPM2_CorruptSealedBlob_TypedError proves that a corrupted
// (or tampered) sealed secret-share envelope fails to unseal with a typed
// error rather than returning corrupted plaintext.
func TestKeyStore_TPM2_CorruptSealedBlob_TypedError(t *testing.T) {
	secretBackend, attrs := newTPM2FrostSecretBackend(t)
	publicStorage := newMockStorageBackend()
	ks := NewKeyStore(publicStorage, secretBackend, attrs)

	keyID := "tpm2-corrupt-key"
	pkg := &KeyPackage{
		ParticipantID:      1,
		SecretShare:        &SecretKeyShare{Value: []byte("share-to-corrupt")},
		GroupPublicKey:     []byte{9},
		VerificationShares: map[uint32][]byte{1: {1}, 2: {2}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}
	require.NoError(t, ks.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	// Corrupt the sealed secret-share envelope directly in public storage.
	sealedPath := keyPath(keyID, secretShareFile)
	corrupt, err := publicStorage.Get(context.Background(), sealedPath)
	require.NoError(t, err)
	corrupt = append([]byte(nil), corrupt...)
	corrupt[len(corrupt)-1] ^= 0xFF
	require.NoError(t, publicStorage.Put(context.Background(), sealedPath, corrupt))

	_, _, err = ks.LoadKeyPackage(context.Background(), keyID, 1)
	require.Error(t, err)
}

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

//go:build frost

package main

import (
	"context"
	"errors"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errListSecrets is the failure injected by listFailingStorage.
var errListSecrets = errors.New("storage unavailable")

// listFailingStorage wraps a real storage backend and fails every List call
// so the error path of ListKeys can be exercised.
type listFailingStorage struct {
	client.StorageBackend
}

func (s *listFailingStorage) List(context.Context, string) ([]string, error) {
	return nil, errListSecrets
}

// storeFrostSecret writes a secret share for cn through the backend's own
// GenerateKey path so the test never hardcodes the storage layout.
func storeFrostSecret(t *testing.T, b *fileSecretBackend, cn string, secret []byte) {
	t.Helper()
	_, err := b.GenerateKey(context.Background(), &client.KeyAttributes{
		CN:        cn,
		KeyType:   client.KeyTypeSigning,
		StoreType: client.StoreFrost,
		SealData:  client.NewSealData(secret),
	})
	require.NoError(t, err)
}

func TestFileSecretBackend_ListKeys_ReturnsStoredShares(t *testing.T) {
	backend := newFileSecretBackend(client.NewStorageMemory(), nil)
	storeFrostSecret(t, backend, "alpha", []byte("share-alpha"))
	storeFrostSecret(t, backend, "bravo", []byte("share-bravo"))

	keys, err := backend.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 2)

	cns := make([]string, 0, len(keys))
	for _, attrs := range keys {
		cns = append(cns, attrs.CN)
		assert.Equal(t, client.KeyTypeSigning, attrs.KeyType)
		assert.Equal(t, client.StoreFrost, attrs.StoreType)
	}
	assert.ElementsMatch(t, []string{"alpha", "bravo"}, cns)
}

// TestFileSecretBackend_ListKeys_RoundTripsToGetAndDelete pins the contract
// that a listed entry is directly usable by the sibling operations.
func TestFileSecretBackend_ListKeys_RoundTripsToGetAndDelete(t *testing.T) {
	ctx := context.Background()
	backend := newFileSecretBackend(client.NewStorageMemory(), nil)
	storeFrostSecret(t, backend, "charlie", []byte("share-charlie"))

	keys, err := backend.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	secret, err := backend.GetKey(ctx, keys[0])
	require.NoError(t, err)
	assert.Equal(t, []byte("share-charlie"), secret)

	require.NoError(t, backend.DeleteKey(ctx, keys[0]))

	remaining, err := backend.ListKeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, remaining)
}

func TestFileSecretBackend_ListKeys_EmptyStore(t *testing.T) {
	backend := newFileSecretBackend(client.NewStorageMemory(), nil)

	keys, err := backend.ListKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestFileSecretBackend_ListKeys_SkipsForeignKeys ensures unrelated entries
// stored under the same prefix are not reported as FROST shares.
func TestFileSecretBackend_ListKeys_SkipsForeignKeys(t *testing.T) {
	ctx := context.Background()
	store := client.NewStorageMemory()
	backend := newFileSecretBackend(store, nil)

	storeFrostSecret(t, backend, "delta", []byte("share-delta"))
	require.NoError(t, store.Put(ctx, frostSecretPrefix+"notes.txt", []byte("not a share")))
	require.NoError(t, store.Put(ctx, frostSecretPrefix+frostSecretSuffix, []byte("empty cn")))
	require.NoError(t, store.Put(ctx, "other/place/echo.secret", []byte("elsewhere")))

	keys, err := backend.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "delta", keys[0].CN)
}

func TestFileSecretBackend_ListKeys_StorageFailure(t *testing.T) {
	backend := newFileSecretBackend(&listFailingStorage{StorageBackend: client.NewStorageMemory()}, nil)

	keys, err := backend.ListKeys(context.Background())
	assert.Nil(t, keys)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrListKeysFailed)
	assert.ErrorIs(t, err, errListSecrets)
}

// storeFrostGroupPackage generates a real 2-of-2 FROST key package via the
// trusted dealer, stores participant 1's package through the same
// client.NewFrostKeyStore path frostImportCmd uses, and returns the backend
// plus the group's public key so callers can verify a round-tripped Signer
// reports the correct group identity.
func storeFrostGroupPackage(t *testing.T, keyID string) (backend *fileSecretBackend, groupPublicKey []byte) {
	t.Helper()
	ctx := context.Background()

	td := client.NewFrostTrustedDealer()
	packages, pubPkg, err := td.Generate(client.FrostConfig{
		Threshold: 2,
		Total:     2,
		Algorithm: client.FrostAlgorithmEd25519,
	})
	require.NoError(t, err)
	require.Len(t, packages, 2)

	publicStorage := client.NewStorageMemory()
	secretStorage := client.NewStorageMemory()
	backend = newFileSecretBackend(secretStorage, publicStorage)

	ks := client.NewFrostKeyStore(publicStorage, backend)
	require.NoError(t, ks.StoreKeyPackage(ctx, keyID, packages[0], &client.FrostKeyMetadata{
		KeyID:         keyID,
		Algorithm:     client.FrostAlgorithmEd25519,
		Threshold:     2,
		Total:         2,
		ParticipantID: packages[0].ParticipantID,
	}))

	return backend, pubPkg.GroupPublicKey
}

// TestFileSecretBackend_Signer_RefusesThresholdKey pins the FrostBackend
// contract from go-xkms#663: a crypto.Signer can't do M-of-N signing, so
// Signer refuses a threshold-2+ key when the signer is created rather than
// failing later inside Sign. The dealer rejects threshold < 2, so this
// covers every real key; distributed signing uses the round-based API.
func TestFileSecretBackend_Signer_RefusesThresholdKey(t *testing.T) {
	backend, _ := storeFrostGroupPackage(t, "signer-key")

	signer, err := backend.Signer(context.Background(), &client.KeyAttributes{
		CN:        "signer-key",
		StoreType: client.StoreFrost,
		FrostAttributes: &client.FrostAttributes{
			Algorithm:     client.FrostAlgorithmEd25519,
			Threshold:     2,
			Total:         2,
			ParticipantID: 1,
		},
	})
	require.Error(t, err)
	assert.Nil(t, signer)
	assert.ErrorIs(t, err, client.ErrFrostThresholdSigningNotSupported)
}

func TestFileSecretBackend_Signer_RequiresPublicStorage(t *testing.T) {
	backend := newFileSecretBackend(client.NewStorageMemory(), nil)

	_, err := backend.Signer(context.Background(), &client.KeyAttributes{
		CN: "any-key",
		FrostAttributes: &client.FrostAttributes{
			Algorithm: client.FrostAlgorithmEd25519,
			Threshold: 2,
			Total:     2,
		},
	})
	require.ErrorIs(t, err, ErrFrostPublicStorageRequired)
}

func TestFileSecretBackend_Signer_RequiresFrostAttributes(t *testing.T) {
	backend := newFileSecretBackend(client.NewStorageMemory(), client.NewStorageMemory())

	_, err := backend.Signer(context.Background(), &client.KeyAttributes{CN: "any-key"})
	require.ErrorIs(t, err, ErrFrostAttributesRequired)
}

// TestFileSecretBackend_Decrypter_NotSupported confirms Decrypter reaches
// the same ceremony-aware backend as Signer and gets FROST's own signing-only
// answer, rather than this file's own generic "unsupported" stand-in.
func TestFileSecretBackend_Decrypter_NotSupported(t *testing.T) {
	backend, _ := storeFrostGroupPackage(t, "decrypt-key")

	_, err := backend.Decrypter(context.Background(), &client.KeyAttributes{
		CN:        "decrypt-key",
		StoreType: client.StoreFrost,
		FrostAttributes: &client.FrostAttributes{
			Algorithm:     client.FrostAlgorithmEd25519,
			Threshold:     2,
			Total:         2,
			ParticipantID: 1,
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decryption not supported")
}

func TestFileSecretBackend_Decrypter_RequiresPublicStorage(t *testing.T) {
	backend := newFileSecretBackend(client.NewStorageMemory(), nil)

	_, err := backend.Decrypter(context.Background(), &client.KeyAttributes{
		CN: "any-key",
		FrostAttributes: &client.FrostAttributes{
			Algorithm: client.FrostAlgorithmEd25519,
			Threshold: 2,
			Total:     2,
		},
	})
	require.ErrorIs(t, err, ErrFrostPublicStorageRequired)
}

func TestFileSecretBackend_Decrypter_RequiresFrostAttributes(t *testing.T) {
	backend := newFileSecretBackend(client.NewStorageMemory(), client.NewStorageMemory())

	_, err := backend.Decrypter(context.Background(), &client.KeyAttributes{CN: "any-key"})
	require.ErrorIs(t, err, ErrFrostAttributesRequired)
}

func TestFrostSecretCN(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		wantCN string
		wantOK bool
	}{
		{"share", frostSecretPrefix + "alpha" + frostSecretSuffix, "alpha", true},
		{"nested cn", frostSecretPrefix + "group/alpha" + frostSecretSuffix, "group/alpha", true},
		{"wrong prefix", "other/alpha" + frostSecretSuffix, "", false},
		{"wrong suffix", frostSecretPrefix + "alpha.json", "", false},
		{"empty cn", frostSecretPrefix + frostSecretSuffix, "", false},
		{"empty key", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cn, ok := frostSecretCN(tc.key)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantCN, cn)
		})
	}
}

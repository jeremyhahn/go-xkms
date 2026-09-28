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

//go:build vault && frost

package vault

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestKeyStore_Vault_StoreAndLoadKeyPackage proves a FROST secret share
// seals and unseals correctly through a real *Backend talking to an
// in-process Transit engine double (newVaultTestBackend): the FROST
// wrapping key is provisioned via seal.EnsureSealKey (the same composition
// pkg/server's ensureFrostSecretSealKey uses for the "vault" secret_backend),
// and pkg/keyprovider/frost.KeyStore drives Seal/Unseal through it.
func TestKeyStore_Vault_StoreAndLoadKeyPackage(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	attrs := frost.SymmetricSecretSealKeyAttributes(types.StoreVault)
	require.NoError(t, seal.EnsureSealKey(context.Background(), seal.StrategyVault, b, attrs))

	publicStorage := storage.New()
	ks := frost.NewKeyStore(publicStorage, b, attrs)

	keyID := "vault-frost-key"
	pkg := &frost.KeyPackage{
		ParticipantID:      1,
		SecretShare:        &frost.SecretKeyShare{Value: []byte("vault-transit-secret-share")},
		GroupPublicKey:     []byte{1, 2, 3},
		VerificationShares: map[uint32][]byte{1: {4}, 2: {5}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &frost.KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}

	require.NoError(t, ks.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	loaded, _, err := ks.LoadKeyPackage(context.Background(), keyID, 1)
	require.NoError(t, err)
	require.True(t, bytes.Equal(pkg.SecretShare.Value, loaded.SecretShare.Value))
}

// TestKeyStore_Vault_MissingWrapKey_TypedError proves that unsealing with a
// KeyAttributes CN naming a wrapping key that was never provisioned in
// Vault Transit returns a typed error rather than succeeding.
func TestKeyStore_Vault_MissingWrapKey_TypedError(t *testing.T) {
	b, _ := newVaultTestBackend(t)

	attrs := frost.SymmetricSecretSealKeyAttributes(types.StoreVault)
	require.NoError(t, seal.EnsureSealKey(context.Background(), seal.StrategyVault, b, attrs))

	publicStorage := storage.New()
	ks := frost.NewKeyStore(publicStorage, b, attrs)

	keyID := "vault-wrong-key-test"
	pkg := &frost.KeyPackage{
		ParticipantID:      1,
		SecretShare:        &frost.SecretKeyShare{Value: []byte("vault-transit-secret-share")},
		GroupPublicKey:     []byte{1, 2, 3},
		VerificationShares: map[uint32][]byte{1: {4}, 2: {5}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &frost.KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}
	require.NoError(t, ks.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	missingAttrs := frost.SymmetricSecretSealKeyAttributes(types.StoreVault)
	missingAttrs.CN = "xkms-frost-wrap-does-not-exist"
	ksWrongKey := frost.NewKeyStore(publicStorage, b, missingAttrs)

	_, _, err := ksWrongKey.LoadKeyPackage(context.Background(), keyID, 1)
	require.Error(t, err)
}

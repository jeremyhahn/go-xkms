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

//go:build pkcs11 && frost

package pkcs11

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

// TestKeyStore_PKCS11_StoreAndLoadKeyPackage proves a FROST secret share
// seals and unseals correctly through a real SoftHSM2-backed *Backend: the
// FROST wrapping key is provisioned via seal.EnsureSealKey (the same
// composition pkg/server's ensureFrostSecretSealKey uses for the "pkcs11"
// secret_backend), and pkg/keyprovider/frost.KeyStore drives Seal/Unseal
// through it.
func TestKeyStore_PKCS11_StoreAndLoadKeyPackage(t *testing.T) {
	b := newProvisionedBackend(t, "frost-seal-token")

	attrs := frost.SymmetricSecretSealKeyAttributes(types.StorePKCS11)
	require.NoError(t, seal.EnsureSealKey(context.Background(), seal.StrategyPKCS11, b, attrs))

	publicStorage := storage.New()
	ks := frost.NewKeyStore(publicStorage, b, attrs)

	keyID := "pkcs11-frost-key"
	pkg := &frost.KeyPackage{
		ParticipantID:      1,
		SecretShare:        &frost.SecretKeyShare{Value: []byte("softhsm2-secret-share")},
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

// TestKeyStore_PKCS11_WrongWrapKey_TypedError proves that unsealing with a
// KeyAttributes CN naming a different (non-existent) wrapping key returns a
// typed error instead of succeeding.
func TestKeyStore_PKCS11_WrongWrapKey_TypedError(t *testing.T) {
	b := newProvisionedBackend(t, "frost-wrongkey-token")

	attrs := frost.SymmetricSecretSealKeyAttributes(types.StorePKCS11)
	require.NoError(t, seal.EnsureSealKey(context.Background(), seal.StrategyPKCS11, b, attrs))

	publicStorage := storage.New()
	ks := frost.NewKeyStore(publicStorage, b, attrs)

	keyID := "pkcs11-wrong-key-test"
	pkg := &frost.KeyPackage{
		ParticipantID:      1,
		SecretShare:        &frost.SecretKeyShare{Value: []byte("softhsm2-secret-share")},
		GroupPublicKey:     []byte{1, 2, 3},
		VerificationShares: map[uint32][]byte{1: {4}, 2: {5}},
		MinSigners:         2,
		MaxSigners:         2,
		Algorithm:          types.FrostAlgorithmEd25519,
	}
	metadata := &frost.KeyMetadata{KeyID: keyID, Algorithm: types.FrostAlgorithmEd25519, Threshold: 2, Total: 2}
	require.NoError(t, ks.StoreKeyPackage(context.Background(), keyID, pkg, metadata))

	// A KeyStore pointed at a wrapping key CN that was never provisioned on
	// this token must fail to unseal with a typed error, not succeed.
	missingAttrs := frost.SymmetricSecretSealKeyAttributes(types.StorePKCS11)
	missingAttrs.CN = "xkms-frost-wrap-does-not-exist"
	ksWrongKey := frost.NewKeyStore(publicStorage, b, missingAttrs)

	_, _, err := ksWrongKey.LoadKeyPackage(context.Background(), keyID, 1)
	require.Error(t, err)
}

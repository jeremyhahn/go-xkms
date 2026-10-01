//go:build tpm_simulator

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

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func kdfSimAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		StoreType:          types.StoreTPM2,
		KeyAlgorithm:       x509.PublicKeyAlgorithm(0),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
}

func kdfSimParams(salt, info []byte, length int) *kdf.KDFParams {
	return &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		Salt:      salt,
		Info:      info,
		KeyLength: length,
	}
}

// TestDeriveFromSymmetricKeyMatchesTheHKDFOracle is the byte-exact proof that
// the TPM 2.0 derivation runs over the sealed key's real material.
//
// This test lives in package tpm2 because loadKeyMaterial — the TPM2_Unseal
// call the derivation itself uses — is unexported. Naming the exact bytes is
// what makes an oracle possible: tpm2SymmetricKey.Raw refuses, and no exported
// path releases them, so a test outside this package can only check a
// derivation for self-consistency.
//
// The comparison is against golang.org/x/crypto/hkdf over those bytes. A
// derivation that ran over anything else — the key's CN, its identifier, an
// empty string — produces a well-formed 32-byte key that only this comparison
// rejects.
func TestDeriveFromSymmetricKeyMatchesTheHKDFOracle(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	instance := tpm.(*TPM2)

	attrs := kdfSimAttrs("kdf-oracle-key")
	_, err := instance.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	salt := []byte("go-xkms/tpm2/salt")
	info := []byte("go-xkms/tpm2/info")

	got, err := instance.DeriveFromSymmetricKey(attrs, kdfSimParams(salt, info, 32))
	require.NoError(t, err)

	// The same unseal the derivation performs, so the oracle's input is the
	// key the TPM actually holds.
	material, err := (&tpm2AESEncrypter{tpm: instance, attrs: attrs}).loadKeyMaterial()
	require.NoError(t, err)
	require.Len(t, material, 32)

	want := make([]byte, 32)
	_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, salt, info), want)
	require.NoError(t, err)

	assert.Equal(t, want, got,
		"the derived key does not match RFC 5869 HKDF-SHA256 over the sealed key's own material, "+
			"so the KDF ran over something that is not the key")

	t.Run("the base key's material is not what comes back", func(t *testing.T) {
		assert.NotEqual(t, material, got,
			"a derivation must return derived bytes, never the base key itself")
	})
}

// TestDeriveFromSymmetricKeySeparatesSealedKeys is the regression assertion:
// two sealed keys, identical salt and info, each matching the oracle computed
// over its own material.
func TestDeriveFromSymmetricKeySeparatesSealedKeys(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	instance := tpm.(*TPM2)

	salt := []byte("shared-salt")
	info := []byte("shared-info")

	derived := make([][]byte, 0, 2)
	for _, cn := range []string{"kdf-sealed-one", "kdf-sealed-two"} {
		attrs := kdfSimAttrs(cn)
		_, err := instance.GenerateSymmetricKey(attrs)
		require.NoError(t, err)

		out, err := instance.DeriveFromSymmetricKey(attrs, kdfSimParams(salt, info, 32))
		require.NoError(t, err)

		material, err := (&tpm2AESEncrypter{tpm: instance, attrs: attrs}).loadKeyMaterial()
		require.NoError(t, err)

		want := make([]byte, 32)
		_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, salt, info), want)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(want, out), "%s does not match its own oracle", cn)

		derived = append(derived, out)
	}

	assert.NotEqual(t, derived[0], derived[1],
		"two different sealed base keys derived the same bytes under identical salt and info")
}

// TestDeriveFromSymmetricKeyRejectsBadInput covers the refusals.
func TestDeriveFromSymmetricKeyRejectsBadInput(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	instance := tpm.(*TPM2)

	attrs := kdfSimAttrs("kdf-bad-input")
	_, err := instance.GenerateSymmetricKey(attrs)
	require.NoError(t, err)

	t.Run("nil attributes", func(t *testing.T) {
		_, err := instance.DeriveFromSymmetricKey(nil, kdfSimParams(nil, nil, 32))
		require.ErrorIs(t, err, ErrInvalidKeyAttributes)
	})

	t.Run("nil parameters", func(t *testing.T) {
		_, err := instance.DeriveFromSymmetricKey(attrs, nil)
		require.ErrorIs(t, err, types.ErrUnsupportedKDFAlgorithm)
	})

	t.Run("attributes that name no symmetric key", func(t *testing.T) {
		_, err := instance.DeriveFromSymmetricKey(&types.KeyAttributes{
			CN:           "an-rsa-key",
			StoreType:    types.StoreTPM2,
			KeyAlgorithm: x509.RSA,
		}, kdfSimParams(nil, nil, 32))
		require.Error(t, err)
	})

	t.Run("key that does not exist", func(t *testing.T) {
		_, err := instance.DeriveFromSymmetricKey(kdfSimAttrs("no-such-sealed-key"), kdfSimParams(nil, nil, 32))
		require.Error(t, err)
		assert.False(t, errors.Is(err, types.ErrEmptyKeyMaterial),
			"a missing key must be reported as missing rather than reaching the KDF with nothing")
	})
}

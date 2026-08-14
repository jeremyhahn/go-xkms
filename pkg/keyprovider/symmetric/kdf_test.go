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

package symmetric

import (
	"bytes"
	"context"
	"crypto"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// deriveTestAttrs describes a stored AES-256 key this backend can derive from.
// Exportable is set only so the test can obtain the oracle's input; the
// derivation itself never consults it, and TestDeriveFromSymmetricKeyIgnores
// Exportability proves that.
func deriveTestAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}
}

func deriveHKDFParams(salt, info []byte, length int) *kdf.KDFParams {
	return &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		Salt:      salt,
		Info:      info,
		KeyLength: length,
	}
}

// TestDeriveFromSymmetricKeyMatchesTheHKDFOracle proves the KDF runs over the
// key material this backend stored, not over the key's name or anything else
// the caller could already compute.
func TestDeriveFromSymmetricKeyMatchesTheHKDFOracle(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()
	ctx := context.Background()

	attrs := deriveTestAttrs("symmetric-derive-oracle")
	_, err := b.GenerateSymmetricKey(ctx, attrs)
	require.NoError(t, err)

	salt := []byte("go-xkms/symmetric/salt")
	info := []byte("go-xkms/symmetric/info")

	got, err := b.DeriveFromSymmetricKey(ctx, attrs, deriveHKDFParams(salt, info, 32))
	require.NoError(t, err)

	material, err := b.ExportKeyMaterial(ctx, attrs)
	require.NoError(t, err)
	require.NotEmpty(t, material)

	want := make([]byte, 32)
	_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, salt, info), want)
	require.NoError(t, err)

	assert.Equal(t, want, got,
		"the derived key does not match RFC 5869 HKDF-SHA256 over this key's own material")
}

// TestDeriveFromSymmetricKeySeparatesBaseKeys is the regression assertion: two
// keys, identical salt and info, different outputs — each matching the oracle
// over its own material.
func TestDeriveFromSymmetricKeySeparatesBaseKeys(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()
	ctx := context.Background()

	salt := []byte("shared-salt")
	info := []byte("shared-info")

	derived := make(map[string][]byte)
	for _, cn := range []string{"symmetric-base-one", "symmetric-base-two"} {
		attrs := deriveTestAttrs(cn)
		_, err := b.GenerateSymmetricKey(ctx, attrs)
		require.NoError(t, err)

		out, err := b.DeriveFromSymmetricKey(ctx, attrs, deriveHKDFParams(salt, info, 32))
		require.NoError(t, err)
		derived[cn] = out

		material, err := b.ExportKeyMaterial(ctx, attrs)
		require.NoError(t, err)
		want := make([]byte, 32)
		_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, salt, info), want)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(want, out), "%s does not match its own oracle", cn)
	}

	assert.NotEqual(t, derived["symmetric-base-one"], derived["symmetric-base-two"],
		"two different base keys derived the same bytes under identical salt and info")
}

// TestDeriveFromSymmetricKeyIgnoresExportability pins the difference between
// deriving and exporting.
//
// PKCS#11 v3.2 §5.18.5 constrains the derived key's sensitivity from the base
// key's and places no extractability requirement on the base key. A backend
// that refused to derive from a non-extractable key would refuse exactly the
// keys derivation exists to serve.
func TestDeriveFromSymmetricKeyIgnoresExportability(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()
	ctx := context.Background()

	attrs := deriveTestAttrs("symmetric-sealed")
	attrs.Exportable = false
	_, err := b.GenerateSymmetricKey(ctx, attrs)
	require.NoError(t, err)

	_, err = b.ExportKeyMaterial(ctx, attrs)
	require.ErrorIs(t, err, backend.ErrKeyNotExportable)

	derived, err := b.DeriveFromSymmetricKey(ctx, attrs, deriveHKDFParams([]byte("s"), []byte("i"), 32))
	require.NoError(t, err)
	assert.Len(t, derived, 32)
}

// TestDeriveFromSymmetricKeyRejectsBadInput covers the refusals.
func TestDeriveFromSymmetricKeyRejectsBadInput(t *testing.T) {
	b := createTestBackend(t)
	ctx := context.Background()

	attrs := deriveTestAttrs("symmetric-bad-input")
	_, err := b.GenerateSymmetricKey(ctx, attrs)
	require.NoError(t, err)

	t.Run("nil attributes", func(t *testing.T) {
		_, err := b.DeriveFromSymmetricKey(ctx, nil, deriveHKDFParams(nil, nil, 32))
		require.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("nil parameters", func(t *testing.T) {
		_, err := b.DeriveFromSymmetricKey(ctx, attrs, nil)
		require.ErrorIs(t, err, types.ErrUnsupportedKDFAlgorithm)
	})

	t.Run("key that does not exist", func(t *testing.T) {
		_, err := b.DeriveFromSymmetricKey(ctx, deriveTestAttrs("no-such-key"), deriveHKDFParams(nil, nil, 32))
		require.ErrorIs(t, err, backend.ErrKeyNotFound)
	})

	t.Run("closed backend", func(t *testing.T) {
		require.NoError(t, b.Close())
		_, err := b.DeriveFromSymmetricKey(ctx, attrs, deriveHKDFParams(nil, nil, 32))
		require.ErrorIs(t, err, ErrStorageClosed)
	})
}

// TestSymmetricBackendAdvertisesDerivation pins the capability assertion the
// service layer performs before it will derive from a stored key.
func TestSymmetricBackendAdvertisesDerivation(t *testing.T) {
	b := createTestBackend(t)
	defer func() { _ = b.Close() }()

	var provider types.KeyProvider = b.Backend
	_, ok := provider.(types.SymmetricKeyDeriver)
	assert.True(t, ok,
		"this backend holds its own symmetric key material, so it must offer derivation")
}

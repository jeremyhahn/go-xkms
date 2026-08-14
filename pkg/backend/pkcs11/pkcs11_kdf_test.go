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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func kdfTestParams(salt, info []byte, length int) *kdf.KDFParams {
	return &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		Salt:      salt,
		Info:      info,
		KeyLength: length,
	}
}

// TestDeriveFromSymmetricKey_MatchesTheHKDFOracle proves the derivation runs
// over the key the token holds.
//
// The oracle's input is the material the fixture put into the token, not
// something read back out of it, so a derivation over any substitute — the
// key's label, its identifier, an empty string — fails this comparison.
func TestDeriveFromSymmetricKey_MatchesTheHKDFOracle(t *testing.T) {
	b := newProvisionedBackend(t, "kdf-oracle")

	attrs := aesAttributes("kdf-oracle-key", true)
	material := randomAESKey(t)
	createSecretKeyFixture(t, b, attrs, material, false, true)

	salt := []byte("go-xkms/pkcs11/salt")
	info := []byte("go-xkms/pkcs11/info")

	got, err := b.DeriveFromSymmetricKey(context.Background(), attrs, kdfTestParams(salt, info, 32))
	require.NoError(t, err)

	want := make([]byte, 32)
	_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, salt, info), want)
	require.NoError(t, err)

	assert.Equal(t, want, got,
		"the derived key does not match RFC 5869 HKDF-SHA256 over the material this key was "+
			"created with, so the KDF ran over something that is not the key")
}

// TestDeriveFromSymmetricKey_SeparatesBaseKeys is the regression assertion:
// two keys, identical salt and info, each matching the oracle over its own
// material and differing from the other.
func TestDeriveFromSymmetricKey_SeparatesBaseKeys(t *testing.T) {
	b := newProvisionedBackend(t, "kdf-separation")
	ctx := context.Background()

	salt := []byte("shared-salt")
	info := []byte("shared-info")

	derived := make([][]byte, 0, 2)
	for _, cn := range []string{"kdf-base-one", "kdf-base-two"} {
		attrs := aesAttributes(cn, true)
		material := randomAESKey(t)
		createSecretKeyFixture(t, b, attrs, material, false, true)

		out, err := b.DeriveFromSymmetricKey(ctx, attrs, kdfTestParams(salt, info, 32))
		require.NoError(t, err)

		want := make([]byte, 32)
		_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, salt, info), want)
		require.NoError(t, err)
		assert.Equal(t, want, out, "%s does not match its own oracle", cn)

		derived = append(derived, out)
	}

	assert.NotEqual(t, derived[0], derived[1],
		"two different base keys derived the same bytes under identical salt and info")
}

// TestDeriveFromSymmetricKey_VariesWithSaltAndInfo changes one parameter at a
// time; each must change the output on its own.
func TestDeriveFromSymmetricKey_VariesWithSaltAndInfo(t *testing.T) {
	b := newProvisionedBackend(t, "kdf-params")
	ctx := context.Background()

	attrs := aesAttributes("kdf-params-key", true)
	createSecretKeyFixture(t, b, attrs, randomAESKey(t), false, true)

	base, err := b.DeriveFromSymmetricKey(ctx, attrs, kdfTestParams([]byte("salt-a"), []byte("info-a"), 32))
	require.NoError(t, err)

	saltChanged, err := b.DeriveFromSymmetricKey(ctx, attrs, kdfTestParams([]byte("salt-b"), []byte("info-a"), 32))
	require.NoError(t, err)
	assert.NotEqual(t, base, saltChanged, "changing only the salt produced the same key")

	infoChanged, err := b.DeriveFromSymmetricKey(ctx, attrs, kdfTestParams([]byte("salt-a"), []byte("info-b"), 32))
	require.NoError(t, err)
	assert.NotEqual(t, base, infoChanged, "changing only the info produced the same key")
}

// TestDeriveFromSymmetricKey_RefusesProtectedKeys pins the capability boundary.
//
// A key the token will not release cannot be derived from at this layer, and
// this backend has no reachable token-side KDF to fall back on: the Go binding
// it drives has no marshaller for CK_HKDF_PARAMS or CK_SP800_108_KDF_PARAMS,
// both of which are pointer-bearing C structures. The honest answer is
// types.ErrKeyDerivationNotSupported — never a derivation over whatever the
// backend could see instead.
func TestDeriveFromSymmetricKey_RefusesProtectedKeys(t *testing.T) {
	b := newProvisionedBackend(t, "kdf-protected")
	ctx := context.Background()

	cases := []struct {
		name        string
		sensitive   bool
		extractable bool
	}{
		{name: "sensitive but extractable", sensitive: true, extractable: true},
		{name: "not sensitive but unextractable", sensitive: false, extractable: false},
		{name: "sensitive and unextractable", sensitive: true, extractable: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := aesAttributes("kdf-protected-"+tc.name, true)
			createSecretKeyFixture(t, b, attrs, randomAESKey(t), tc.sensitive, tc.extractable)

			derived, err := b.DeriveFromSymmetricKey(ctx, attrs, kdfTestParams(nil, nil, 32))
			assert.ErrorIs(t, err, types.ErrKeyDerivationNotSupported)
			assert.Empty(t, derived, "no key material may come back from a refused derivation")
		})
	}
}

// TestDeriveFromSymmetricKey_RejectsBadInput covers the remaining refusals.
func TestDeriveFromSymmetricKey_RejectsBadInput(t *testing.T) {
	b := newProvisionedBackend(t, "kdf-bad-input")
	ctx := context.Background()

	attrs := aesAttributes("kdf-bad-input-key", true)
	createSecretKeyFixture(t, b, attrs, randomAESKey(t), false, true)

	t.Run("nil attributes", func(t *testing.T) {
		_, err := b.DeriveFromSymmetricKey(ctx, nil, kdfTestParams(nil, nil, 32))
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("nil parameters", func(t *testing.T) {
		_, err := b.DeriveFromSymmetricKey(ctx, attrs, nil)
		assert.ErrorIs(t, err, types.ErrUnsupportedKDFAlgorithm)
	})

	t.Run("key that does not exist", func(t *testing.T) {
		missing := aesAttributes("kdf-no-such-key", true)
		_, err := b.DeriveFromSymmetricKey(ctx, missing, kdfTestParams(nil, nil, 32))
		assert.ErrorIs(t, err, backend.ErrKeyNotFound)
	})

	t.Run("asymmetric key attributes", func(t *testing.T) {
		rsa := &types.KeyAttributes{
			CN:           "kdf-rsa-key",
			KeyType:      backend.KEY_TYPE_TLS,
			StoreType:    backend.STORE_PKCS11,
			KeyAlgorithm: x509.RSA,
		}
		_, err := b.DeriveFromSymmetricKey(ctx, rsa, kdfTestParams(nil, nil, 32))
		assert.ErrorIs(t, err, backend.ErrAsymmetricKeyExportNotAllowed)
	})
}

// TestPKCS11BackendAdvertisesDerivation pins the capability assertion the
// service layer performs. Losing it silently disables C_DeriveKey for every
// key this token holds.
func TestPKCS11BackendAdvertisesDerivation(t *testing.T) {
	var provider types.KeyProvider = (*Backend)(nil)

	_, ok := provider.(types.SymmetricKeyDeriver)
	assert.True(t, ok,
		"the token can release an extractable key's material, so this backend must offer "+
			"derivation; without the capability the service layer refuses every C_DeriveKey "+
			"against it, including for keys the token would happily derive from")
}

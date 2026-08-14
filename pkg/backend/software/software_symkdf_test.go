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

package software

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// symKDFFixture returns a software backend that can both derive from and
// export a stored symmetric key. Exportability is needed only by the test, to
// obtain the oracle's input; the derivation itself never requires it.
func symKDFFixture(t *testing.T, cn string) (*SoftwareBackend, *types.KeyAttributes) {
	t.Helper()

	be, _ := createTestBackend(t)
	sw, ok := be.(*SoftwareBackend)
	require.True(t, ok)

	attrs := createAESAttrs(cn, 256, types.SymmetricAES256GCM)
	attrs.Exportable = true

	_, err := sw.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)

	return sw, attrs
}

func hkdfParams(salt, info []byte, length int) *kdf.KDFParams {
	return &kdf.KDFParams{
		Algorithm: kdf.AlgorithmHKDF,
		Hash:      crypto.SHA256,
		Salt:      salt,
		Info:      info,
		KeyLength: length,
	}
}

// TestDeriveFromSymmetricKeyMatchesTheHKDFOracle proves the derivation runs
// over the key the backend actually holds.
//
// The oracle is golang.org/x/crypto/hkdf over the very bytes this key was
// generated with, obtained through ExportKeyMaterial. A derivation that ran
// over anything else — the key's name, its identifier, an empty string —
// produces a well-formed 32-byte key that only this comparison can reject.
func TestDeriveFromSymmetricKeyMatchesTheHKDFOracle(t *testing.T) {
	sw, attrs := symKDFFixture(t, "derive-oracle")
	ctx := context.Background()

	salt := []byte("go-xkms/software/salt")
	info := []byte("go-xkms/software/info")

	got, err := sw.DeriveFromSymmetricKey(ctx, attrs, hkdfParams(salt, info, 32))
	require.NoError(t, err)

	material, err := sw.ExportKeyMaterial(ctx, attrs)
	require.NoError(t, err)
	require.NotEmpty(t, material)

	want := make([]byte, 32)
	_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, salt, info), want)
	require.NoError(t, err)

	assert.Equal(t, want, got,
		"the derived key does not match RFC 5869 HKDF-SHA256 over this key's own material, "+
			"so the KDF ran over something that is not the key")
}

// TestDeriveFromSymmetricKeySeparatesBaseKeys is the assertion that catches a
// regression to deriving from something that is not the key.
//
// Two different keys, identical salt and info. Their derived keys must differ,
// and each must match the oracle computed over its own material. The second
// half is what the old code could never satisfy: it derived from the key's
// name, so the outputs differed only because the names did.
func TestDeriveFromSymmetricKeySeparatesBaseKeys(t *testing.T) {
	ctx := context.Background()
	salt := []byte("shared-salt")
	info := []byte("shared-info")

	first, firstAttrs := symKDFFixture(t, "base-key-one")
	second, secondAttrs := symKDFFixture(t, "base-key-two")

	firstDerived, err := first.DeriveFromSymmetricKey(ctx, firstAttrs, hkdfParams(salt, info, 32))
	require.NoError(t, err)
	secondDerived, err := second.DeriveFromSymmetricKey(ctx, secondAttrs, hkdfParams(salt, info, 32))
	require.NoError(t, err)

	assert.NotEqual(t, firstDerived, secondDerived,
		"two different base keys derived the same bytes under identical salt and info")

	for _, tc := range []struct {
		name    string
		be      *SoftwareBackend
		attrs   *types.KeyAttributes
		derived []byte
	}{
		{"first", first, firstAttrs, firstDerived},
		{"second", second, secondAttrs, secondDerived},
	} {
		t.Run(tc.name+" matches its own oracle", func(t *testing.T) {
			material, err := tc.be.ExportKeyMaterial(ctx, tc.attrs)
			require.NoError(t, err)

			want := make([]byte, 32)
			_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, salt, info), want)
			require.NoError(t, err)

			assert.Equal(t, want, tc.derived)
		})
	}
}

// TestDeriveFromSymmetricKeyVariesWithSaltAndInfo changes one parameter at a
// time. Each must change the output on its own, or the parameter is being
// accepted and discarded.
func TestDeriveFromSymmetricKeyVariesWithSaltAndInfo(t *testing.T) {
	sw, attrs := symKDFFixture(t, "vary-params")
	ctx := context.Background()

	base, err := sw.DeriveFromSymmetricKey(ctx, attrs, hkdfParams([]byte("salt-a"), []byte("info-a"), 32))
	require.NoError(t, err)

	t.Run("salt only", func(t *testing.T) {
		other, err := sw.DeriveFromSymmetricKey(ctx, attrs, hkdfParams([]byte("salt-b"), []byte("info-a"), 32))
		require.NoError(t, err)
		assert.NotEqual(t, base, other,
			"changing only the salt produced the same key, so rotating salts is not rotating keys")
	})

	t.Run("info only", func(t *testing.T) {
		other, err := sw.DeriveFromSymmetricKey(ctx, attrs, hkdfParams([]byte("salt-a"), []byte("info-b"), 32))
		require.NoError(t, err)
		assert.NotEqual(t, base, other,
			"changing only the info produced the same key, so every purpose separated by the "+
				"info string would share one key")
	})
}

// TestDeriveFromSymmetricKeyDoesNotRequireExportability pins the one place a
// derivation must not behave like an export.
//
// PKCS#11 v3.2 §5.18.5 constrains the DERIVED key's CKA_SENSITIVE and
// CKA_EXTRACTABLE from the base key's; it places no extractability requirement
// on the base key itself. Refusing to derive from a non-extractable key would
// refuse exactly the keys derivation exists to serve.
func TestDeriveFromSymmetricKeyDoesNotRequireExportability(t *testing.T) {
	be, _ := createTestBackend(t)
	sw := be.(*SoftwareBackend)
	ctx := context.Background()

	attrs := createAESAttrs("sealed-base", 256, types.SymmetricAES256GCM)
	attrs.Exportable = false
	_, err := sw.GenerateSymmetricKey(ctx, attrs)
	require.NoError(t, err)

	// The same key refuses to be exported ...
	_, err = sw.ExportKeyMaterial(ctx, attrs)
	require.ErrorIs(t, err, backend.ErrKeyNotExportable)

	// ... and still derives.
	derived, err := sw.DeriveFromSymmetricKey(ctx, attrs, hkdfParams([]byte("salt"), []byte("info"), 32))
	require.NoError(t, err)
	assert.Len(t, derived, 32)
}

// TestDeriveFromSymmetricKeyRejectsBadInput covers the refusals.
func TestDeriveFromSymmetricKeyRejectsBadInput(t *testing.T) {
	sw, attrs := symKDFFixture(t, "bad-input")
	ctx := context.Background()

	t.Run("nil attributes", func(t *testing.T) {
		_, err := sw.DeriveFromSymmetricKey(ctx, nil, hkdfParams(nil, nil, 32))
		require.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("nil parameters", func(t *testing.T) {
		_, err := sw.DeriveFromSymmetricKey(ctx, attrs, nil)
		require.ErrorIs(t, err, types.ErrUnsupportedKDFAlgorithm)
	})

	t.Run("key that does not exist", func(t *testing.T) {
		missing := createAESAttrs("no-such-key", 256, types.SymmetricAES256GCM)
		_, err := sw.DeriveFromSymmetricKey(ctx, missing, hkdfParams(nil, nil, 32))
		require.Error(t, err)
		assert.True(t, errors.Is(err, backend.ErrKeyNotFound),
			"a missing base key must be reported as missing, not derived from a default: got %v", err)
	})

	t.Run("asymmetric key attributes", func(t *testing.T) {
		rsa := createRSAAttrs("an-rsa-key", 2048)
		_, err := sw.DeriveFromSymmetricKey(ctx, rsa, hkdfParams(nil, nil, 32))
		require.Error(t, err)
	})

	t.Run("closed backend", func(t *testing.T) {
		closing, closingAttrs := symKDFFixture(t, "closed-backend")
		require.NoError(t, closing.Close())
		_, err := closing.DeriveFromSymmetricKey(ctx, closingAttrs, hkdfParams(nil, nil, 32))
		require.ErrorIs(t, err, ErrStorageClosed)
	})
}

// TestSoftwareBackendAdvertisesDerivation pins the capability assertion the
// service layer performs. A backend that stops satisfying
// types.SymmetricKeyDeriver silently loses C_DeriveKey for every key it holds.
func TestSoftwareBackendAdvertisesDerivation(t *testing.T) {
	be, _ := createTestBackend(t)

	_, ok := be.(types.SymmetricKeyDeriver)
	assert.True(t, ok,
		"the software backend holds its own symmetric key material, so it must offer derivation; "+
			"without the capability the service layer refuses every C_DeriveKey against it")
}

// TestDeriveFromSymmetricKeyOutputLengths checks the requested length is what
// comes back, including a length longer than one PRF block.
func TestDeriveFromSymmetricKeyOutputLengths(t *testing.T) {
	sw, attrs := symKDFFixture(t, "lengths")
	ctx := context.Background()

	for _, length := range []int{16, 32, 64, 100} {
		derived, err := sw.DeriveFromSymmetricKey(ctx, attrs, hkdfParams([]byte("salt"), []byte("info"), length))
		require.NoError(t, err)
		require.Len(t, derived, length)

		material, err := sw.ExportKeyMaterial(ctx, attrs)
		require.NoError(t, err)
		want := make([]byte, length)
		_, err = io.ReadFull(hkdf.New(crypto.SHA256.New, material, []byte("salt"), []byte("info")), want)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(want, derived), "length %d does not match the oracle", length)
	}
}

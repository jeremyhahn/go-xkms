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

package server

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	softwarebackend "github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// fixedKeyAttrsSealerTestBackend builds a software backend with a generated
// RSA key ready to seal/unseal through, standing in for the
// awskms/gcpkms/azurekv-shaped backends fixedKeyAttrsSealer was written for
// (see platform_store.go's doc comment). The software backend implements
// types.Sealer identically -- a symmetric wrapping identity resolved from
// fixed KeyAttributes on every call -- so it exercises the same contract
// without requiring cloud credentials or the "awskms"/"gcpkms"/"azurekv"
// build tags those packages' own fixedKeyAttrsSealer tests carry.
func fixedKeyAttrsSealerTestBackend(t *testing.T) (types.Sealer, *types.KeyAttributes) {
	t.Helper()
	keyStorage, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	be, err := softwarebackend.NewBackend(&softwarebackend.Config{KeyStorage: keyStorage})
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "fixed-key-attrs-sealer-test",
		KeyType:      backend.KEY_TYPE_TLS,
		StoreType:    backend.STORE_SW,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
		Hash: crypto.SHA256,
	}
	_, err = be.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	sealer, ok := be.(types.Sealer)
	require.True(t, ok, "*softwarebackend.SoftwareBackend must implement types.Sealer")

	return sealer, attrs
}

// TestFixedKeyAttrsSealer_CanSeal proves CanSeal delegates to the wrapped
// sealer.
func TestFixedKeyAttrsSealer_CanSeal(t *testing.T) {
	inner, attrs := fixedKeyAttrsSealerTestBackend(t)
	sealer := &fixedKeyAttrsSealer{inner: inner, attrs: attrs}

	assert.Equal(t, inner.CanSeal(), sealer.CanSeal())
	assert.True(t, sealer.CanSeal())
}

// TestFixedKeyAttrsSealer_SealUnsealRoundTrip proves Seal/Unseal both ignore
// the caller-supplied opts and always use the fixed KeyAttributes -- the
// entire reason this adapter exists (pkg/storage/sealed.Backend always
// calls Unseal with nil options).
func TestFixedKeyAttrsSealer_SealUnsealRoundTrip(t *testing.T) {
	inner, attrs := fixedKeyAttrsSealerTestBackend(t)
	sealer := &fixedKeyAttrsSealer{inner: inner, attrs: attrs}

	ctx := context.Background()
	plaintext := []byte("fixed-key-attrs-sealer round trip secret")

	sealed, err := sealer.Seal(ctx, plaintext, nil)
	require.NoError(t, err)
	require.NotNil(t, sealed)

	// Unseal is always called with nil opts by pkg/storage/sealed.Backend;
	// pass a caller-supplied non-nil value too to prove it is ignored either
	// way.
	got, err := sealer.Unseal(ctx, sealed, &types.UnsealOptions{})
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	got2, err := sealer.Unseal(ctx, sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got2)
}

// TestFixedKeyAttrsSealer_SealIgnoresCallerKeyAttributes proves a caller
// that supplies its own (wrong) KeyAttributes in SealOptions is overridden
// by the fixed identity, not honored -- the whole point of "fixed".
func TestFixedKeyAttrsSealer_SealIgnoresCallerKeyAttributes(t *testing.T) {
	inner, attrs := fixedKeyAttrsSealerTestBackend(t)
	sealer := &fixedKeyAttrsSealer{inner: inner, attrs: attrs}

	ctx := context.Background()
	wrongAttrs := &types.KeyAttributes{CN: "does-not-exist"}

	sealed, err := sealer.Seal(ctx, []byte("data"), &types.SealOptions{KeyAttributes: wrongAttrs})
	require.NoError(t, err, "the caller's wrong KeyAttributes must be ignored, not used to look up a nonexistent key")

	got, err := sealer.Unseal(ctx, sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)
}

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
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

// capturingStorage keeps the exact value slice handed to Put by reference
// rather than by copy, so a test can read the same backing array after the
// call returns and see whether the plaintext was wiped.
//
// Only key material is captured: an import writes the metadata record too, and
// capturing the most recent Put would hold that JSON instead, making every
// assertion below vacuous.
type capturingStorage struct {
	storage.Backend

	captured []byte
}

func (s *capturingStorage) Put(ctx context.Context, key string, value []byte) error {
	if !strings.HasPrefix(key, "meta/") {
		s.captured = value
	}
	return s.Backend.Put(ctx, key, value)
}

// TestImportKey_WipesUnwrappedMaterialOnSuccess asserts the plaintext
// UnwrapKey returns does not outlive the import. The garbage collector neither
// zeroes the slice nor promises to reuse its pages promptly, so without an
// explicit wipe the key stays readable in ordinary process memory for an
// unbounded time.
func TestImportKey_WipesUnwrappedMaterialOnSuccess(t *testing.T) {
	store := &capturingStorage{Backend: storage.New()}
	b, err := NewBackend(&Config{KeyStorage: store})
	require.NoError(t, err)
	sb, ok := b.(*Backend)
	require.True(t, ok)
	defer func() { _ = sb.Close() }()

	ctx := context.Background()
	attrs := rollbackAttrs("wipe-success")

	keyMaterial := make([]byte, 32)
	_, randErr := rand.Read(keyMaterial)
	require.NoError(t, randErr)
	original := bytes.Clone(keyMaterial)

	params, paramsErr := sb.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, paramsErr)
	wrapped, wrapErr := sb.WrapKey(ctx, keyMaterial, params)
	require.NoError(t, wrapErr)

	require.NoError(t, sb.ImportKey(ctx, attrs, wrapped))

	require.Len(t, store.captured, len(original),
		"the captured slice must be the key material, not some other record")
	require.NotEqual(t, original, store.captured,
		"the unwrapped key material was left readable on the heap after a successful import")
	require.Equal(t, make([]byte, len(original)), store.captured,
		"the unwrapped key material must be zeroed, not merely altered")
}

// TestImportKey_WipesUnwrappedMaterialOnMetadataFailure is the failure-path
// half. The deferred wipe is what covers the returns between the unwrap and
// the end of the function; a wipe written as a trailing statement instead
// would leave the plaintext behind on exactly the paths that matter.
func TestImportKey_WipesUnwrappedMaterialOnMetadataFailure(t *testing.T) {
	store := &capturingStorage{Backend: storage.New()}
	failing := &metaFailStorage{Backend: store, failMetaPut: true}
	b, err := NewBackend(&Config{KeyStorage: failing})
	require.NoError(t, err)
	sb, ok := b.(*Backend)
	require.True(t, ok)
	defer func() { _ = sb.Close() }()

	ctx := context.Background()
	attrs := rollbackAttrs("wipe-failure")

	keyMaterial := make([]byte, 32)
	_, randErr := rand.Read(keyMaterial)
	require.NoError(t, randErr)

	params, paramsErr := sb.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, paramsErr)
	wrapped, wrapErr := sb.WrapKey(ctx, keyMaterial, params)
	require.NoError(t, wrapErr)

	require.Error(t, sb.ImportKey(ctx, attrs, wrapped),
		"ImportKey succeeded despite the injected metadata failure")

	require.Len(t, store.captured, 32,
		"the captured slice must be the key material, not some other record")
	require.Equal(t, make([]byte, 32), store.captured,
		"the unwrapped key material must be zeroed on the metadata failure path too")
}

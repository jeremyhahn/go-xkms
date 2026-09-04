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
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// metaFailStorage fails the metadata Put and, optionally, the Delete the
// rollback then attempts. Key material and its metadata record live under
// different path prefixes, so selecting on the prefix aims the injection at
// the second of the two writes without depending on call order.
type metaFailStorage struct {
	storage.Backend

	failMetaPut bool
	failDelete  bool

	deletes []string
}

func (s *metaFailStorage) Put(ctx context.Context, key string, value []byte) error {
	if s.failMetaPut && strings.HasPrefix(key, "meta/") {
		return &errs.Message{Msg: "injected metadata put failure"}
	}
	return s.Backend.Put(ctx, key, value)
}

func (s *metaFailStorage) Delete(ctx context.Context, key string) error {
	s.deletes = append(s.deletes, key)
	if s.failDelete {
		return &errs.Message{Msg: "injected delete failure"}
	}
	return s.Backend.Delete(ctx, key)
}

// newMetaFailBackend builds a symmetric backend over storage whose metadata
// write fails.
func newMetaFailBackend(t *testing.T, failDelete bool) (*Backend, *metaFailStorage) {
	t.Helper()

	store := &metaFailStorage{Backend: storage.New(), failMetaPut: true, failDelete: failDelete}
	b, err := NewBackend(&Config{KeyStorage: store})
	require.NoError(t, err)
	sb, ok := b.(*Backend)
	require.True(t, ok, "backend is not *Backend")
	t.Cleanup(func() { _ = sb.Close() })
	return sb, store
}

// rollbackAttrs builds attributes whose Exportable and Sensitive values live
// only in the metadata record, so losing the record loses exactly them.
func rollbackAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
		Sensitive:          false,
	}
}

// TestGenerateSymmetricKey_MetadataFailureRollsBackTheKey is go-xkms#150 on
// the generation path. GenerateSymmetricKey stores the key bytes and then, as
// a separate write, the metadata record; a failure in the second left the
// first committed while the caller was told the generation failed.
func TestGenerateSymmetricKey_MetadataFailureRollsBackTheKey(t *testing.T) {
	b, store := newMetaFailBackend(t, false)
	ctx := context.Background()
	attrs := rollbackAttrs("gen-rollback")

	_, err := b.GenerateSymmetricKey(ctx, attrs)
	require.Error(t, err, "GenerateSymmetricKey succeeded despite the injected metadata failure")

	exists, existsErr := storage.KeyExists(ctx, store, attrs.ID())
	require.NoError(t, existsErr)
	require.False(t, exists,
		"the key is still stored after a failed generation: the metadata failure must roll the key blob back")
}

// TestGenerateSymmetricKey_MetadataFailureLeavesTheIDReusable asserts the
// consequence the rollback exists to produce. GenerateSymmetricKey refuses an
// identifier that already exists, so an orphan left by a failed attempt blocks
// its own retry with backend.ErrKeyAlreadyExists.
func TestGenerateSymmetricKey_MetadataFailureLeavesTheIDReusable(t *testing.T) {
	b, store := newMetaFailBackend(t, false)
	ctx := context.Background()
	attrs := rollbackAttrs("gen-retry")

	_, err := b.GenerateSymmetricKey(ctx, attrs)
	require.Error(t, err)

	store.failMetaPut = false

	_, retryErr := b.GenerateSymmetricKey(ctx, attrs)
	require.NotErrorIs(t, retryErr, backend.ErrKeyAlreadyExists,
		"the orphan from the failed generation blocked the retry at the same identifier")
	require.NoError(t, retryErr)
}

// TestGenerateSymmetricKey_MetadataFailureReportsAFailedRollback covers the
// branch where the compensating delete also fails. Nothing can remove the key
// then, so the error has to name the identifier left occupied.
func TestGenerateSymmetricKey_MetadataFailureReportsAFailedRollback(t *testing.T) {
	b, store := newMetaFailBackend(t, true)
	attrs := rollbackAttrs("gen-rollback-fails")

	_, err := b.GenerateSymmetricKey(context.Background(), attrs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "rollback of key",
		"the error must report that the rollback also failed")
	require.Contains(t, err.Error(), attrs.ID(),
		"the error must name the orphaned key")
	require.Contains(t, store.deletes, storage.KeyPath(attrs.ID()),
		"the rollback must target the key path")
}

// TestImportKey_MetadataFailureRollsBackTheKey is go-xkms#150 on the symmetric
// provider's own import path, which has the same two-write shape as
// generation.
func TestImportKey_MetadataFailureRollsBackTheKey(t *testing.T) {
	b, store := newMetaFailBackend(t, false)
	ctx := context.Background()
	attrs := rollbackAttrs("import-rollback")

	keyMaterial := make([]byte, 32)
	_, randErr := rand.Read(keyMaterial)
	require.NoError(t, randErr)

	params, paramsErr := b.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, paramsErr)
	wrapped, wrapErr := b.WrapKey(ctx, keyMaterial, params)
	require.NoError(t, wrapErr)

	require.Error(t, b.ImportKey(ctx, attrs, wrapped),
		"ImportKey succeeded despite the injected metadata failure")

	exists, existsErr := storage.KeyExists(ctx, store, attrs.ID())
	require.NoError(t, existsErr)
	require.False(t, exists,
		"the key is still stored after a failed import: the metadata failure must roll the key blob back")
}

// TestSaveKeyMetadataOrRollback_NoRollbackOnSuccess is the bad-input mirror of
// the tests above: when the metadata write succeeds nothing may be deleted.
// Without this, a rollback that fired unconditionally would still satisfy
// every assertion about the failure path while destroying every key.
func TestSaveKeyMetadataOrRollback_NoRollbackOnSuccess(t *testing.T) {
	store := &metaFailStorage{Backend: storage.New()}
	b, err := NewBackend(&Config{KeyStorage: store})
	require.NoError(t, err)
	sb, ok := b.(*Backend)
	require.True(t, ok)
	defer func() { _ = sb.Close() }()

	ctx := context.Background()
	attrs := rollbackAttrs("no-rollback")

	_, genErr := sb.GenerateSymmetricKey(ctx, attrs)
	require.NoError(t, genErr)

	require.Empty(t, store.deletes, "a successful metadata write must not delete anything")

	exists, existsErr := storage.KeyExists(ctx, store, attrs.ID())
	require.NoError(t, existsErr)
	require.True(t, exists, "the key must survive a successful generation")
}

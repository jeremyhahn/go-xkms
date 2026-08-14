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
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewKeyMetadata tests that newKeyMetadata carries Exportable and
// Sensitive through from the supplied attributes and always stamps the current
// schema version, since that is the only thing that lets a future format change
// tell an old record from a new one.
//
// The two flags are varied independently because they mean different things:
// Exportable governs whether the key may be wrapped out, Sensitive whether its
// plaintext may ever be read. A key can legitimately be both.
func TestNewKeyMetadata(t *testing.T) {
	tests := []struct {
		name       string
		exportable bool
		sensitive  bool
	}{
		{name: "exportable true", exportable: true},
		{name: "exportable false (default)", exportable: false},
		{name: "sensitive true", sensitive: true},
		{name: "exportable and sensitive", exportable: true, sensitive: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{CN: "k", Exportable: tt.exportable, Sensitive: tt.sensitive}
			meta := newKeyMetadata(attrs)
			assert.Equal(t, keyMetadataSchemaVersion2, meta.SchemaVersion)
			assert.Equal(t, tt.exportable, meta.Exportable)
			assert.Equal(t, tt.sensitive, meta.Sensitive)
		})
	}
}

// TestBackend_saveKeyMetadata tests the success and bad-input paths of
// saveKeyMetadata directly, independent of any single caller.
func TestBackend_saveKeyMetadata(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		attrs := &types.KeyAttributes{CN: "meta-key", Exportable: true, Sensitive: true}
		require.NoError(t, tb.saveKeyMetadata(context.Background(), "meta-key-id", attrs))

		// Read back through the exact same storage.Backend seam key material
		// uses, proving the record landed there and nowhere else.
		raw, err := storage.GetKeyMetadata(context.Background(), tb.storage, "meta-key-id")
		require.NoError(t, err)

		var meta keyMetadata
		require.NoError(t, json.Unmarshal(raw, &meta))
		assert.True(t, meta.Exportable)
		assert.True(t, meta.Sensitive,
			"Sensitive decides whether plaintext is ever released, so it has to reach the record")
		assert.Equal(t, keyMetadataSchemaVersion2, meta.SchemaVersion)
	})

	// A version 1 record predates the Sensitive field, so the JSON has no such
	// key and it decodes to false. loadKeyMetadata must not pass that on: false
	// is the *less* protective value, and PKCS#11 v3.2 §4.9 footnote 11 makes
	// CKA_SENSITIVE a one-way ratchet ("cannot be changed once set to CK_TRUE").
	// Supplying "not sensitive" for a key that never recorded its sensitivity
	// would be this store weakening a key on its own initiative, which is the
	// one direction the specification forbids.
	//
	// The assertion is on loadKeyMetadata rather than on json.Unmarshal because
	// the raw decode genuinely does yield false; the correction is the seam's
	// job, and testing the decode alone would pin the bug instead of the fix.
	t.Run("a version 1 record is read as sensitive", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		require.NoError(t, storage.SaveKeyMetadata(context.Background(), tb.storage,
			"v1-id", []byte(`{"schema_version":1,"exportable":true}`)))

		meta := tb.loadKeyMetadata(context.Background(), "v1-id")
		assert.True(t, meta.Exportable,
			"the record does state exportability, so that much must be honoured")
		assert.True(t, meta.Sensitive,
			"a record that says nothing about sensitivity must be read as protective")
	})

	// The same rule for a key with no record at all, which is every key created
	// before metadata persistence existed.
	t.Run("a key with no record is read as sensitive", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		meta := tb.loadKeyMetadata(context.Background(), "never-saved")
		assert.False(t, meta.Exportable)
		assert.True(t, meta.Sensitive)
	})

	t.Run("bad input: empty key ID", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		err := tb.saveKeyMetadata(context.Background(), "", &types.KeyAttributes{Exportable: true})
		require.Error(t, err)
		assert.ErrorIs(t, err, storage.ErrInvalidID)
	})
}

// TestBackend_loadKeyMetadata tests the success and backward-compatibility
// (bad-input) paths of loadKeyMetadata directly.
func TestBackend_loadKeyMetadata(t *testing.T) {
	t.Run("success: round trip", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		attrs := &types.KeyAttributes{CN: "round-trip", Exportable: true}
		require.NoError(t, tb.saveKeyMetadata(context.Background(), "round-trip-id", attrs))

		meta := tb.loadKeyMetadata(context.Background(), "round-trip-id")
		assert.True(t, meta.Exportable)
	})

	t.Run("bad input: no record for key ID", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		// No metadata was ever saved for this ID -- this is exactly the
		// state of every key that predates metadata persistence. It must
		// not be an error, and it must default to the safe Exportable=false.
		meta := tb.loadKeyMetadata(context.Background(), "never-saved-id")
		assert.False(t, meta.Exportable)
	})

	t.Run("bad input: corrupt record", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		require.NoError(t, storage.SaveKeyMetadata(context.Background(), tb.storage, "corrupt-id", []byte("not json")))

		meta := tb.loadKeyMetadata(context.Background(), "corrupt-id")
		assert.False(t, meta.Exportable)
	})
}

// TestBackend_deleteKeyMetadata tests the success and bad-input paths of
// deleteKeyMetadata directly.
func TestBackend_deleteKeyMetadata(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		require.NoError(t, tb.saveKeyMetadata(context.Background(), "to-delete", &types.KeyAttributes{Exportable: true}))
		require.NoError(t, tb.deleteKeyMetadata(context.Background(), "to-delete"))

		_, err := storage.GetKeyMetadata(context.Background(), tb.storage, "to-delete")
		assert.ErrorIs(t, err, storage.ErrNotFound)
	})

	t.Run("no record present is not an error", func(t *testing.T) {
		// DeleteKey must succeed for keys that predate metadata persistence,
		// which never had a metadata record to remove in the first place.
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		assert.NoError(t, tb.deleteKeyMetadata(context.Background(), "never-existed"))
	})

	t.Run("bad input: storage error surfaces as a wrapped error", func(t *testing.T) {
		b := &Backend{storage: &MockFailingStorage{failOnDelete: true}}

		err := b.deleteKeyMetadata(context.Background(), "any-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete key metadata")
	})
}

// TestGenerateSymmetricKey_ExportableSurvivesReload proves the fix for the
// confirmed defect end to end: attrs.Exportable, supplied only at
// generation time, must still be true after the key is forgotten and
// rediscovered via ListKeys, and ExportKeyMaterial -- which trusts the
// reloaded attrs, not the caller's original struct -- must then succeed.
func TestGenerateSymmetricKey_ExportableSurvivesReload(t *testing.T) {
	tb := createTestBackend(t)
	defer func() { _ = tb.Close() }()

	original := &types.KeyAttributes{
		CN:                 "exportable-round-trip",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}
	key, err := tb.GenerateSymmetricKey(context.Background(), original)
	require.NoError(t, err)
	rawKey, err := key.Raw()
	require.NoError(t, err)

	// Simulate a fresh lookup, as findKeyAttrs (pkg/xkms) does: attributes
	// are reconstructed entirely from persisted state, not from the
	// caller's original struct.
	reloaded, err := tb.ListKeys(context.Background())
	require.NoError(t, err)

	var reloadedAttrs *types.KeyAttributes
	for _, a := range reloaded {
		if a.CN == "exportable-round-trip" {
			reloadedAttrs = a
		}
	}
	require.NotNil(t, reloadedAttrs, "generated key must be present in ListKeys")
	assert.True(t, reloadedAttrs.Exportable, "Exportable must survive create -> reload")

	// Before this fix, ExportKeyMaterial always failed here with
	// backend.ErrKeyNotExportable because the reconstructed attrs always
	// carried Exportable=false.
	material, err := tb.ExportKeyMaterial(context.Background(), reloadedAttrs)
	require.NoError(t, err)
	assert.Equal(t, rawKey, material)
}

// TestListKeys_KeyWithNoMetadataRecord_DefaultsNonExportable proves the
// backward-compatibility path: a key written directly to storage (as every
// key created before metadata persistence existed would have been, since
// nothing wrote a metadata record for it) must still list cleanly, with
// Exportable defaulting to false rather than ListKeys failing outright.
func TestListKeys_KeyWithNoMetadataRecord_DefaultsNonExportable(t *testing.T) {
	tb := createTestBackend(t)
	defer func() { _ = tb.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "pre-existing-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	keyData := make([]byte, 32)
	_, err := rand.Read(keyData)
	require.NoError(t, err)

	// Bypass GenerateSymmetricKey entirely so no metadata record is ever
	// written -- this is exactly the on-disk state of a key that predates
	// this feature.
	require.NoError(t, storage.SaveKey(context.Background(), tb.storage, attrs.ID(), keyData))

	keys, err := tb.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "pre-existing-key", keys[0].CN)
	assert.False(t, keys[0].Exportable)
}

// TestDeleteKey_RemovesMetadataRecord proves DeleteKey leaves no orphaned
// metadata record behind for a deleted key.
func TestDeleteKey_RemovesMetadataRecord(t *testing.T) {
	tb := createTestBackend(t)
	defer func() { _ = tb.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "delete-metadata-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}
	_, err := tb.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)

	keyID := attrs.ID()
	_, err = storage.GetKeyMetadata(context.Background(), tb.storage, keyID)
	require.NoError(t, err, "metadata record must exist right after generation")

	require.NoError(t, tb.DeleteKey(context.Background(), attrs))

	_, err = storage.GetKeyMetadata(context.Background(), tb.storage, keyID)
	assert.ErrorIs(t, err, storage.ErrNotFound, "metadata record must not survive DeleteKey")
}

// TestImportKey_ExportableSurvivesReload proves ImportKey persists the
// caller's Exportable attribute exactly like GenerateSymmetricKey does --
// the defect this package fixes named ImportKey as one of the creation
// paths that must not drop it.
func TestImportKey_ExportableSurvivesReload(t *testing.T) {
	tb := createTestBackend(t)
	defer func() { _ = tb.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "imported-exportable-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}

	keyMaterial := make([]byte, 32)
	_, err := rand.Read(keyMaterial)
	require.NoError(t, err)

	params, err := tb.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	wrapped, err := tb.WrapKey(context.Background(), keyMaterial, params)
	require.NoError(t, err)

	require.NoError(t, tb.ImportKey(context.Background(), attrs, wrapped))

	reloaded, err := tb.ListKeys(context.Background())
	require.NoError(t, err)

	var reloadedAttrs *types.KeyAttributes
	for _, a := range reloaded {
		if a.CN == "imported-exportable-key" {
			reloadedAttrs = a
		}
	}
	require.NotNil(t, reloadedAttrs, "imported key must be present in ListKeys")
	assert.True(t, reloadedAttrs.Exportable, "Exportable must survive import -> reload")
}

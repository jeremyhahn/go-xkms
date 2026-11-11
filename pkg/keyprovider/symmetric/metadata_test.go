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
			assert.Equal(t, keyMetadataSchemaVersion, meta.SchemaVersion)
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
		assert.Equal(t, keyMetadataSchemaVersion, meta.SchemaVersion)
	})

	t.Run("bad input: empty key ID", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		err := tb.saveKeyMetadata(context.Background(), "", &types.KeyAttributes{Exportable: true})
		require.Error(t, err)
		assert.ErrorIs(t, err, storage.ErrInvalidID)
	})
}

// TestBackend_SaveKeyMetadata proves the exported seam an importer outside
// this package uses records the attributes the backend reads back, and
// refuses a record it could never find again.
func TestBackend_SaveKeyMetadata(t *testing.T) {
	tb := createTestBackend(t)
	defer func() { _ = tb.Close() }()
	ctx := context.Background()

	attrs := &types.KeyAttributes{CN: "imported", Exportable: true, Sensitive: true}
	require.NoError(t, tb.SaveKeyMetadata(ctx, "imported-id", attrs))
	meta, err := tb.loadKeyMetadata(ctx, "imported-id")
	require.NoError(t, err)
	assert.True(t, meta.Exportable)
	assert.True(t, meta.Sensitive)

	assert.ErrorIs(t, tb.SaveKeyMetadata(ctx, "", attrs), storage.ErrInvalidID)
}

// TestBackend_loadKeyMetadata tests the success and bad-input paths of
// loadKeyMetadata directly.
func TestBackend_loadKeyMetadata(t *testing.T) {
	t.Run("success: round trip", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		attrs := &types.KeyAttributes{CN: "round-trip", Exportable: true}
		require.NoError(t, tb.saveKeyMetadata(context.Background(), "round-trip-id", attrs))

		meta, err := tb.loadKeyMetadata(context.Background(), "round-trip-id")
		require.NoError(t, err)
		assert.True(t, meta.Exportable)
	})

	// A key with no record at all -- there is no supported way to produce
	// one, since every key this package creates writes its record in the
	// same operation -- is refused with the typed sentinel rather than
	// defaulted to a safe-but-invented shape.
	t.Run("bad input: no record for key ID is a typed error", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		meta, err := tb.loadKeyMetadata(context.Background(), "never-saved-id")
		require.Error(t, err)
		assert.Nil(t, meta)
		assert.ErrorIs(t, err, ErrKeyMetadataNotFound)
	})

	t.Run("bad input: corrupt record", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		require.NoError(t, storage.SaveKeyMetadata(context.Background(), tb.storage, "corrupt-id", []byte("not json")))

		meta, err := tb.loadKeyMetadata(context.Background(), "corrupt-id")
		require.Error(t, err)
		assert.Nil(t, meta)
		assert.Contains(t, err.Error(), "failed to parse key metadata")
	})

	// The removed multi-version format: a record stamped with a schema
	// version other than the current one is refused with a typed error
	// rather than read through version-specific inference.
	t.Run("bad input: unsupported schema version is a typed error", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		require.NoError(t, storage.SaveKeyMetadata(context.Background(), tb.storage,
			"old-schema-id", []byte(`{"schema_version":1,"exportable":true}`)))

		meta, err := tb.loadKeyMetadata(context.Background(), "old-schema-id")
		require.Error(t, err)
		assert.Nil(t, meta)
		assert.Contains(t, err.Error(), "unsupported schema version")
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

	// Every key this package creates has a metadata record, so a missing
	// record is not the ordinary case: it is reported as the typed sentinel.
	t.Run("no record present is a typed error", func(t *testing.T) {
		tb := createTestBackend(t)
		defer func() { _ = tb.Close() }()

		err := tb.deleteKeyMetadata(context.Background(), "never-existed")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrKeyMetadataNotFound)
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

// TestListKeys_KeyWithNoMetadataRecord_FailsWithTypedError proves ListKeys
// refuses a key with no metadata record rather than silently defaulting its
// Exportable/Sensitive attributes: there is no supported way for a key
// created through this package to be missing one.
func TestListKeys_KeyWithNoMetadataRecord_FailsWithTypedError(t *testing.T) {
	tb := createTestBackend(t)
	defer func() { _ = tb.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "no-metadata-key",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	keyData := make([]byte, 32)
	_, err := rand.Read(keyData)
	require.NoError(t, err)

	// Bypass GenerateSymmetricKey entirely so no metadata record is ever
	// written -- this is the state loadKeyMetadata treats as invalid.
	require.NoError(t, storage.SaveKey(context.Background(), tb.storage, attrs.ID(), keyData))

	_, err = tb.ListKeys(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyMetadataNotFound)
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

// TestImportKey_TenantSurvivesReload proves the tenant a key was imported
// under comes back from ListKeys. The identifier alone cannot prove it: a
// tenanted key without a partition and a partitioned key without a tenant
// both produce five segments, and the segment-count parse used to read the
// tenant back as a partition — which made a tenant's imported key invisible
// to that tenant's scoped view (go-xkms#162, go-xkms#163). The version 3
// record states TenantID and Partition explicitly, and ListKeys must prefer
// it over the guess.
func TestImportKey_TenantSurvivesReload(t *testing.T) {
	tb := createTestBackend(t)
	defer func() { _ = tb.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "tenant-imported-key",
		KeyType:            types.KeyTypeSecret,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
		TenantID:           "acme",
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
		if a.CN == "tenant-imported-key" {
			reloadedAttrs = a
		}
	}
	require.NotNil(t, reloadedAttrs, "imported key must be present in ListKeys")
	assert.Equal(t, "acme", reloadedAttrs.TenantID, "TenantID must survive import -> reload")
	assert.Empty(t, reloadedAttrs.Partition, "the tenant must not be misread as a partition")
}

// TestListKeys_OldSchemaRecordIsRefused proves a record written under a
// removed schema version (here, the pre-TenantID/Partition shape) is refused
// with the typed error rather than read through version-specific inference:
// there is a single supported schema version, and an older record is invalid
// data, not a compatibility case to interpret.
func TestListKeys_OldSchemaRecordIsRefused(t *testing.T) {
	tb := createTestBackend(t)
	defer func() { _ = tb.Close() }()

	// A five-segment identifier, stored with a removed version 2 record
	// (no tenant_id/partition fields).
	const keyID = "legacy-part:software:secret:legacy-key:aes256-gcm"
	require.NoError(t, storage.SaveKey(context.Background(), tb.storage, keyID, []byte("opaque")))
	require.NoError(t, storage.SaveKeyMetadata(context.Background(), tb.storage,
		keyID, []byte(`{"schema_version":2,"exportable":true,"sensitive":false}`)))

	_, err := tb.ListKeys(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported schema version")
}

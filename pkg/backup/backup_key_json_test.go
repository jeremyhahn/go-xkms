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

package backup

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyBackupKey mirrors BackupKey's on-disk shape from before go-xkms#587,
// when PrivateKey was an exported []byte field with no json tags. It is the
// golden-fixture reference: BackupKey's custom (Un)MarshalJSON must produce
// and accept exactly this historical shape so archives written by older
// builds keep decoding.
type legacyBackupKey struct {
	ID         string
	Attributes *types.KeyAttributes
	PrivateKey []byte
	PublicKey  []byte
	Metadata   map[string]interface{}
	Created    time.Time
	Modified   time.Time
	Version    uint64
}

// TestBackupKey_JSON_GoldenFixture proves BackupKey's protected private key
// round-trips through the historical wire format byte-for-byte: today's
// JSON form decodes into the protected type, and re-encoding it reproduces
// the identical bytes.
func TestBackupKey_JSON_GoldenFixture(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	modified := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)

	legacy := legacyBackupKey{
		ID:         "key-1",
		PrivateKey: []byte("private-key-bytes"),
		PublicKey:  []byte("public-key-bytes"),
		Metadata:   map[string]interface{}{"note": "golden"},
		Created:    created,
		Modified:   modified,
		Version:    3,
	}

	golden, err := json.Marshal(legacy)
	require.NoError(t, err)

	var decoded BackupKey
	require.NoError(t, json.Unmarshal(golden, &decoded))
	assert.Equal(t, legacy.ID, decoded.ID)
	assert.Equal(t, legacy.PublicKey, decoded.PublicKey)
	assert.Equal(t, legacy.Metadata, decoded.Metadata)
	assert.True(t, legacy.Created.Equal(decoded.Created))
	assert.True(t, legacy.Modified.Equal(decoded.Modified))
	assert.Equal(t, legacy.Version, decoded.Version)
	assert.Equal(t, legacy.PrivateKey, decoded.PrivateKeyBytes())

	reencoded, err := json.Marshal(&decoded)
	require.NoError(t, err)
	assert.Equal(t, golden, reencoded, "byte-identical re-encoding of the historical form")
}

// TestBackupKey_JSON_GoldenFixture_NoPrivateKey proves a key with no private
// key material still round-trips to the historical "null" form, matching
// what a nil []byte field marshaled before this type carried a protected
// buffer.
func TestBackupKey_JSON_GoldenFixture_NoPrivateKey(t *testing.T) {
	legacy := legacyBackupKey{
		ID:        "key-2",
		PublicKey: []byte("public-key-bytes"),
		Version:   1,
	}

	golden, err := json.Marshal(legacy)
	require.NoError(t, err)

	var decoded BackupKey
	require.NoError(t, json.Unmarshal(golden, &decoded))
	assert.False(t, decoded.HasPrivateKey())
	assert.Nil(t, decoded.PrivateKeyBytes())

	reencoded, err := json.Marshal(&decoded)
	require.NoError(t, err)
	assert.Equal(t, golden, reencoded)
}

// TestBackupKey_SetPrivateKey_RoundTrip proves SetPrivateKey stores key
// material that PrivateKeyBytes and HasPrivateKey can observe, and that the
// stored copy is independent of the caller's (now-wiped) source slice.
func TestBackupKey_SetPrivateKey_RoundTrip(t *testing.T) {
	key := &BackupKey{ID: "key-3"}
	assert.False(t, key.HasPrivateKey())
	assert.Nil(t, key.PrivateKeyBytes())

	source := []byte("super-secret-key-material")
	require.NoError(t, key.SetPrivateKey(source))

	assert.True(t, key.HasPrivateKey())
	assert.Equal(t, []byte("super-secret-key-material"), key.PrivateKeyBytes())
}

// TestBackupKey_SetPrivateKey_EmptyClearsExisting proves SetPrivateKey with
// an empty slice clears a previously stored key rather than leaving the
// destroyed buffer behind, so a caller cannot observe stale key material
// after clearing it.
func TestBackupKey_SetPrivateKey_EmptyClearsExisting(t *testing.T) {
	key := &BackupKey{ID: "key-4"}
	require.NoError(t, key.SetPrivateKey([]byte("will-be-cleared")))
	require.True(t, key.HasPrivateKey())

	require.NoError(t, key.SetPrivateKey(nil))

	assert.False(t, key.HasPrivateKey())
	assert.Nil(t, key.PrivateKeyBytes())
}

// TestBackupKey_UnmarshalJSON_InvalidJSON proves malformed JSON is reported
// as a decode error rather than silently producing a zero-valued key.
func TestBackupKey_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var key BackupKey
	err := json.Unmarshal([]byte("{not valid json"), &key)
	require.Error(t, err)
}

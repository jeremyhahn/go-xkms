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

package pkcs8

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestResolveKeyOrigin is the single point where the legacy inference is
// applied, so it is the single point worth pinning.
//
// The distinction that matters is between a record that could not carry an
// origin and one that should have. The first predates every import path and
// resolves to generated; the second was written by a build that had the field
// and did not set it, which is a defect and must stay unknown so a consumer
// failing closed refuses it. Collapsing the two would let a future write path
// that forgets to stamp the origin silently inherit the trust of a genuinely
// old key.
func TestResolveKeyOrigin(t *testing.T) {
	cases := []struct {
		name     string
		metadata *keyMetadata
		want     types.KeyOrigin
		why      string
	}{
		{
			name:     "no record at all",
			metadata: nil,
			want:     types.KeyOriginGenerated,
			why:      "predates the record entirely, so predates every import path",
		},
		{
			name:     "record from before the field existed",
			metadata: &keyMetadata{SchemaVersion: 0},
			want:     types.KeyOriginGenerated,
			why:      "schema 0 could not carry an origin",
		},
		{
			name:     "schema v1 record",
			metadata: &keyMetadata{SchemaVersion: keyMetadataSchemaVersion1},
			want:     types.KeyOriginGenerated,
			why:      "v1 predates the origin field",
		},
		{
			name:     "schema v2 recording generated",
			metadata: &keyMetadata{SchemaVersion: keyMetadataSchemaVersion2, KeyOrigin: "generated"},
			want:     types.KeyOriginGenerated,
			why:      "the record says so",
		},
		{
			name:     "schema v2 recording imported",
			metadata: &keyMetadata{SchemaVersion: keyMetadataSchemaVersion2, KeyOrigin: "imported"},
			want:     types.KeyOriginImported,
			why:      "the record says so",
		},
		{
			name:     "schema v2 with no origin is a defect, not a legacy key",
			metadata: &keyMetadata{SchemaVersion: keyMetadataSchemaVersion2},
			want:     types.KeyOriginUnknown,
			why:      "a build that had the field did not set it; must not inherit legacy trust",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveKeyOrigin(tc.metadata), tc.why)
		})
	}
}

// TestNewKeyMetadata_CarriesOrigin verifies the write side records the origin
// at the current schema version, so a record round-trips through
// resolveKeyOrigin as what it was written as.
func TestNewKeyMetadata_CarriesOrigin(t *testing.T) {
	for _, origin := range []types.KeyOrigin{types.KeyOriginGenerated, types.KeyOriginImported} {
		record := newKeyMetadata(&types.KeyAttributes{CN: "roundtrip", KeyOrigin: origin})
		assert.Equal(t, keyMetadataSchemaVersionCurrent, record.SchemaVersion)
		assert.Equal(t, string(origin), record.KeyOrigin)
		assert.Equal(t, origin, resolveKeyOrigin(record))
	}
}

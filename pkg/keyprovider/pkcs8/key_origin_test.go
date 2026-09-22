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

// TestResolveKeyOrigin proves resolveKeyOrigin is a plain read: whatever the
// record's KeyOrigin field decodes to is what comes back, with no
// version-gated inference substituting a different value for a record that
// carries no origin. A record (or no record at all) with nothing recorded
// resolves to types.KeyOriginUnknown -- the absence of a claim, not a claim
// of generation -- so a consumer that fails closed on unknown origin (see
// pkg/xkms.refuseUnattestableKey) refuses it rather than silently trusting
// it as generated.
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
			want:     types.KeyOriginUnknown,
			why:      "no record means no claim of origin",
		},
		{
			name:     "record with no origin recorded",
			metadata: &keyMetadata{SchemaVersion: keyMetadataSchemaVersion},
			want:     types.KeyOriginUnknown,
			why:      "an empty key_origin field is read as unknown, not inferred as generated",
		},
		{
			name:     "record recording generated",
			metadata: &keyMetadata{SchemaVersion: keyMetadataSchemaVersion, KeyOrigin: "generated"},
			want:     types.KeyOriginGenerated,
			why:      "the record says so",
		},
		{
			name:     "record recording imported",
			metadata: &keyMetadata{SchemaVersion: keyMetadataSchemaVersion, KeyOrigin: "imported"},
			want:     types.KeyOriginImported,
			why:      "the record says so",
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
		assert.Equal(t, keyMetadataSchemaVersion, record.SchemaVersion)
		assert.Equal(t, string(origin), record.KeyOrigin)
		assert.Equal(t, origin, resolveKeyOrigin(record))
	}
}

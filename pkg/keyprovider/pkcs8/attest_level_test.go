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

package pkcs8

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListKeys_AttestLevelIsAlwaysSoftware proves ListKeys reports
// types.AttestLevelSoftware for every key this backend holds, regardless of
// what the caller stamped on attrs before GenerateKey. Unlike KeyOrigin,
// AttestLevel needs no metadata round trip here: PKCS#8 storage is software
// cryptography by construction, so the answer cannot legitimately be
// anything else, and a caller-supplied claim to the contrary is corrected
// rather than trusted — mirroring GenerateKey's own refusal to accept a
// caller-supplied KeyOrigin.
func TestListKeys_AttestLevelIsAlwaysSoftware(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	cases := []struct {
		name    string
		claimed types.AttestLevel
	}{
		{"unset", types.AttestLevel("")},
		{"claimed software", types.AttestLevelSoftware},
		{"claimed hardware", types.AttestLevelHardware},
		{"claimed unattested", types.AttestLevelUnattested},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := createECDSAAttrs("attest-level-"+tc.name, "P-256")
			attrs.AttestLevel = tc.claimed

			_, err := be.GenerateKey(context.Background(), attrs)
			require.NoError(t, err)

			keys, err := be.ListKeys(context.Background())
			require.NoError(t, err)

			var found *types.KeyAttributes
			for _, k := range keys {
				if k.CN == attrs.CN {
					found = k
					break
				}
			}
			require.NotNil(t, found, "generated key must be listed")
			assert.Equal(t, types.AttestLevelSoftware, found.AttestLevel)
		})
	}
}

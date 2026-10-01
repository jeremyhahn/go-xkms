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

package fido2

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prfVectors is testdata/webauthn_prf_salt_vectors.json, which sdk/ts's
// browser-path test reads too: both surfaces prove the same bytes.
type prfVectors struct {
	Vectors []struct {
		Salt     string `json:"salt"`
		PRFInput string `json:"prf_input"`
	} `json:"vectors"`
}

func loadPRFVectors(t *testing.T) prfVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/webauthn_prf_salt_vectors.json")
	require.NoError(t, err)
	var v prfVectors
	require.NoError(t, json.Unmarshal(data, &v))
	require.NotEmpty(t, v.Vectors)
	return v
}

// TestWebAuthnPRFSalt_MatchesTheBrowserVectors is the CLI half of the
// cross-surface vector test: the transform a non-browser client applies is
// the one a browser applies.
func TestWebAuthnPRFSalt_MatchesTheBrowserVectors(t *testing.T) {
	for _, v := range loadPRFVectors(t).Vectors {
		salt, err := hex.DecodeString(v.Salt)
		require.NoError(t, err)
		assert.Equal(t, v.PRFInput, hex.EncodeToString(WebAuthnPRFSalt(salt)), v.Salt)
	}
}

// TestWebAuthnPRFSalt_IsDomainSeparated proves the transform is not the
// identity and distinguishes salts.
func TestWebAuthnPRFSalt_IsDomainSeparated(t *testing.T) {
	salt := make([]byte, 32)
	got := WebAuthnPRFSalt(salt)
	assert.Len(t, got, 32)
	assert.NotEqual(t, salt, got)
	salt[0] = 1
	assert.NotEqual(t, got, WebAuthnPRFSalt(salt))
}

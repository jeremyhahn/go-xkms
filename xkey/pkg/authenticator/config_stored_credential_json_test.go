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

package authenticator

import (
	"encoding/json"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// legacyStoredCredential mirrors StoredCredential's on-disk shape from
// before go-xkms#587, when PrivateKey was an exported []byte field. It is
// the golden-fixture reference: StoredCredential's custom (Un)MarshalJSON
// must produce and accept exactly this historical shape so credentials
// persisted by older builds keep decoding.
type legacyStoredCredential struct {
	CredentialID        []byte
	RPID                string
	RPName              string
	UserID              []byte
	UserName            string
	UserDisplayName     string
	PrivateKey          []byte
	PublicKeyCOSE       []byte
	Algorithm           int
	SignCount           uint32
	Discoverable        bool
	HMACSecretKey       []byte
	CredProtect         uint8
	CreatedAt           int64
	RPUVPolicy          string           `json:"rp_uv_policy,omitempty"`
	RPUPPolicy          bool             `json:"rp_up_policy"`
	RPResidentKeyPolicy string           `json:"rp_resident_key_policy,omitempty"`
	RPAttestationPref   string           `json:"rp_attestation_pref,omitempty"`
	BackendID           xkms.BackendType `json:"backend_id,omitempty"`
}

// TestStoredCredential_JSON_GoldenFixture proves StoredCredential's
// protected private key round-trips through the historical wire format
// byte-for-byte: today's JSON form decodes into the protected type, and
// re-encoding it reproduces the identical bytes.
func TestStoredCredential_JSON_GoldenFixture(t *testing.T) {
	legacy := legacyStoredCredential{
		CredentialID:        []byte{1, 2, 3, 4},
		RPID:                "example.com",
		RPName:              "Example Corp",
		UserID:              []byte{5, 6, 7, 8},
		UserName:            "user@example.com",
		UserDisplayName:     "Test User",
		PrivateKey:          []byte("pkcs8-private-key-bytes"),
		PublicKeyCOSE:       []byte{9, 10, 11, 12},
		Algorithm:           COSEAlgES256,
		SignCount:           7,
		Discoverable:        true,
		HMACSecretKey:       []byte{13, 14, 15, 16},
		CredProtect:         2,
		CreatedAt:           1700000000,
		RPUVPolicy:          "preferred",
		RPUPPolicy:          true,
		RPResidentKeyPolicy: "required",
		RPAttestationPref:   "direct",
		BackendID:           xkms.BackendTypeSoftware,
	}

	golden, err := json.Marshal(legacy)
	require.NoError(t, err)

	var decoded StoredCredential
	require.NoError(t, json.Unmarshal(golden, &decoded))
	assert.Equal(t, legacy.CredentialID, decoded.CredentialID)
	assert.Equal(t, legacy.RPID, decoded.RPID)
	assert.Equal(t, legacy.UserID, decoded.UserID)
	assert.Equal(t, legacy.PublicKeyCOSE, decoded.PublicKeyCOSE)
	assert.Equal(t, legacy.Algorithm, decoded.Algorithm)
	assert.Equal(t, legacy.SignCount, decoded.SignCount)
	assert.Equal(t, legacy.Discoverable, decoded.Discoverable)
	assert.Equal(t, legacy.HMACSecretKey, decoded.HMACSecretKey)
	assert.Equal(t, legacy.CredProtect, decoded.CredProtect)
	assert.Equal(t, legacy.CreatedAt, decoded.CreatedAt)
	assert.Equal(t, legacy.RPUVPolicy, decoded.RPUVPolicy)
	assert.Equal(t, legacy.RPUPPolicy, decoded.RPUPPolicy)
	assert.Equal(t, legacy.RPResidentKeyPolicy, decoded.RPResidentKeyPolicy)
	assert.Equal(t, legacy.RPAttestationPref, decoded.RPAttestationPref)
	assert.Equal(t, legacy.BackendID, decoded.BackendID)
	assert.Equal(t, legacy.PrivateKey, decoded.PrivateKeyBytes())

	reencoded, err := json.Marshal(&decoded)
	require.NoError(t, err)
	assert.Equal(t, golden, reencoded, "byte-identical re-encoding of the historical form")
}

// TestStoredCredential_JSON_GoldenFixture_NoPrivateKey proves a
// hardware-backed credential with no exportable private key still
// round-trips to the historical "null" form.
func TestStoredCredential_JSON_GoldenFixture_NoPrivateKey(t *testing.T) {
	legacy := legacyStoredCredential{
		CredentialID: []byte{1, 2, 3, 4},
		RPID:         "example.com",
		RPUPPolicy:   true,
		BackendID:    xkms.BackendTypeTPM2,
	}

	golden, err := json.Marshal(legacy)
	require.NoError(t, err)

	var decoded StoredCredential
	require.NoError(t, json.Unmarshal(golden, &decoded))
	assert.False(t, decoded.HasPrivateKey())
	assert.Nil(t, decoded.PrivateKeyBytes())

	reencoded, err := json.Marshal(&decoded)
	require.NoError(t, err)
	assert.Equal(t, golden, reencoded)
}

// TestStoredCredential_SetPrivateKey_RoundTrip proves SetPrivateKey stores
// key material that PrivateKeyBytes and HasPrivateKey can observe.
func TestStoredCredential_SetPrivateKey_RoundTrip(t *testing.T) {
	cred := &StoredCredential{CredentialID: []byte{1}}
	assert.False(t, cred.HasPrivateKey())
	assert.Nil(t, cred.PrivateKeyBytes())

	require.NoError(t, cred.SetPrivateKey([]byte("pkcs8-bytes")))

	assert.True(t, cred.HasPrivateKey())
	assert.Equal(t, []byte("pkcs8-bytes"), cred.PrivateKeyBytes())
}

// TestStoredCredential_SetPrivateKey_EmptyClearsExisting proves
// SetPrivateKey with an empty slice clears a previously stored key, which
// is the normal path for a hardware-backed credential whose key backend
// cannot export.
func TestStoredCredential_SetPrivateKey_EmptyClearsExisting(t *testing.T) {
	cred := &StoredCredential{CredentialID: []byte{1}}
	require.NoError(t, cred.SetPrivateKey([]byte("will-be-cleared")))
	require.True(t, cred.HasPrivateKey())

	require.NoError(t, cred.SetPrivateKey(nil))

	assert.False(t, cred.HasPrivateKey())
	assert.Nil(t, cred.PrivateKeyBytes())
}

// TestStoredCredential_UnmarshalJSON_InvalidJSON proves malformed JSON is
// reported as a decode error rather than silently producing a zero-valued
// credential.
func TestStoredCredential_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var cred StoredCredential
	err := json.Unmarshal([]byte("{not valid json"), &cred)
	require.Error(t, err)
}

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setFullVendorRPPolicy stores a fully-populated policy for rpID through the
// vendor command, the way an SO establishes governance for an RP.
func setFullVendorRPPolicy(t *testing.T, auth *Authenticator, rpID string) {
	t.Helper()

	setData := buildVendorConfigRequest(t, map[interface{}]interface{}{
		vendorParamKeyVendorCmd:      uint8(VendorCmdSetRPPolicy),
		vendorParamKeyRPID:           rpID,
		vendorParamKeyUVOverride:     "required",
		vendorParamKeyAttestOverride: "direct",
		vendorParamKeyUPOverride:     true,
		vendorParamKeyEnterprise:     true,
		vendorParamKeyBlocked:        false,
	})
	resp, err := auth.handleConfig(setData)
	require.NoError(t, err)
	require.Equal(t, uint8(StatusOK), resp[0])
}

// TestVendorSetRPPolicy_PartialRequestPreservesPolicy is the #321 regression
// probe on the CTAP wire: a two-key CBOR map (rpID + blocked) against a
// populated RP must change only Blocked. Before the fix, the absent keys were
// indistinguishable from fields set to their zero values and the SO's UV,
// attestation and enterprise settings were silently cleared to their
// permissive states.
func TestVendorSetRPPolicy_PartialRequestPreservesPolicy(t *testing.T) {
	auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
	defer func() { _ = auth.Close() }()

	setFullVendorRPPolicy(t, auth, "rp.example")

	// The two-key request from the issue body: only rpID and blocked.
	partialData := buildVendorConfigRequest(t, map[interface{}]interface{}{
		vendorParamKeyVendorCmd: uint8(VendorCmdSetRPPolicy),
		vendorParamKeyRPID:      "rp.example",
		vendorParamKeyBlocked:   true,
	})
	resp, err := auth.handleConfig(partialData)
	require.NoError(t, err)
	require.Equal(t, uint8(StatusOK), resp[0])

	loaded, err := auth.rpPolicyStore.GetPolicy("rp.example")
	require.NoError(t, err)
	assert.Equal(t, "required", loaded.UVOverride, "UVOverride must survive the partial request")
	require.NotNil(t, loaded.UPOverride, "UPOverride must survive the partial request")
	assert.True(t, *loaded.UPOverride)
	assert.Equal(t, "direct", loaded.AttestationOverride, "AttestationOverride must survive the partial request")
	assert.True(t, loaded.Enterprise, "Enterprise must survive the partial request")
	assert.True(t, loaded.Blocked, "Blocked was carried by the request and must change")
}

// TestVendorSetRPPolicy_BlockSurvivesUnrelatedRequest asserts the sharpest
// consequence of #321 on the wire: blocking an RP and later setting an
// unrelated field must not lift the block.
func TestVendorSetRPPolicy_BlockSurvivesUnrelatedRequest(t *testing.T) {
	auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
	defer func() { _ = auth.Close() }()

	blockData := buildVendorConfigRequest(t, map[interface{}]interface{}{
		vendorParamKeyVendorCmd: uint8(VendorCmdSetRPPolicy),
		vendorParamKeyRPID:      "blocked.example",
		vendorParamKeyBlocked:   true,
	})
	resp, err := auth.handleConfig(blockData)
	require.NoError(t, err)
	require.Equal(t, uint8(StatusOK), resp[0])

	uvData := buildVendorConfigRequest(t, map[interface{}]interface{}{
		vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
		vendorParamKeyRPID:       "blocked.example",
		vendorParamKeyUVOverride: "required",
	})
	resp, err = auth.handleConfig(uvData)
	require.NoError(t, err)
	require.Equal(t, uint8(StatusOK), resp[0])

	loaded, err := auth.rpPolicyStore.GetPolicy("blocked.example")
	require.NoError(t, err)
	assert.True(t, loaded.Blocked, "a request that omits blocked must not lift the RP block")
	assert.Equal(t, "required", loaded.UVOverride)
}

// TestVendorSetRPPolicy_ExplicitFalseUnblocks asserts the distinction the
// presence-carrying update must preserve: a key explicitly present with a
// zero value does take effect.
func TestVendorSetRPPolicy_ExplicitFalseUnblocks(t *testing.T) {
	auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
	defer func() { _ = auth.Close() }()

	setFullVendorRPPolicy(t, auth, "unblock.example")

	blockData := buildVendorConfigRequest(t, map[interface{}]interface{}{
		vendorParamKeyVendorCmd: uint8(VendorCmdSetRPPolicy),
		vendorParamKeyRPID:      "unblock.example",
		vendorParamKeyBlocked:   true,
	})
	resp, err := auth.handleConfig(blockData)
	require.NoError(t, err)
	require.Equal(t, uint8(StatusOK), resp[0])

	unblockData := buildVendorConfigRequest(t, map[interface{}]interface{}{
		vendorParamKeyVendorCmd: uint8(VendorCmdSetRPPolicy),
		vendorParamKeyRPID:      "unblock.example",
		vendorParamKeyBlocked:   false,
	})
	resp, err = auth.handleConfig(unblockData)
	require.NoError(t, err)
	require.Equal(t, uint8(StatusOK), resp[0])

	loaded, err := auth.rpPolicyStore.GetPolicy("unblock.example")
	require.NoError(t, err)
	assert.False(t, loaded.Blocked, "an explicit blocked=false must lift the block")
	assert.Equal(t, "required", loaded.UVOverride, "the other governance fields must survive")
	assert.True(t, loaded.Enterprise)
}

// TestVendorSetRPPolicy_InvalidUVOverrideRejected verifies an invalid value
// in a partial request is refused and leaves the stored policy untouched.
func TestVendorSetRPPolicy_InvalidUVOverrideRejected(t *testing.T) {
	auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
	defer func() { _ = auth.Close() }()

	setFullVendorRPPolicy(t, auth, "invalid.example")

	badData := buildVendorConfigRequest(t, map[interface{}]interface{}{
		vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
		vendorParamKeyRPID:       "invalid.example",
		vendorParamKeyUVOverride: "sometimes",
	})
	_, err := auth.handleConfig(badData)
	require.Error(t, err)

	loaded, err := auth.rpPolicyStore.GetPolicy("invalid.example")
	require.NoError(t, err)
	assert.Equal(t, "required", loaded.UVOverride, "a rejected request must not change the stored policy")
}

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

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// createTestConfigAuthenticatorWithRPPolicyStore creates an authenticator with
// SO PIN initialized, SO unlocked, and an in-memory RP policy store configured.
func createTestConfigAuthenticatorWithRPPolicyStore(t *testing.T) *Authenticator {
	t.Helper()

	storage := NewMemoryStorage()
	config := &Config{
		Storage:             storage,
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       8,
		SupportedAlgorithms: []int{COSEAlgES256},
		RPPolicyStore:       NewMemoryRPPolicyStore(),
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	// Initialize SO PIN and leave it unlocked
	err = auth.keyManager.InitializeSOPIN("securepin123")
	require.NoError(t, err)
	require.True(t, auth.keyManager.IsSOUnlocked())

	return auth
}

// createTestConfigAuthenticatorWithRPPolicyStoreLocked creates an authenticator
// with SO PIN initialized, RP policy store configured, but SO locked.
func createTestConfigAuthenticatorWithRPPolicyStoreLocked(t *testing.T) *Authenticator {
	t.Helper()

	auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
	auth.keyManager.Lock()
	require.False(t, auth.keyManager.IsSOUnlocked())

	return auth
}

// buildVendorConfigRequest encodes a vendor subcommand request as CBOR for
// use with handleConfig or ProcessCBOR(CmdConfig, ...).
func buildVendorConfigRequest(t *testing.T, params map[interface{}]interface{}) []byte {
	t.Helper()

	data, err := cbor.Marshal(map[int]interface{}{
		configKeySubCommand:       uint8(AuthConfigCmdVendorPrototype),
		configKeySubCommandParams: params,
	})
	require.NoError(t, err)
	return data
}

// TestVendorRPPolicySetAndGet verifies that an RP policy can be created via the
// VendorCmdSetRPPolicy vendor command and retrieved via VendorCmdGetRPPolicy.
func TestVendorRPPolicySetAndGet(t *testing.T) {
	t.Run("set and get basic policy", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Set policy via vendor command
		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "example.com",
			vendorParamKeyUVOverride: "required",
		}

		setData := buildVendorConfigRequest(t, setParams)
		resp, err := auth.handleConfig(setData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Retrieve policy via vendor command
		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "example.com",
		}

		getData := buildVendorConfigRequest(t, getParams)
		getResp, err := auth.handleConfig(getData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), getResp[0])

		// Decode the CBOR response payload (skip status byte)
		var respMap map[int]interface{}
		err = cbor.Unmarshal(getResp[1:], &respMap)
		require.NoError(t, err)

		policyRaw, ok := respMap[configResponseKeyPolicy]
		require.True(t, ok, "response must contain policy key")

		policyMap, ok := policyRaw.(map[interface{}]interface{})
		require.True(t, ok, "policy must be a map")

		require.Equal(t, "example.com", policyMap["rpId"])
		require.Equal(t, "required", policyMap["uvOverride"])
	})

	t.Run("set policy with all fields", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:      uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:           "corp.example.com",
			vendorParamKeyUVOverride:     "discouraged",
			vendorParamKeyAttestOverride: "enterprise",
			vendorParamKeyUPOverride:     false,
			vendorParamKeyEnterprise:     true,
			vendorParamKeyBlocked:        false,
		}

		setData := buildVendorConfigRequest(t, setParams)
		resp, err := auth.handleConfig(setData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Get the policy back and verify all fields
		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "corp.example.com",
		}

		getData := buildVendorConfigRequest(t, getParams)
		getResp, err := auth.handleConfig(getData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), getResp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(getResp[1:], &respMap)
		require.NoError(t, err)

		policyMap, ok := respMap[configResponseKeyPolicy].(map[interface{}]interface{})
		require.True(t, ok)

		require.Equal(t, "corp.example.com", policyMap["rpId"])
		require.Equal(t, "discouraged", policyMap["uvOverride"])
		require.Equal(t, "enterprise", policyMap["attestationOverride"])
		require.Equal(t, false, policyMap["upOverride"])
		require.Equal(t, true, policyMap["enterprise"])
		// Blocked is false, so it should not be present in the response
		_, blockedPresent := policyMap["blocked"]
		require.False(t, blockedPresent, "blocked=false should be omitted from response")
	})

	t.Run("get nonexistent policy returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "nonexistent.example.com",
		}

		getData := buildVendorConfigRequest(t, getParams)
		_, err := auth.handleConfig(getData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrRPPolicyNotFound)
	})

	t.Run("set policy missing rpId returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyUVOverride: "required",
			// Missing rpId
		}

		setData := buildVendorConfigRequest(t, setParams)
		_, err := auth.handleConfig(setData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
	})

	t.Run("get policy missing rpId returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			// Missing rpId
		}

		getData := buildVendorConfigRequest(t, getParams)
		_, err := auth.handleConfig(getData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
	})

	t.Run("set policy overwrites existing", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Set initial policy
		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "overwrite.example.com",
			vendorParamKeyUVOverride: "required",
		}
		setData := buildVendorConfigRequest(t, setParams)
		resp, err := auth.handleConfig(setData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Overwrite with new UV override
		updateParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "overwrite.example.com",
			vendorParamKeyUVOverride: "discouraged",
		}
		updateData := buildVendorConfigRequest(t, updateParams)
		resp, err = auth.handleConfig(updateData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Verify the update took effect
		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "overwrite.example.com",
		}
		getData := buildVendorConfigRequest(t, getParams)
		getResp, err := auth.handleConfig(getData)
		require.NoError(t, err)

		var respMap map[int]interface{}
		err = cbor.Unmarshal(getResp[1:], &respMap)
		require.NoError(t, err)

		policyMap := respMap[configResponseKeyPolicy].(map[interface{}]interface{})
		require.Equal(t, "discouraged", policyMap["uvOverride"])
	})
}

// TestVendorRPPolicyDelete verifies that an RP policy can be deleted via the
// VendorCmdDeleteRPPolicy vendor command.
func TestVendorRPPolicyDelete(t *testing.T) {
	t.Run("set then delete policy", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Set a policy
		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "delete-me.example.com",
			vendorParamKeyUVOverride: "required",
		}
		setData := buildVendorConfigRequest(t, setParams)
		resp, err := auth.handleConfig(setData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Delete the policy
		delParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdDeleteRPPolicy),
			vendorParamKeyRPID:      "delete-me.example.com",
		}
		delData := buildVendorConfigRequest(t, delParams)
		resp, err = auth.handleConfig(delData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Verify the policy is gone
		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "delete-me.example.com",
		}
		getData := buildVendorConfigRequest(t, getParams)
		_, err = auth.handleConfig(getData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrRPPolicyNotFound)
	})

	t.Run("delete nonexistent policy returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		delParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdDeleteRPPolicy),
			vendorParamKeyRPID:      "nonexistent.example.com",
		}
		delData := buildVendorConfigRequest(t, delParams)
		_, err := auth.handleConfig(delData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrRPPolicyNotFound)
	})

	t.Run("delete policy missing rpId returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		delParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdDeleteRPPolicy),
			// Missing rpId
		}
		delData := buildVendorConfigRequest(t, delParams)
		_, err := auth.handleConfig(delData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrRPPolicyInvalidRPID)
	})

	t.Run("delete policy with nil rpPolicyStore returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Clear the policy store to simulate nil
		auth.rpPolicyStore = nil

		delParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdDeleteRPPolicy),
			vendorParamKeyRPID:      "example.com",
		}
		delData := buildVendorConfigRequest(t, delParams)
		_, err := auth.handleConfig(delData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})
}

// TestVendorRPPolicyList verifies that multiple RP policies can be listed via
// the VendorCmdListRPPolicies vendor command.
func TestVendorRPPolicyList(t *testing.T) {
	t.Run("list multiple policies", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Set multiple policies
		rpIDs := []string{"alpha.example.com", "beta.example.com", "gamma.example.com"}
		for _, rpID := range rpIDs {
			setParams := map[interface{}]interface{}{
				vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
				vendorParamKeyRPID:       rpID,
				vendorParamKeyUVOverride: "required",
			}
			setData := buildVendorConfigRequest(t, setParams)
			resp, err := auth.handleConfig(setData)
			require.NoError(t, err)
			require.Equal(t, uint8(StatusOK), resp[0])
		}

		// List all policies
		listParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdListRPPolicies),
		}
		listData := buildVendorConfigRequest(t, listParams)
		listResp, err := auth.handleConfig(listData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), listResp[0])

		// Decode response
		var respMap map[int]interface{}
		err = cbor.Unmarshal(listResp[1:], &respMap)
		require.NoError(t, err)

		policiesRaw, ok := respMap[configResponseKeyPolicies]
		require.True(t, ok, "response must contain policies key")

		policiesList, ok := policiesRaw.([]interface{})
		require.True(t, ok, "policies must be an array")
		require.Equal(t, len(rpIDs), len(policiesList))

		// Collect all returned RPIDs
		returnedRPIDs := make(map[string]bool)
		for _, pRaw := range policiesList {
			policyMap, ok := pRaw.(map[interface{}]interface{})
			require.True(t, ok)
			rpID, ok := policyMap["rpId"].(string)
			require.True(t, ok)
			returnedRPIDs[rpID] = true
		}

		for _, rpID := range rpIDs {
			require.True(t, returnedRPIDs[rpID], "expected RPID %q in list response", rpID)
		}
	})

	t.Run("list empty policies returns empty list", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		listParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdListRPPolicies),
		}
		listData := buildVendorConfigRequest(t, listParams)
		listResp, err := auth.handleConfig(listData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), listResp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(listResp[1:], &respMap)
		require.NoError(t, err)

		policiesRaw, ok := respMap[configResponseKeyPolicies]
		require.True(t, ok)

		policiesList, ok := policiesRaw.([]interface{})
		require.True(t, ok)
		require.Empty(t, policiesList)
	})

	t.Run("list policies with nil rpPolicyStore returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		auth.rpPolicyStore = nil

		listParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdListRPPolicies),
		}
		listData := buildVendorConfigRequest(t, listParams)
		_, err := auth.handleConfig(listData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})
}

// TestVendorRPPolicyRequiresSOUnlock verifies that SetRPPolicy, DeleteRPPolicy,
// and related write operations fail when the SO is not unlocked.
func TestVendorRPPolicyRequiresSOUnlock(t *testing.T) {
	t.Run("SetRPPolicy fails without SO unlock", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStoreLocked(t)
		defer func() { _ = auth.Close() }()

		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "example.com",
			vendorParamKeyUVOverride: "required",
		}
		setData := buildVendorConfigRequest(t, setParams)
		_, err := auth.handleConfig(setData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("DeleteRPPolicy fails without SO unlock", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStoreLocked(t)
		defer func() { _ = auth.Close() }()

		delParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdDeleteRPPolicy),
			vendorParamKeyRPID:      "example.com",
		}
		delData := buildVendorConfigRequest(t, delParams)
		_, err := auth.handleConfig(delData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("SetRPPolicy fails with nil keyManager", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		auth.keyManager = nil

		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "example.com",
			vendorParamKeyUVOverride: "required",
		}
		setData := buildVendorConfigRequest(t, setParams)
		_, err := auth.handleConfig(setData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("GetRPPolicy succeeds without SO unlock", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Set a policy while SO is unlocked
		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "readable.example.com",
			vendorParamKeyUVOverride: "preferred",
		}
		setData := buildVendorConfigRequest(t, setParams)
		resp, err := auth.handleConfig(setData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Lock the SO
		auth.keyManager.Lock()
		require.False(t, auth.keyManager.IsSOUnlocked())

		// GetRPPolicy should still work without SO unlock
		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "readable.example.com",
		}
		getData := buildVendorConfigRequest(t, getParams)
		getResp, err := auth.handleConfig(getData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), getResp[0])
	})

	t.Run("ListRPPolicies succeeds without SO unlock", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Lock the SO
		auth.keyManager.Lock()
		require.False(t, auth.keyManager.IsSOUnlocked())

		// ListRPPolicies should still work
		listParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdListRPPolicies),
		}
		listData := buildVendorConfigRequest(t, listParams)
		listResp, err := auth.handleConfig(listData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), listResp[0])
	})
}

// TestVendorRPPolicyGetWithNoStore verifies that GetRPPolicy and ListRPPolicies
// return an error when the rpPolicyStore is nil.
func TestVendorRPPolicyGetWithNoStore(t *testing.T) {
	t.Run("GetRPPolicy with nil store returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		// auth has no rpPolicyStore by default
		require.Nil(t, auth.rpPolicyStore)

		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "example.com",
		}
		getData := buildVendorConfigRequest(t, getParams)
		_, err := auth.handleConfig(getData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("ListRPPolicies with nil store returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticator(t)
		defer func() { _ = auth.Close() }()

		require.Nil(t, auth.rpPolicyStore)

		listParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdListRPPolicies),
		}
		listData := buildVendorConfigRequest(t, listParams)
		_, err := auth.handleConfig(listData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("SetRPPolicy with nil store returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		// SO is unlocked but no rpPolicyStore
		require.Nil(t, auth.rpPolicyStore)

		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "example.com",
			vendorParamKeyUVOverride: "required",
		}
		setData := buildVendorConfigRequest(t, setParams)
		_, err := auth.handleConfig(setData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})

	t.Run("DeleteRPPolicy with nil store returns error", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithSOPIN(t)
		defer func() { _ = auth.Close() }()

		require.Nil(t, auth.rpPolicyStore)

		delParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdDeleteRPPolicy),
			vendorParamKeyRPID:      "example.com",
		}
		delData := buildVendorConfigRequest(t, delParams)
		_, err := auth.handleConfig(delData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrInvalidParameter)
	})
}

// TestVendorSetProfile verifies the VendorCmdSetProfile vendor command
// for configuring transports and enterprise attestation.
func TestVendorSetProfile(t *testing.T) {
	t.Run("set transports", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		profileParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetProfile),
			vendorParamKeyTransports: []interface{}{
				"usb", "nfc", "ble",
			},
		}
		profileData := buildVendorConfigRequest(t, profileParams)
		resp, err := auth.handleConfig(profileData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		require.Equal(t, []string{"usb", "nfc", "ble"}, auth.config.Transports)
	})

	t.Run("enable enterprise attestation", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		require.False(t, auth.config.EnableEnterpriseAttestation)

		profileParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetProfile),
			vendorParamKeyEnableEP:  true,
		}
		profileData := buildVendorConfigRequest(t, profileParams)
		resp, err := auth.handleConfig(profileData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		require.True(t, auth.config.EnableEnterpriseAttestation)
	})

	t.Run("set transports and enterprise attestation together", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		profileParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetProfile),
			vendorParamKeyTransports: []interface{}{"internal", "hybrid"},
			vendorParamKeyEnableEP:   true,
		}
		profileData := buildVendorConfigRequest(t, profileParams)
		resp, err := auth.handleConfig(profileData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		require.Equal(t, []string{"internal", "hybrid"}, auth.config.Transports)
		require.True(t, auth.config.EnableEnterpriseAttestation)
	})

	t.Run("disable enterprise attestation", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Enable first
		auth.config.EnableEnterpriseAttestation = true

		profileParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetProfile),
			vendorParamKeyEnableEP:  false,
		}
		profileData := buildVendorConfigRequest(t, profileParams)
		resp, err := auth.handleConfig(profileData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		require.False(t, auth.config.EnableEnterpriseAttestation)
	})

	t.Run("empty transports list does not overwrite", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		original := auth.config.Transports

		// Send empty transports list (should not overwrite due to len check)
		profileParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetProfile),
			vendorParamKeyTransports: []interface{}{},
		}
		profileData := buildVendorConfigRequest(t, profileParams)
		resp, err := auth.handleConfig(profileData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		require.Equal(t, original, auth.config.Transports)
	})

	t.Run("no profile fields is a no-op success", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		originalTransports := auth.config.Transports
		originalEP := auth.config.EnableEnterpriseAttestation

		profileParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetProfile),
		}
		profileData := buildVendorConfigRequest(t, profileParams)
		resp, err := auth.handleConfig(profileData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		require.Equal(t, originalTransports, auth.config.Transports)
		require.Equal(t, originalEP, auth.config.EnableEnterpriseAttestation)
	})
}

// TestVendorSetProfileRequiresSOUnlock verifies that VendorCmdSetProfile
// fails when the SO is not unlocked.
func TestVendorSetProfileRequiresSOUnlock(t *testing.T) {
	t.Run("SetProfile fails without SO unlock", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStoreLocked(t)
		defer func() { _ = auth.Close() }()

		profileParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetProfile),
			vendorParamKeyTransports: []interface{}{"usb"},
		}
		profileData := buildVendorConfigRequest(t, profileParams)
		_, err := auth.handleConfig(profileData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})

	t.Run("SetProfile fails with nil keyManager", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		auth.keyManager = nil

		profileParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetProfile),
			vendorParamKeyEnableEP:  true,
		}
		profileData := buildVendorConfigRequest(t, profileParams)
		_, err := auth.handleConfig(profileData)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrKeyManagerLocked)
	})
}

// TestVendorRPPolicyProcessCBOR verifies vendor RP policy commands work
// through the public ProcessCBOR entry point.
func TestVendorRPPolicyProcessCBOR(t *testing.T) {
	t.Run("set and get policy via ProcessCBOR", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Set policy via ProcessCBOR
		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd:  uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:       "processcbor.example.com",
			vendorParamKeyUVOverride: "preferred",
			vendorParamKeyBlocked:    true,
		}
		setData := buildVendorConfigRequest(t, setParams)
		resp, err := auth.ProcessCBOR(CmdConfig, setData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Get policy via ProcessCBOR
		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "processcbor.example.com",
		}
		getData := buildVendorConfigRequest(t, getParams)
		getResp, err := auth.ProcessCBOR(CmdConfig, getData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), getResp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(getResp[1:], &respMap)
		require.NoError(t, err)

		policyMap := respMap[configResponseKeyPolicy].(map[interface{}]interface{})
		require.Equal(t, "processcbor.example.com", policyMap["rpId"])
		require.Equal(t, "preferred", policyMap["uvOverride"])
		require.Equal(t, true, policyMap["blocked"])
	})

	t.Run("list policies via ProcessCBOR", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Set two policies
		for _, rpID := range []string{"one.example.com", "two.example.com"} {
			setParams := map[interface{}]interface{}{
				vendorParamKeyVendorCmd: uint8(VendorCmdSetRPPolicy),
				vendorParamKeyRPID:      rpID,
			}
			setData := buildVendorConfigRequest(t, setParams)
			resp, err := auth.ProcessCBOR(CmdConfig, setData)
			require.NoError(t, err)
			require.Equal(t, uint8(StatusOK), resp[0])
		}

		// List via ProcessCBOR
		listParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdListRPPolicies),
		}
		listData := buildVendorConfigRequest(t, listParams)
		listResp, err := auth.ProcessCBOR(CmdConfig, listData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), listResp[0])

		var respMap map[int]interface{}
		err = cbor.Unmarshal(listResp[1:], &respMap)
		require.NoError(t, err)

		policiesList := respMap[configResponseKeyPolicies].([]interface{})
		require.Len(t, policiesList, 2)
	})

	t.Run("delete policy via ProcessCBOR", func(t *testing.T) {
		auth := createTestConfigAuthenticatorWithRPPolicyStore(t)
		defer func() { _ = auth.Close() }()

		// Set a policy
		setParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdSetRPPolicy),
			vendorParamKeyRPID:      "deletable.example.com",
		}
		setData := buildVendorConfigRequest(t, setParams)
		resp, err := auth.ProcessCBOR(CmdConfig, setData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Delete via ProcessCBOR
		delParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdDeleteRPPolicy),
			vendorParamKeyRPID:      "deletable.example.com",
		}
		delData := buildVendorConfigRequest(t, delParams)
		resp, err = auth.ProcessCBOR(CmdConfig, delData)
		require.NoError(t, err)
		require.Equal(t, uint8(StatusOK), resp[0])

		// Verify deleted
		getParams := map[interface{}]interface{}{
			vendorParamKeyVendorCmd: uint8(VendorCmdGetRPPolicy),
			vendorParamKeyRPID:      "deletable.example.com",
		}
		getData := buildVendorConfigRequest(t, getParams)
		_, err = auth.ProcessCBOR(CmdConfig, getData)
		require.Error(t, err)
	})
}

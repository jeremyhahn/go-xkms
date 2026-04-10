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

package config

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	require.NotNil(t, p)

	assert.Equal(t, 6, p.MinPINLength)
	assert.Equal(t, 5, p.PINMaxAttempts)
	assert.True(t, p.RequireSOPIN)
	assert.True(t, p.RequireUserPIN)
	assert.True(t, p.RequireEncryptedStorage)
	assert.Equal(t, "barrier", p.StorageType)
	assert.True(t, p.UserCanConfigureAutoUnseal)
	assert.True(t, p.UserCanConfigureTheme)
	assert.True(t, p.UserCanManageTrustStore)
	assert.True(t, p.UserCanViewAuditLog)
	assert.True(t, p.UserCanManageSealedData)
	assert.True(t, p.UserCanChangeOwnPIN)
	assert.True(t, p.APIExplorerEnabled)
	assert.True(t, p.FIDO2RequireUserPresence)
	assert.True(t, p.FIDO2UserIntentCheck)
	assert.True(t, p.ExtensionEnabled)
	assert.True(t, p.ExtensionRequireAuthentication)
	assert.True(t, p.ExtensionRequirePairing)
	assert.True(t, p.ExtensionForceAudit)
	assert.True(t, p.UserCanConfigureExtension)
	assert.Equal(t, 1, p.PolicyVersion)
}

func TestDefaultPolicyZeroFields(t *testing.T) {
	p := DefaultPolicy()
	require.NotNil(t, p)

	// These fields must NOT be set by DefaultPolicy.
	assert.False(t, p.RequireTPM)
	assert.False(t, p.RequirePlatformPolicy)
	assert.Nil(t, p.PlatformPCRs)
	assert.Empty(t, p.PlatformPCRBank)
	assert.False(t, p.RequirePasswordProtection)
	assert.Empty(t, p.PasswordProtectionMode)
	assert.Nil(t, p.AllowedBackends)
	assert.Empty(t, p.DefaultBackend)
	assert.False(t, p.FIDO2AlwaysUV)
	assert.False(t, p.FIDO2RequireResidentKey)
	assert.Empty(t, p.AttestationMode)
	assert.False(t, p.AllowAutoUnseal)
	assert.Empty(t, p.APIExplorerSandboxPolicy)
	assert.Nil(t, p.ExtensionAllowedDomains)
	assert.Nil(t, p.ExtensionBlockedDomains)
	assert.Equal(t, 0, p.ExtensionMaxFillsPerMinute)
	assert.Empty(t, p.OrganizationName)
}

func TestPolicyCanonicalJSON_Valid(t *testing.T) {
	_ = t.TempDir()

	p := DefaultPolicy()

	data, err := PolicyCanonicalJSON(p)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Must be valid JSON.
	assert.True(t, json.Valid(data))

	// Must unmarshal back to an equivalent policy.
	var restored PolicySection
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, p.MinPINLength, restored.MinPINLength)
	assert.Equal(t, p.RequireSOPIN, restored.RequireSOPIN)
	assert.Equal(t, p.RequireUserPIN, restored.RequireUserPIN)
	assert.Equal(t, p.RequireEncryptedStorage, restored.RequireEncryptedStorage)
	assert.Equal(t, p.StorageType, restored.StorageType)
	assert.Equal(t, p.PolicyVersion, restored.PolicyVersion)
	assert.Equal(t, p.UserCanConfigureAutoUnseal, restored.UserCanConfigureAutoUnseal)
	assert.Equal(t, p.UserCanConfigureTheme, restored.UserCanConfigureTheme)
	assert.Equal(t, p.UserCanManageTrustStore, restored.UserCanManageTrustStore)
	assert.Equal(t, p.UserCanViewAuditLog, restored.UserCanViewAuditLog)
	assert.Equal(t, p.UserCanManageSealedData, restored.UserCanManageSealedData)
	assert.Equal(t, p.UserCanChangeOwnPIN, restored.UserCanChangeOwnPIN)
	assert.Equal(t, p.APIExplorerEnabled, restored.APIExplorerEnabled)
	assert.Equal(t, p.APIExplorerSandboxPolicy, restored.APIExplorerSandboxPolicy)
	assert.Equal(t, p.FIDO2RequireUserPresence, restored.FIDO2RequireUserPresence)
	assert.Equal(t, p.FIDO2UserIntentCheck, restored.FIDO2UserIntentCheck)
	assert.Equal(t, p.ExtensionEnabled, restored.ExtensionEnabled)
	assert.Equal(t, p.ExtensionRequireAuthentication, restored.ExtensionRequireAuthentication)
	assert.Equal(t, p.ExtensionRequirePairing, restored.ExtensionRequirePairing)
	assert.Equal(t, p.ExtensionForceAudit, restored.ExtensionForceAudit)
	assert.Equal(t, p.ExtensionAllowedDomains, restored.ExtensionAllowedDomains)
	assert.Equal(t, p.ExtensionBlockedDomains, restored.ExtensionBlockedDomains)
	assert.Equal(t, p.ExtensionMaxFillsPerMinute, restored.ExtensionMaxFillsPerMinute)
	assert.Equal(t, p.UserCanConfigureExtension, restored.UserCanConfigureExtension)
}

func TestPolicyCanonicalJSON_Deterministic(t *testing.T) {
	p := DefaultPolicy()

	data1, err1 := PolicyCanonicalJSON(p)
	require.NoError(t, err1)

	data2, err2 := PolicyCanonicalJSON(p)
	require.NoError(t, err2)

	assert.True(t, bytes.Equal(data1, data2),
		"two calls to PolicyCanonicalJSON on the same policy must produce identical bytes")
}

func TestPolicyCanonicalJSON_DifferentPoliciesProduceDifferentJSON(t *testing.T) {
	p1 := DefaultPolicy()

	p2 := DefaultPolicy()
	p2.MinPINLength = 12
	p2.OrganizationName = "ACME Corp"
	p2.PolicyVersion = 2

	data1, err := PolicyCanonicalJSON(p1)
	require.NoError(t, err)

	data2, err := PolicyCanonicalJSON(p2)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(data1, data2),
		"different policies must produce different JSON output")
}

func TestPolicyCanonicalJSON_NilPolicy(t *testing.T) {
	data, err := PolicyCanonicalJSON(nil)

	// json.Marshal(nil) returns "null" without error. We verify the
	// function does not panic and returns something sensible.
	if err != nil {
		// If the implementation guards against nil, an error is acceptable.
		assert.Nil(t, data)
		return
	}
	// Otherwise, json.Marshal produces "null" for a nil pointer.
	assert.Equal(t, []byte("null"), data)
}

func TestPolicyCanonicalJSON_FieldOrder(t *testing.T) {
	p := DefaultPolicy()

	data, err := PolicyCanonicalJSON(p)
	require.NoError(t, err)

	// Use json.Decoder to extract keys in the order they appear.
	dec := json.NewDecoder(bytes.NewReader(data))

	// Consume opening '{'.
	tok, err := dec.Token()
	require.NoError(t, err)
	delim, ok := tok.(json.Delim)
	require.True(t, ok)
	assert.Equal(t, json.Delim('{'), delim)

	var keys []string
	for dec.More() {
		tok, err = dec.Token()
		require.NoError(t, err)

		key, ok := tok.(string)
		require.True(t, ok, "expected string key, got %T", tok)
		keys = append(keys, key)

		// Consume the value token (skip it).
		var raw json.RawMessage
		err = dec.Decode(&raw)
		require.NoError(t, err)
	}

	// The expected field order matches the JSON struct tag order in PolicySection.
	expectedOrder := []string{
		"min_pin_length",
		"pin_max_attempts",
		"require_so_pin",
		"require_user_pin",
		"require_encrypted_storage",
		"storage_type",
		"require_tpm",
		"require_platform_policy",
		"platform_pcrs",
		"platform_pcr_bank",
		"require_password_protection",
		"password_protection_mode",
		"allowed_backends",
		"default_backend",
		"fido2_always_uv",
		"fido2_require_resident_key",
		"fido2_require_user_presence",
		"fido2_user_intent_check",
		"attestation_mode",
		"allow_auto_unseal",
		"user_can_configure_auto_unseal",
		"user_can_configure_theme",
		"user_can_manage_trust_store",
		"user_can_view_audit_log",
		"user_can_manage_sealed_data",
		"user_can_change_own_pin",
		"api_explorer_enabled",
		"api_explorer_sandbox_policy",
		"developer_tools_enabled",
		"user_can_toggle_dev_tools",
		"extension_enabled",
		"extension_require_authentication",
		"extension_require_pairing",
		"extension_force_audit",
		"extension_allowed_domains",
		"extension_blocked_domains",
		"extension_max_fills_per_minute",
		"user_can_configure_extension",
		"organization_name",
		"policy_version",
	}

	assert.Equal(t, expectedOrder, keys,
		"JSON field order must match struct declaration order")
}

func TestPolicyCanonicalJSON_WithAllFields(t *testing.T) {
	_ = t.TempDir()

	p := &PolicySection{
		MinPINLength:                   8,
		RequireSOPIN:                   true,
		RequireUserPIN:                 true,
		RequireEncryptedStorage:        true,
		StorageType:                    "barrier",
		RequireTPM:                     true,
		RequirePlatformPolicy:          true,
		PlatformPCRs:                   []int{0, 1, 7},
		PlatformPCRBank:                "sha256",
		RequirePasswordProtection:      true,
		PasswordProtectionMode:         "argon2id",
		AllowedBackends:                []string{"software", "tpm2"},
		DefaultBackend:                 "tpm2",
		FIDO2AlwaysUV:                  true,
		FIDO2RequireResidentKey:        true,
		FIDO2RequireUserPresence:       true,
		FIDO2UserIntentCheck:           true,
		AttestationMode:                "packed",
		AllowAutoUnseal:                true,
		UserCanConfigureAutoUnseal:     false,
		UserCanConfigureTheme:          false,
		UserCanManageTrustStore:        false,
		UserCanViewAuditLog:            false,
		UserCanManageSealedData:        false,
		UserCanChangeOwnPIN:            false,
		APIExplorerEnabled:             true,
		APIExplorerSandboxPolicy:       "strict",
		DeveloperToolsEnabled:          true,
		UserCanToggleDevTools:          true,
		ExtensionEnabled:               true,
		ExtensionRequireAuthentication: true,
		ExtensionRequirePairing:        true,
		ExtensionForceAudit:            true,
		ExtensionAllowedDomains:        []string{"example.com", "corp.internal"},
		ExtensionBlockedDomains:        []string{"evil.com"},
		ExtensionMaxFillsPerMinute:     30,
		UserCanConfigureExtension:      false,
		OrganizationName:               "Test Organization",
		PolicyVersion:                  42,
	}

	data, err := PolicyCanonicalJSON(p)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	assert.True(t, json.Valid(data))

	// Unmarshal and verify all fields survived.
	var restored PolicySection
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, p.MinPINLength, restored.MinPINLength)
	assert.Equal(t, p.RequireSOPIN, restored.RequireSOPIN)
	assert.Equal(t, p.RequireUserPIN, restored.RequireUserPIN)
	assert.Equal(t, p.RequireEncryptedStorage, restored.RequireEncryptedStorage)
	assert.Equal(t, p.StorageType, restored.StorageType)
	assert.Equal(t, p.RequireTPM, restored.RequireTPM)
	assert.Equal(t, p.RequirePlatformPolicy, restored.RequirePlatformPolicy)
	assert.Equal(t, p.PlatformPCRs, restored.PlatformPCRs)
	assert.Equal(t, p.PlatformPCRBank, restored.PlatformPCRBank)
	assert.Equal(t, p.RequirePasswordProtection, restored.RequirePasswordProtection)
	assert.Equal(t, p.PasswordProtectionMode, restored.PasswordProtectionMode)
	assert.Equal(t, p.AllowedBackends, restored.AllowedBackends)
	assert.Equal(t, p.DefaultBackend, restored.DefaultBackend)
	assert.Equal(t, p.FIDO2AlwaysUV, restored.FIDO2AlwaysUV)
	assert.Equal(t, p.FIDO2RequireResidentKey, restored.FIDO2RequireResidentKey)
	assert.Equal(t, p.FIDO2RequireUserPresence, restored.FIDO2RequireUserPresence)
	assert.Equal(t, p.FIDO2UserIntentCheck, restored.FIDO2UserIntentCheck)
	assert.Equal(t, p.AttestationMode, restored.AttestationMode)
	assert.Equal(t, p.AllowAutoUnseal, restored.AllowAutoUnseal)
	assert.Equal(t, p.UserCanConfigureAutoUnseal, restored.UserCanConfigureAutoUnseal)
	assert.Equal(t, p.UserCanConfigureTheme, restored.UserCanConfigureTheme)
	assert.Equal(t, p.UserCanManageTrustStore, restored.UserCanManageTrustStore)
	assert.Equal(t, p.UserCanViewAuditLog, restored.UserCanViewAuditLog)
	assert.Equal(t, p.UserCanManageSealedData, restored.UserCanManageSealedData)
	assert.Equal(t, p.UserCanChangeOwnPIN, restored.UserCanChangeOwnPIN)
	assert.Equal(t, p.APIExplorerEnabled, restored.APIExplorerEnabled)
	assert.Equal(t, p.APIExplorerSandboxPolicy, restored.APIExplorerSandboxPolicy)
	assert.Equal(t, p.DeveloperToolsEnabled, restored.DeveloperToolsEnabled)
	assert.Equal(t, p.UserCanToggleDevTools, restored.UserCanToggleDevTools)
	assert.Equal(t, p.ExtensionEnabled, restored.ExtensionEnabled)
	assert.Equal(t, p.ExtensionRequireAuthentication, restored.ExtensionRequireAuthentication)
	assert.Equal(t, p.ExtensionRequirePairing, restored.ExtensionRequirePairing)
	assert.Equal(t, p.ExtensionForceAudit, restored.ExtensionForceAudit)
	assert.Equal(t, p.ExtensionAllowedDomains, restored.ExtensionAllowedDomains)
	assert.Equal(t, p.ExtensionBlockedDomains, restored.ExtensionBlockedDomains)
	assert.Equal(t, p.ExtensionMaxFillsPerMinute, restored.ExtensionMaxFillsPerMinute)
	assert.Equal(t, p.UserCanConfigureExtension, restored.UserCanConfigureExtension)
	assert.Equal(t, p.OrganizationName, restored.OrganizationName)
	assert.Equal(t, p.PolicyVersion, restored.PolicyVersion)

	// Verify specific values appear in the raw JSON.
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"min_pin_length":8`)
	assert.Contains(t, jsonStr, `"organization_name":"Test Organization"`)
	assert.Contains(t, jsonStr, `"policy_version":42`)
	assert.Contains(t, jsonStr, `"platform_pcrs":[0,1,7]`)
	assert.Contains(t, jsonStr, `"allowed_backends":["software","tpm2"]`)
	assert.Contains(t, jsonStr, `"api_explorer_enabled":true`)
	assert.Contains(t, jsonStr, `"api_explorer_sandbox_policy":"strict"`)
	assert.Contains(t, jsonStr, `"fido2_require_user_presence":true`)
	assert.Contains(t, jsonStr, `"fido2_user_intent_check":true`)
	assert.Contains(t, jsonStr, `"extension_enabled":true`)
	assert.Contains(t, jsonStr, `"extension_allowed_domains":["example.com","corp.internal"]`)
	assert.Contains(t, jsonStr, `"extension_blocked_domains":["evil.com"]`)
	assert.Contains(t, jsonStr, `"extension_max_fills_per_minute":30`)
	assert.Contains(t, jsonStr, `"user_can_configure_extension":false`)
}

func TestPolicySectionAPIExplorerFields(t *testing.T) {
	p := DefaultPolicy()
	require.NotNil(t, p)

	assert.True(t, p.APIExplorerEnabled,
		"DefaultPolicy must enable API explorer by default")
	assert.Equal(t, "", p.APIExplorerSandboxPolicy,
		"DefaultPolicy must leave APIExplorerSandboxPolicy empty so user preference applies")
}

func TestPolicyCanonicalJSON_APIExplorerFields(t *testing.T) {
	p := DefaultPolicy()

	data, err := PolicyCanonicalJSON(p)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// The JSON must contain the new fields with their default values.
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"api_explorer_enabled":true`,
		"canonical JSON must include api_explorer_enabled from default policy")
	assert.Contains(t, jsonStr, `"api_explorer_sandbox_policy":""`,
		"canonical JSON must include api_explorer_sandbox_policy as empty string")

	// Verify round-trip preserves the fields.
	var restored PolicySection
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.True(t, restored.APIExplorerEnabled)
	assert.Equal(t, "", restored.APIExplorerSandboxPolicy)
}

func TestPolicySection_APIExplorerDisabled(t *testing.T) {
	p := &PolicySection{
		APIExplorerEnabled:       false,
		APIExplorerSandboxPolicy: "read-only",
	}

	data, err := PolicyCanonicalJSON(p)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	assert.True(t, json.Valid(data))

	// Verify the raw JSON contains the expected values.
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"api_explorer_enabled":false`)
	assert.Contains(t, jsonStr, `"api_explorer_sandbox_policy":"read-only"`)

	// Round-trip must preserve both fields.
	var restored PolicySection
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.False(t, restored.APIExplorerEnabled,
		"disabled API explorer must survive JSON round-trip")
	assert.Equal(t, "read-only", restored.APIExplorerSandboxPolicy,
		"custom sandbox policy must survive JSON round-trip")
}

func TestPolicySectionExtensionFields(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		p := DefaultPolicy()
		require.NotNil(t, p)

		assert.True(t, p.ExtensionEnabled,
			"DefaultPolicy must enable browser extension by default")
		assert.True(t, p.ExtensionRequireAuthentication,
			"DefaultPolicy must require authentication for extension by default")
		assert.True(t, p.ExtensionRequirePairing,
			"DefaultPolicy must require pairing for extension by default")
		assert.True(t, p.ExtensionForceAudit,
			"DefaultPolicy must force audit for extension by default")
		assert.True(t, p.UserCanConfigureExtension,
			"DefaultPolicy must allow user to configure extension by default")

		// Zero-value fields.
		assert.Nil(t, p.ExtensionAllowedDomains,
			"DefaultPolicy must not set allowed domains")
		assert.Nil(t, p.ExtensionBlockedDomains,
			"DefaultPolicy must not set blocked domains")
		assert.Equal(t, 0, p.ExtensionMaxFillsPerMinute,
			"DefaultPolicy must not set max fills per minute (zero means unlimited)")
	})

	t.Run("disabled extension serializes correctly", func(t *testing.T) {
		p := &PolicySection{
			ExtensionEnabled:               false,
			ExtensionRequireAuthentication: false,
			ExtensionRequirePairing:        false,
			ExtensionForceAudit:            false,
			UserCanConfigureExtension:      false,
		}

		data, err := PolicyCanonicalJSON(p)
		require.NoError(t, err)
		require.NotEmpty(t, data)
		assert.True(t, json.Valid(data))

		jsonStr := string(data)
		assert.Contains(t, jsonStr, `"extension_enabled":false`)
		assert.Contains(t, jsonStr, `"extension_require_authentication":false`)
		assert.Contains(t, jsonStr, `"extension_require_pairing":false`)
		assert.Contains(t, jsonStr, `"extension_force_audit":false`)
		assert.Contains(t, jsonStr, `"user_can_configure_extension":false`)

		var restored PolicySection
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.False(t, restored.ExtensionEnabled)
		assert.False(t, restored.ExtensionRequireAuthentication)
		assert.False(t, restored.ExtensionRequirePairing)
		assert.False(t, restored.ExtensionForceAudit)
		assert.False(t, restored.UserCanConfigureExtension)
	})

	t.Run("domain lists and rate limit", func(t *testing.T) {
		p := &PolicySection{
			ExtensionEnabled:           true,
			ExtensionAllowedDomains:    []string{"example.com", "corp.internal", "*.trusted.org"},
			ExtensionBlockedDomains:    []string{"evil.com", "phishing.net"},
			ExtensionMaxFillsPerMinute: 15,
		}

		data, err := PolicyCanonicalJSON(p)
		require.NoError(t, err)
		require.NotEmpty(t, data)
		assert.True(t, json.Valid(data))

		jsonStr := string(data)
		assert.Contains(t, jsonStr, `"extension_allowed_domains":["example.com","corp.internal","*.trusted.org"]`)
		assert.Contains(t, jsonStr, `"extension_blocked_domains":["evil.com","phishing.net"]`)
		assert.Contains(t, jsonStr, `"extension_max_fills_per_minute":15`)

		var restored PolicySection
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.Equal(t, []string{"example.com", "corp.internal", "*.trusted.org"}, restored.ExtensionAllowedDomains)
		assert.Equal(t, []string{"evil.com", "phishing.net"}, restored.ExtensionBlockedDomains)
		assert.Equal(t, 15, restored.ExtensionMaxFillsPerMinute)
	})
}

func TestPolicyCanonicalJSON_ExtensionFields(t *testing.T) {
	t.Run("default policy round-trip", func(t *testing.T) {
		p := DefaultPolicy()

		data, err := PolicyCanonicalJSON(p)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		jsonStr := string(data)
		assert.Contains(t, jsonStr, `"extension_enabled":true`,
			"canonical JSON must include extension_enabled from default policy")
		assert.Contains(t, jsonStr, `"extension_require_authentication":true`,
			"canonical JSON must include extension_require_authentication from default policy")
		assert.Contains(t, jsonStr, `"extension_require_pairing":true`,
			"canonical JSON must include extension_require_pairing from default policy")
		assert.Contains(t, jsonStr, `"extension_force_audit":true`,
			"canonical JSON must include extension_force_audit from default policy")
		assert.Contains(t, jsonStr, `"user_can_configure_extension":true`,
			"canonical JSON must include user_can_configure_extension from default policy")
		// Nil slices marshal as null in JSON.
		assert.Contains(t, jsonStr, `"extension_allowed_domains":null`,
			"canonical JSON must include extension_allowed_domains as null for default policy")
		assert.Contains(t, jsonStr, `"extension_blocked_domains":null`,
			"canonical JSON must include extension_blocked_domains as null for default policy")
		assert.Contains(t, jsonStr, `"extension_max_fills_per_minute":0`,
			"canonical JSON must include extension_max_fills_per_minute as 0 for default policy")

		var restored PolicySection
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.True(t, restored.ExtensionEnabled)
		assert.True(t, restored.ExtensionRequireAuthentication)
		assert.True(t, restored.ExtensionRequirePairing)
		assert.True(t, restored.ExtensionForceAudit)
		assert.True(t, restored.UserCanConfigureExtension)
		assert.Nil(t, restored.ExtensionAllowedDomains)
		assert.Nil(t, restored.ExtensionBlockedDomains)
		assert.Equal(t, 0, restored.ExtensionMaxFillsPerMinute)
	})

	t.Run("custom extension policy round-trip", func(t *testing.T) {
		p := DefaultPolicy()
		p.ExtensionEnabled = true
		p.ExtensionRequireAuthentication = true
		p.ExtensionRequirePairing = false
		p.ExtensionForceAudit = true
		p.ExtensionAllowedDomains = []string{"bank.example.com", "internal.corp"}
		p.ExtensionBlockedDomains = []string{"malware.example.com"}
		p.ExtensionMaxFillsPerMinute = 60
		p.UserCanConfigureExtension = false

		data, err := PolicyCanonicalJSON(p)
		require.NoError(t, err)
		require.NotEmpty(t, data)
		assert.True(t, json.Valid(data))

		var restored PolicySection
		err = json.Unmarshal(data, &restored)
		require.NoError(t, err)

		assert.True(t, restored.ExtensionEnabled)
		assert.True(t, restored.ExtensionRequireAuthentication)
		assert.False(t, restored.ExtensionRequirePairing,
			"disabled pairing must survive JSON round-trip")
		assert.True(t, restored.ExtensionForceAudit)
		assert.Equal(t, []string{"bank.example.com", "internal.corp"}, restored.ExtensionAllowedDomains,
			"allowed domains must survive JSON round-trip")
		assert.Equal(t, []string{"malware.example.com"}, restored.ExtensionBlockedDomains,
			"blocked domains must survive JSON round-trip")
		assert.Equal(t, 60, restored.ExtensionMaxFillsPerMinute,
			"max fills per minute must survive JSON round-trip")
		assert.False(t, restored.UserCanConfigureExtension,
			"locked extension config must survive JSON round-trip")
	})
}

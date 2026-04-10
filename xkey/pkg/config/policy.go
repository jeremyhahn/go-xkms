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

import "encoding/json"

// PolicySection holds organization-level security policy that governs
// backend selection, PIN requirements, platform binding, and user
// permissions. Fields are exported with deterministic JSON struct tags
// so that json.Marshal produces a canonical byte representation suitable
// for HMAC integrity verification.
type PolicySection struct {
	MinPINLength               int      `yaml:"min_pin_length" json:"min_pin_length" mapstructure:"min_pin_length"`
	PINMaxAttempts             int      `yaml:"pin_max_attempts" json:"pin_max_attempts" mapstructure:"pin_max_attempts"`
	RequireSOPIN               bool     `yaml:"require_so_pin" json:"require_so_pin" mapstructure:"require_so_pin"`
	RequireUserPIN             bool     `yaml:"require_user_pin" json:"require_user_pin" mapstructure:"require_user_pin"`
	RequireEncryptedStorage    bool     `yaml:"require_encrypted_storage" json:"require_encrypted_storage" mapstructure:"require_encrypted_storage"`
	StorageType                string   `yaml:"storage_type" json:"storage_type" mapstructure:"storage_type"`
	RequireTPM                 bool     `yaml:"require_tpm" json:"require_tpm" mapstructure:"require_tpm"`
	RequirePlatformPolicy      bool     `yaml:"require_platform_policy" json:"require_platform_policy" mapstructure:"require_platform_policy"`
	PlatformPCRs               []int    `yaml:"platform_pcrs" json:"platform_pcrs" mapstructure:"platform_pcrs"`
	PlatformPCRBank            string   `yaml:"platform_pcr_bank" json:"platform_pcr_bank" mapstructure:"platform_pcr_bank"`
	RequirePasswordProtection  bool     `yaml:"require_password_protection" json:"require_password_protection" mapstructure:"require_password_protection"`
	PasswordProtectionMode     string   `yaml:"password_protection_mode" json:"password_protection_mode" mapstructure:"password_protection_mode"`
	AllowedBackends            []string `yaml:"allowed_backends" json:"allowed_backends" mapstructure:"allowed_backends"`
	DefaultBackend             string   `yaml:"default_backend" json:"default_backend" mapstructure:"default_backend"`
	FIDO2AlwaysUV              bool     `yaml:"fido2_always_uv" json:"fido2_always_uv" mapstructure:"fido2_always_uv"`
	FIDO2RequireResidentKey    bool     `yaml:"fido2_require_resident_key" json:"fido2_require_resident_key" mapstructure:"fido2_require_resident_key"`
	FIDO2RequireUserPresence   bool     `yaml:"fido2_require_user_presence" json:"fido2_require_user_presence" mapstructure:"fido2_require_user_presence"`
	FIDO2UserIntentCheck       bool     `yaml:"fido2_user_intent_check" json:"fido2_user_intent_check" mapstructure:"fido2_user_intent_check"`
	AttestationMode            string   `yaml:"attestation_mode" json:"attestation_mode" mapstructure:"attestation_mode"`
	AllowAutoUnseal            bool     `yaml:"allow_auto_unseal" json:"allow_auto_unseal" mapstructure:"allow_auto_unseal"`
	UserCanConfigureAutoUnseal bool     `yaml:"user_can_configure_auto_unseal" json:"user_can_configure_auto_unseal" mapstructure:"user_can_configure_auto_unseal"`
	UserCanConfigureTheme      bool     `yaml:"user_can_configure_theme" json:"user_can_configure_theme" mapstructure:"user_can_configure_theme"`
	UserCanManageTrustStore    bool     `yaml:"user_can_manage_trust_store" json:"user_can_manage_trust_store" mapstructure:"user_can_manage_trust_store"`
	UserCanViewAuditLog        bool     `yaml:"user_can_view_audit_log" json:"user_can_view_audit_log" mapstructure:"user_can_view_audit_log"`
	UserCanManageSealedData    bool     `yaml:"user_can_manage_sealed_data" json:"user_can_manage_sealed_data" mapstructure:"user_can_manage_sealed_data"`
	UserCanChangeOwnPIN        bool     `yaml:"user_can_change_own_pin" json:"user_can_change_own_pin" mapstructure:"user_can_change_own_pin"`
	APIExplorerEnabled         bool     `yaml:"api_explorer_enabled" json:"api_explorer_enabled" mapstructure:"api_explorer_enabled"`
	APIExplorerSandboxPolicy   string   `yaml:"api_explorer_sandbox_policy" json:"api_explorer_sandbox_policy" mapstructure:"api_explorer_sandbox_policy"`
	DeveloperToolsEnabled      bool     `yaml:"developer_tools_enabled" json:"developer_tools_enabled" mapstructure:"developer_tools_enabled"`
	UserCanToggleDevTools      bool     `yaml:"user_can_toggle_dev_tools" json:"user_can_toggle_dev_tools" mapstructure:"user_can_toggle_dev_tools"`

	// Browser extension enterprise policy.
	ExtensionEnabled               bool     `yaml:"extension_enabled" json:"extension_enabled" mapstructure:"extension_enabled"`
	ExtensionRequireAuthentication bool     `yaml:"extension_require_authentication" json:"extension_require_authentication" mapstructure:"extension_require_authentication"`
	ExtensionRequirePairing        bool     `yaml:"extension_require_pairing" json:"extension_require_pairing" mapstructure:"extension_require_pairing"`
	ExtensionForceAudit            bool     `yaml:"extension_force_audit" json:"extension_force_audit" mapstructure:"extension_force_audit"`
	ExtensionAllowedDomains        []string `yaml:"extension_allowed_domains" json:"extension_allowed_domains" mapstructure:"extension_allowed_domains"`
	ExtensionBlockedDomains        []string `yaml:"extension_blocked_domains" json:"extension_blocked_domains" mapstructure:"extension_blocked_domains"`
	ExtensionMaxFillsPerMinute     int      `yaml:"extension_max_fills_per_minute" json:"extension_max_fills_per_minute" mapstructure:"extension_max_fills_per_minute"`
	UserCanConfigureExtension      bool     `yaml:"user_can_configure_extension" json:"user_can_configure_extension" mapstructure:"user_can_configure_extension"`

	OrganizationName string `yaml:"organization_name" json:"organization_name" mapstructure:"organization_name"`
	PolicyVersion    int    `yaml:"policy_version" json:"policy_version" mapstructure:"policy_version"`
}

// DefaultPolicy returns a PolicySection populated with secure defaults
// suitable for standalone desktop use.
func DefaultPolicy() *PolicySection {
	return &PolicySection{
		MinPINLength:                   6,
		PINMaxAttempts:                 5,
		RequireSOPIN:                   true,
		RequireUserPIN:                 true,
		RequireEncryptedStorage:        true,
		StorageType:                    "barrier",
		UserCanConfigureAutoUnseal:     true,
		UserCanConfigureTheme:          true,
		UserCanManageTrustStore:        true,
		UserCanViewAuditLog:            true,
		UserCanManageSealedData:        true,
		UserCanChangeOwnPIN:            true,
		APIExplorerEnabled:             true,
		DeveloperToolsEnabled:          true,
		UserCanToggleDevTools:          true,
		FIDO2RequireUserPresence:       true,
		FIDO2UserIntentCheck:           true,
		ExtensionEnabled:               true,
		ExtensionRequireAuthentication: true,
		ExtensionRequirePairing:        true,
		ExtensionForceAudit:            true,
		UserCanConfigureExtension:      true,
		PolicyVersion:                  1,
	}
}

// PolicyCanonicalJSON returns the deterministic JSON encoding of the
// PolicySection. Because encoding/json marshals struct fields in the
// order they are declared, the output is stable and suitable for HMAC
// computation without requiring sorted-key canonicalization.
func PolicyCanonicalJSON(p *PolicySection) ([]byte, error) {
	return json.Marshal(p)
}

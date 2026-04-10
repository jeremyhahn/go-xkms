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

package ipc

import "fmt"

// Autofill action constants identify the specific operation within an autofill
// IPC message. Used for map-based O(1) dispatch.
const (
	ActionAutofillSearch       = "search"        // Search credentials by domain
	ActionAutofillGet          = "get"            // Get credential + password for fill
	ActionAutofillTOTP         = "totp"           // Get TOTP code for domain
	ActionAutofillTOTPByID     = "totp_by_id"     // Get TOTP by account ID
	ActionAutofillStatus       = "status"         // Check app lock state + policy
	ActionAutofillPolicy       = "policy"         // Get current policy
	ActionAutofillSave         = "save"           // Save new credential from form submission
	ActionAutofillIgnoreDomain = "ignore_domain"  // Ignore domain (never prompt to save)
	ActionAutofillFocus        = "focus"          // Bring the GUI window to the foreground
)

// validAutofillActions is the set of recognized autofill actions for O(1) lookup.
var validAutofillActions = map[string]bool{
	ActionAutofillSearch:       true,
	ActionAutofillGet:          true,
	ActionAutofillTOTP:         true,
	ActionAutofillTOTPByID:     true,
	ActionAutofillStatus:       true,
	ActionAutofillPolicy:       true,
	ActionAutofillSave:         true,
	ActionAutofillIgnoreDomain: true,
	ActionAutofillFocus:        true,
}

// AutofillPayload carries autofill-specific request data in an IPC Message.
type AutofillPayload struct {
	Action    string `json:"action"`              // "search", "get", "totp", "totp_by_id", "status", "policy", "save", "ignore_domain", "focus"
	Domain    string `json:"domain,omitempty"`    // domain for search/totp/save/ignore_domain actions
	ID        string `json:"id,omitempty"`        // credential or OATH account ID for get/totp_by_id
	Challenge string `json:"challenge,omitempty"` // base64-encoded 32-byte random challenge for CTAP2 auth
	Username  string `json:"username,omitempty"`  // username for save action
	Password  string `json:"password,omitempty"`  // password for save action
	Title     string `json:"title,omitempty"`     // title for save action
}

// AutofillCredential represents a credential returned from a search.
type AutofillCredential struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Username string `json:"username"`
	URL      string `json:"url"`
	HasTOTP  bool   `json:"has_totp"`
	TOTPID   string `json:"totp_id,omitempty"`
}

// AutofillAssertion carries the CTAP2 assertion proof that authentication
// was performed (PIN + touch). The extension can verify this independently
// or simply trust the native host (since the host already verified it).
type AutofillAssertion struct {
	AuthData     string `json:"auth_data"`            // base64 authenticator data
	Signature    string `json:"signature"`            // base64 ECDSA signature
	CredentialID string `json:"credential_id"`        // base64 credential ID
	PublicKey    string `json:"public_key,omitempty"` // base64 COSE public key (first fill only)
}

// AutofillFillResult contains the actual credential data for form filling.
// The password is only sent at fill-time, never cached by the extension.
// When CTAP2 authentication is enabled, the Assertion field carries the
// cryptographic proof that the user authorized the fill.
type AutofillFillResult struct {
	Username  string             `json:"username"`
	Password  string             `json:"password"`
	Assertion *AutofillAssertion `json:"assertion,omitempty"`
}

// AutofillTOTP contains a generated TOTP code and its validity.
type AutofillTOTP struct {
	Code      string `json:"code"`
	TimeLeft  int    `json:"time_left"`
	Period    int    `json:"period"`
	AccountID string `json:"account_id"`
	Issuer    string `json:"issuer"`
}

// AutofillStatus represents the current autofill system state.
type AutofillStatus struct {
	Available        bool   `json:"available"`         // autofill system is ready
	AppLocked        bool   `json:"app_locked"`        // app is locked
	FillMode         string `json:"fill_mode"`         // current fill mode
	ExtensionEnabled bool   `json:"extension_enabled"` // master toggle
}

// AutofillResult carries autofill-specific response data.
type AutofillResult struct {
	Credentials []AutofillCredential  `json:"credentials,omitempty"`
	Fill        *AutofillFillResult   `json:"fill,omitempty"`
	TOTP        *AutofillTOTP         `json:"totp,omitempty"`
	Status      *AutofillStatus       `json:"status,omitempty"`
	Policy      *AutofillPolicyResult `json:"policy,omitempty"`
	Saved       bool                  `json:"saved,omitempty"`  // true when credential was saved
	Exists      bool                  `json:"exists,omitempty"` // true when credential already exists
}

// AutofillPolicyResult wraps the policy for IPC responses.
type AutofillPolicyResult struct {
	FillMode              string   `json:"fill_mode"`
	TOTPPolicy            string   `json:"totp_policy"`
	SessionTimeoutSec     int      `json:"session_timeout_sec"`
	RequireAuthentication bool     `json:"require_authentication"`
	AllowedDomains        []string `json:"allowed_domains"`
	BlockedDomains        []string `json:"blocked_domains"`
	MaxFillsPerMinute     int      `json:"max_fills_per_minute"`
	AuditEnabled          bool     `json:"audit_enabled"`
}

// Validate checks the AutofillPayload for correctness. It returns
// ErrInvalidMessage if the action is empty, unrecognized, or if
// required fields for the action are missing.
func (p *AutofillPayload) Validate() error {
	if p.Action == "" {
		return fmt.Errorf("%w: autofill action is required", ErrInvalidMessage)
	}
	if !validAutofillActions[p.Action] {
		return fmt.Errorf("%w: unknown autofill action %q", ErrInvalidMessage, p.Action)
	}
	switch p.Action {
	case ActionAutofillSearch, ActionAutofillTOTP:
		if p.Domain == "" {
			return fmt.Errorf("%w: domain is required for %s action", ErrInvalidMessage, p.Action)
		}
	case ActionAutofillGet, ActionAutofillTOTPByID:
		if p.ID == "" {
			return fmt.Errorf("%w: id is required for %s action", ErrInvalidMessage, p.Action)
		}
	case ActionAutofillSave:
		if p.Domain == "" {
			return fmt.Errorf("%w: domain is required for %s action", ErrInvalidMessage, p.Action)
		}
		if p.Username == "" {
			return fmt.Errorf("%w: username is required for %s action", ErrInvalidMessage, p.Action)
		}
		if p.Password == "" {
			return fmt.Errorf("%w: password is required for %s action", ErrInvalidMessage, p.Action)
		}
	case ActionAutofillIgnoreDomain:
		if p.Domain == "" {
			return fmt.Errorf("%w: domain is required for %s action", ErrInvalidMessage, p.Action)
		}
	case ActionAutofillStatus, ActionAutofillPolicy, ActionAutofillFocus:
		// No additional fields required
	}
	return nil
}

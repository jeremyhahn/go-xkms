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

package policy

// MFALevel represents the strength of multi-factor authentication required.
type MFALevel int

const (
	// MFANone requires no MFA (internal/system operations only).
	MFANone MFALevel = iota

	// MFAFIDO2 requires FIDO2 authentication with user verification.
	// This is 2FA: possession (authenticator) + UV (PIN/biometric).
	// Compliant with NIST SP 800-63B AAL2.
	MFAFIDO2

	// MFAFIDO2OATH requires FIDO2 + OATH TOTP/HOTP.
	// This is 3FA for sensitive operations.
	// Compliant with NIST SP 800-63B AAL3.
	MFAFIDO2OATH
)

// mfaLevelNames provides O(1) lookup for MFA level string representation.
var mfaLevelNames = map[MFALevel]string{
	MFANone:      "none",
	MFAFIDO2:     "fido2",
	MFAFIDO2OATH: "fido2+oath",
}

// mfaLevelMap provides O(1) lookup for MFA level parsing.
var mfaLevelMap = map[string]MFALevel{
	"none":       MFANone,
	"fido2":      MFAFIDO2,
	"fido2+oath": MFAFIDO2OATH,
}

// String returns the human-readable name of the MFA level.
func (l MFALevel) String() string {
	if name, ok := mfaLevelNames[l]; ok {
		return name
	}
	return "unknown"
}

// ParseMFALevel parses an MFA level from a string.
func ParseMFALevel(s string) (MFALevel, error) {
	level, ok := mfaLevelMap[s]
	if !ok {
		return MFANone, ErrInvalidMFALevel
	}
	return level, nil
}

// SatisfiedBy reports whether the provided level meets or exceeds this level.
func (l MFALevel) SatisfiedBy(provided MFALevel) bool {
	return provided >= l
}

// Well-known operation constants for policy evaluation.
const (
	OpBarrierUnseal   = "barrier_unseal"
	OpBarrierSeal     = "barrier_seal"
	OpKeyExport       = "key_export"
	OpKeyImport       = "key_import"
	OpKeyGenerate     = "key_generate"
	OpKeyDelete       = "key_delete"
	OpTenantCreate    = "tenant_create"
	OpTenantDelete    = "tenant_delete"
	OpUserCreate      = "user_create"
	OpUserDelete      = "user_delete"
	OpCustodianInvite = "custodian_invite"
	OpShareProvide    = "share_provide"
	OpShareReceive    = "share_receive"
	OpEscrowKey       = "escrow_key"
	OpRecoverKey      = "recover_key"
	OpCertRequest     = "cert_request"
	OpLogin           = "login"
)

// OperationPolicy defines the MFA requirement for a specific operation.
type OperationPolicy struct {
	// Operation is the name of the operation this policy applies to.
	Operation string `json:"operation"`

	// RequiredLevel is the minimum MFA level required.
	RequiredLevel MFALevel `json:"required_level"`

	// Description explains why this level is required.
	Description string `json:"description,omitempty"`

	// Enforced indicates whether this policy is active. When false,
	// the policy is advisory only and does not block operations.
	Enforced bool `json:"enforced"`
}

// MFAPolicy holds the complete MFA policy configuration.
type MFAPolicy struct {
	// DefaultLevel is the MFA level required for operations without
	// an explicit policy. Defaults to MFAFIDO2.
	DefaultLevel MFALevel `json:"default_level"`

	// Operations maps operation names to their specific policies.
	Operations map[string]*OperationPolicy `json:"operations"`
}

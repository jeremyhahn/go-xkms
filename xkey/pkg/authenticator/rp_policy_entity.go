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

import "time"

// RPPolicyEntity is the DAO entity representation of a per-RP authentication
// policy. It mirrors RPPolicy with DAO-compatible field tags for indexed
// persistence via go-qrdb, and adds governance fields for algorithm
// restrictions and resident key requirements.
type RPPolicyEntity struct {
	// ID is the auto-assigned DAO entity identifier.
	ID uint64 `json:"id"`

	// RPID is the relying party identifier this policy applies to.
	RPID string `json:"rp_id" index:"unique"`

	// PolicyName is an optional human-readable name for this policy.
	PolicyName string `json:"policy_name"`

	// AllowedAlgorithms is a comma-separated list of allowed COSE algorithm
	// identifiers (e.g., "-7,-257"). Empty means all algorithms are allowed.
	AllowedAlgorithms string `json:"allowed_algorithms"`

	// RequireResidentKey forces discoverable credential creation for this RP.
	RequireResidentKey bool `json:"require_resident_key"`

	// RequireUserVerification forces user verification for this RP.
	RequireUserVerification bool `json:"require_user_verification"`

	// UVOverride overrides the RP's userVerification request.
	// Valid values: "", "required", "preferred", "discouraged".
	UVOverride string `json:"uv_override"`

	// UPOverride overrides user presence. Nil pointer means no override.
	// Stored as nullable boolean.
	UPOverride *bool `json:"up_override"`

	// AttestationOverride overrides the attestation mode for this RP.
	// Valid values: "", "none", "indirect", "direct", "enterprise".
	AttestationOverride string `json:"attestation_override"`

	// Enterprise marks this RP as trusted for enterprise attestation.
	Enterprise bool `json:"enterprise"`

	// Blocked prevents all operations for this RPID.
	Blocked bool `json:"blocked"`

	// CreatedAt is when the policy was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the policy was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// EntityID returns the DAO entity identifier.
func (e *RPPolicyEntity) EntityID() uint64 { return e.ID }

// SetEntityID sets the DAO entity identifier.
func (e *RPPolicyEntity) SetEntityID(id uint64) { e.ID = id }

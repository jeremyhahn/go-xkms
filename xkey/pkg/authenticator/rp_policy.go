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

import "errors"

// RPPolicy defines SO-configurable per-RP authentication policies.
// These policies allow the Security Officer to override RP requests
// for specific relying parties, enabling enterprise governance over
// authenticator behavior.
type RPPolicy struct {
	// RPID is the relying party identifier this policy applies to.
	RPID string `json:"rpId"`

	// UVOverride overrides the RP's userVerification request.
	// "": use RP's request (no override)
	// "required": force UV even if RP didn't request it
	// "discouraged": skip UV even if RP/credential requires it
	UVOverride string `json:"uvOverride,omitempty"`

	// UPOverride overrides the RP's user presence request.
	// nil: use RP request/default
	// false: silent auth (no user interaction)
	// true: always require user presence
	UPOverride *bool `json:"upOverride,omitempty"`

	// AttestationOverride overrides the attestation mode for this RP.
	// "": use RP request (no override)
	// "none", "direct", "enterprise": force specific attestation
	AttestationOverride string `json:"attestationOverride,omitempty"`

	// Enterprise marks this RP as trusted for enterprise attestation.
	// When true, enterprise attestation requests from this RP are honored.
	Enterprise bool `json:"enterprise,omitempty"`

	// Blocked prevents credential creation and assertion for this RP.
	// When true, all operations for this RPID are denied.
	Blocked bool `json:"blocked,omitempty"`
}

// RPPolicyStore persists per-RP policies.
// Implementations must be safe for concurrent use.
type RPPolicyStore interface {
	// SetPolicy creates or updates a per-RP policy.
	SetPolicy(policy *RPPolicy) error

	// GetPolicy retrieves the policy for a specific RPID.
	// Returns ErrRPPolicyNotFound if no policy exists for the RPID.
	GetPolicy(rpID string) (*RPPolicy, error)

	// DeletePolicy removes the policy for a specific RPID.
	// Returns ErrRPPolicyNotFound if no policy exists for the RPID.
	DeletePolicy(rpID string) error

	// ListPolicies returns all stored RP policies.
	ListPolicies() ([]*RPPolicy, error)
}

// RP policy errors.
var (
	// ErrRPPolicyNotFound indicates no policy exists for the given RPID.
	ErrRPPolicyNotFound = errors.New("authenticator: RP policy not found")

	// ErrRPPolicyInvalidRPID indicates the RPID in the policy is empty.
	ErrRPPolicyInvalidRPID = errors.New("authenticator: RP policy RPID is empty")

	// ErrRPPolicyNil indicates a nil policy was provided.
	ErrRPPolicyNil = errors.New("authenticator: RP policy is nil")

	// ErrRPPolicyStoreClosed indicates the RP policy store has been closed.
	ErrRPPolicyStoreClosed = errors.New("authenticator: RP policy store closed")

	// ErrRPBlocked indicates the RP is blocked by SO policy.
	ErrRPBlocked = errors.New("authenticator: RP blocked by policy")
)

// ValidUVOverrides are the valid values for RPPolicy.UVOverride.
var ValidUVOverrides = map[string]bool{
	"":            true,
	"required":    true,
	"preferred":   true,
	"discouraged": true,
}

// ValidAttestationOverrides are the valid values for RPPolicy.AttestationOverride.
var ValidAttestationOverrides = map[string]bool{
	"":           true,
	"none":       true,
	"indirect":   true,
	"direct":     true,
	"enterprise": true,
}

// Validate checks if the RPPolicy has valid values.
func (p *RPPolicy) Validate() error {
	if p == nil {
		return ErrRPPolicyNil
	}
	if p.RPID == "" {
		return ErrRPPolicyInvalidRPID
	}
	if !ValidUVOverrides[p.UVOverride] {
		return ErrInvalidParameter
	}
	if !ValidAttestationOverrides[p.AttestationOverride] {
		return ErrInvalidParameter
	}
	return nil
}

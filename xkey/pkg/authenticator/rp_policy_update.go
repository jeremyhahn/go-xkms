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

// RPPolicyUpdate describes a partial change to a stored RPPolicy. It is the
// presence-carrying update representation: a nil field means "leave the
// stored value unchanged", while a non-nil field replaces it — including
// replacement with the field's zero value, which callers express by pointing
// at an explicit zero (for example an explicit false to unblock an RP).
//
// Presence lives here, in the update type, and only here. The stored RPPolicy
// and every read path keep plain, non-pointer values so the enforcement sites
// that read Blocked, Enterprise and the overrides never grow nil checks.
//
// UPOverride cannot be reset to "no override" (nil) through an update; no
// caller surface can express that today. Clearing it requires a full
// SetPolicy or DeletePolicy.
type RPPolicyUpdate struct {
	// RPID is the relying party identifier whose policy is updated.
	RPID string

	// UVOverride, when non-nil, replaces RPPolicy.UVOverride. An explicit
	// empty string clears the override ("use the RP's request").
	UVOverride *string

	// UPOverride, when non-nil, replaces RPPolicy.UPOverride with its value.
	UPOverride *bool

	// AttestationOverride, when non-nil, replaces
	// RPPolicy.AttestationOverride. An explicit empty string clears the
	// override.
	AttestationOverride *string

	// Enterprise, when non-nil, replaces RPPolicy.Enterprise.
	Enterprise *bool

	// Blocked, when non-nil, replaces RPPolicy.Blocked. Only an explicit
	// false lifts an RP block; an update that omits Blocked leaves an
	// existing block in place.
	Blocked *bool
}

// RP policy update errors.
var (
	// ErrRPPolicyUpdateNil indicates a nil update was provided.
	ErrRPPolicyUpdateNil = errors.New("authenticator: RP policy update is nil")

	// ErrRPPolicyConflict indicates a policy write lost its optimistic
	// concurrency check to a concurrent writer on every bounded retry.
	// The store's record was NOT changed by this call.
	ErrRPPolicyConflict = errors.New("authenticator: RP policy modified concurrently, update not applied")
)

// Validate checks that the update targets an RP and carries only valid
// override values. Returns ErrRPPolicyUpdateNil for a nil update,
// ErrRPPolicyInvalidRPID for an empty RPID, and ErrInvalidParameter for an
// invalid UV or attestation override value.
func (u *RPPolicyUpdate) Validate() error {
	if u == nil {
		return ErrRPPolicyUpdateNil
	}
	if u.RPID == "" {
		return ErrRPPolicyInvalidRPID
	}
	if u.UVOverride != nil && !ValidUVOverrides[*u.UVOverride] {
		return ErrInvalidParameter
	}
	if u.AttestationOverride != nil && !ValidAttestationOverrides[*u.AttestationOverride] {
		return ErrInvalidParameter
	}
	return nil
}

// applyRPPolicyUpdate overlays an update onto the currently stored policy and
// returns the policy to store. A nil existing policy means no policy is
// stored for the RPID yet; the update is then applied onto a zero policy
// (upsert). The existing policy is never mutated.
func applyRPPolicyUpdate(existing *RPPolicy, update *RPPolicyUpdate) *RPPolicy {
	merged := &RPPolicy{RPID: update.RPID}
	if existing != nil {
		merged = copyRPPolicy(existing)
		merged.RPID = update.RPID
	}

	if update.UVOverride != nil {
		merged.UVOverride = *update.UVOverride
	}
	if update.UPOverride != nil {
		v := *update.UPOverride
		merged.UPOverride = &v
	}
	if update.AttestationOverride != nil {
		merged.AttestationOverride = *update.AttestationOverride
	}
	if update.Enterprise != nil {
		merged.Enterprise = *update.Enterprise
	}
	if update.Blocked != nil {
		merged.Blocked = *update.Blocked
	}

	return merged
}

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package policy manages named, TPM-authorized policies that many TPM keys
// and sealed objects share, the registry of which object uses which policy,
// and each tenant's TPM scope (tpm.mode none, shared or vtpm).
//
// A named policy is an OR of branches, each an AND of conditions: pcr (a PCR
// selection whose values are captured live), auth_value (the object's
// password) and locality (the TPM localities a command may come from). An
// object bound to a named policy carries PolicyAuthorizeNV(the policy's NV
// index) as its authPolicy -- OR PolicyAuthValue when the object has a
// password and the policy has no auth_value condition. The index holds
// PolicyAuthorize(the scope's authority, policyRef), and the authority signs
// one approval per branch: the branch's assertions plus PolicyNV(the scope's
// counter == epoch). Updating a policy re-captures its PCRs and re-signs
// every branch; revoking bumps the counter; rotating the authority rewrites
// the indices. None of these re-keys an object. See
// docs/tpm-policies/architecture.md.
package policy

import (
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// PlatformPolicy is the built-in policy every scope has (PCR 16 OR the
// object's auth value). It cannot be created, updated or deleted.
const PlatformPolicy = types.TPMPolicyPlatform

// VTPMStatePolicy is the system-scope policy a vTPM's state key is sealed
// under, so a firmware change is handled by updating it.
const VTPMStatePolicy = "vtpm-state"

// Mode is a tenant's TPM mode.
type Mode string

const (
	// ModeNone gives the tenant no TPM objects.
	ModeNone Mode = "none"

	// ModeShared keeps the tenant's objects on the physical TPM under a
	// per-tenant storage key beneath the Platform SRK.
	ModeShared Mode = "shared"

	// ModeVTPM keeps the tenant's objects in a per-tenant virtual TPM.
	ModeVTPM Mode = "vtpm"

	// DefaultMode is a tenant's mode until the system administrator sets
	// another.
	DefaultMode = ModeShared
)

// modes is the set of valid Mode values.
var modes = map[Mode]struct{}{ModeNone: {}, ModeShared: {}, ModeVTPM: {}}

// ParseMode returns the Mode named by s, or *InvalidModeError.
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	if _, ok := modes[m]; !ok {
		return "", &InvalidModeError{Mode: s}
	}
	return m, nil
}

// ObjectKind distinguishes the TPM objects a policy can be assigned to.
type ObjectKind string

const (
	// ObjectKey is an asymmetric or symmetric key.
	ObjectKey ObjectKind = "key"

	// ObjectSealed is a sealed data object.
	ObjectSealed ObjectKind = "sealed"
)

// Authority identifies a scope's policy-authority signing key.
type Authority struct {
	// CN is the key's name in the scope's key store.
	CN string `json:"cn"`

	// Name is the key's TPM Name, which approvals are verified against.
	Name []byte `json:"name"`

	// Public is the key's TPM public area (TPMT_PUBLIC), which a policy
	// session loads to verify an approval's signature.
	Public []byte `json:"public"`

	// Generation counts rotations: the first authority is generation 1.
	Generation uint64 `json:"generation"`
}

// Scope is a tenant's TPM scope: its mode, storage key, policy authority and
// revocation counter.
type Scope struct {
	Tenant string `json:"tenant"`
	Mode   Mode   `json:"mode"`

	// StorageKey is the CN of the tenant's storage key (shared mode); empty
	// for the system scope, whose parent is the Platform SRK.
	StorageKey string `json:"storage_key,omitempty"`

	// Authority is the current policy authority.
	Authority Authority `json:"authority"`

	// Rotating is the authority a rotation in progress is moving to; nil
	// when no rotation is in progress.
	Rotating *Authority `json:"rotating,omitempty"`

	// Counter is the scope's NV counter index and Epoch the value every
	// current approval was signed at.
	Counter uint32 `json:"counter"`
	Epoch   uint64 `json:"epoch"`

	// SealedSecrets is the scope's secrets (storage-key auth, authority
	// auth, NV write auth), sealed by the TPM under the platform policy.
	SealedSecrets []byte `json:"sealed_secrets"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Approval is the authority's signed approval of one policy branch, with
// the values it captured, at an epoch.
type Approval struct {
	Epoch               uint64    `json:"epoch"`
	AuthorityGeneration uint64    `json:"authority_generation"`
	Signature           []byte    `json:"signature"`
	ApprovedAt          time.Time `json:"approved_at"`
}

// ConditionType is the kind of a policy branch condition.
type ConditionType string

const (
	// ConditionPCR requires the selected PCRs to hold the values captured
	// when the policy was created or last updated.
	ConditionPCR ConditionType = "pcr"

	// ConditionAuthValue requires the object's password.
	ConditionAuthValue ConditionType = "auth_value"

	// ConditionLocality requires the command to come from one of the
	// allowed TPM localities.
	ConditionLocality ConditionType = "locality"
)

// Condition is one condition of a policy branch. Only the fields of its Type
// are set.
type Condition struct {
	Type ConditionType `json:"type"`

	// Bank is a pcr condition's PCR bank ("sha256", ...) and PCRs its
	// selected indices, ascending.
	Bank string `json:"bank,omitempty"`
	PCRs []uint `json:"pcrs,omitempty"`

	// PCRValues are a pcr condition's values, captured from the TPM when
	// the policy was created or last updated, and PCRDigest the PolicyPCR
	// digest over them. A caller never supplies them.
	PCRValues map[uint][]byte `json:"pcr_values,omitempty"`
	PCRDigest []byte          `json:"pcr_digest,omitempty"`

	// Localities are a locality condition's allowed localities, 0 through
	// 4, ascending.
	Localities []uint `json:"localities,omitempty"`
}

// Branch is one branch of a policy: the AND of its conditions. It has at most
// one condition of each type.
type Branch struct {
	Conditions []Condition `json:"conditions"`
}

// PCRBranch returns a branch holding one pcr condition over pcrs of bank:
// the whole of a policy that approves one PCR state.
func PCRBranch(bank string, pcrs ...uint) Branch {
	return Branch{Conditions: []Condition{{Type: ConditionPCR, Bank: bank, PCRs: pcrs}}}
}

// Policy is a named, reusable TPM policy: an OR of branches, bound to an NV
// index objects authorize through. Its structure never changes after
// creation; an update only re-captures the values of its pcr conditions.
type Policy struct {
	Name string `json:"name"`

	// Description is free text, settable at creation and at any time after.
	Description string `json:"description,omitempty"`

	// Branches are the policy's branches, tried in order when an object is
	// used.
	Branches []Branch `json:"branches"`

	// Index is the policy's NV index and IndexName its TPM Name, which
	// every object bound to the policy commits to.
	Index     uint32 `json:"index"`
	IndexName []byte `json:"index_name"`

	// PolicyRef binds approvals to this policy and no other.
	PolicyRef []byte `json:"policy_ref"`

	// Approvals are the current approvals, index-aligned with Branches. A
	// nil entry is a revoked branch; a revoke clears every entry until the
	// next update.
	Approvals []*Approval `json:"approvals,omitempty"`

	// AutoUnseal marks the policy barrier auto-unseal uses; at most one
	// policy per scope carries it.
	AutoUnseal bool `json:"auto_unseal,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// approved reports whether every branch holds an approval. Approvals are
// written and revoked for every branch at once, so a policy is either
// approved in full or revoked.
func (p *Policy) approved() bool {
	if len(p.Branches) == 0 || len(p.Approvals) != len(p.Branches) {
		return false
	}
	for _, a := range p.Approvals {
		if a == nil {
			return false
		}
	}
	return true
}

// revoke clears every branch's approval.
func (p *Policy) revoke() {
	p.Approvals = make([]*Approval, len(p.Branches))
}

// hasAuthValueCondition reports whether any branch requires the object's
// password.
func (p *Policy) hasAuthValueCondition() bool {
	for _, b := range p.Branches {
		for _, c := range b.Conditions {
			if c.Type == ConditionAuthValue {
				return true
			}
		}
	}
	return false
}

// Assignment records the policy an object was created under.
type Assignment struct {
	ObjectID string     `json:"object_id"`
	Kind     ObjectKind `json:"kind"`
	Policy   string     `json:"policy"`

	// AuthPolicy is the object's authPolicy digest at creation.
	AuthPolicy []byte `json:"auth_policy,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// CreatePolicyRequest describes a named policy to create. PCR values are
// never supplied by the caller: they are read from the scope's TPM.
type CreatePolicyRequest struct {
	// Name is the policy's name, unique within the scope.
	Name string

	// Description is free text.
	Description string

	// Branches are the policy's branches: at least one, each with at least
	// one condition and at most one of each type. A pcr condition names a
	// bank (sha1, sha256, sha384 or sha512) and PCRs 0 through 23 without
	// duplicates; a locality condition names localities 0 through 4 without
	// duplicates; an auth_value condition names nothing.
	Branches []Branch

	// AutoUnseal marks the policy barrier auto-unseal uses, clearing the
	// mark from any other policy of the scope.
	AutoUnseal bool

	// OwnerAuth authorizes defining the policy's NV index under the
	// physical TPM's owner hierarchy (and the scope's counter, when the
	// scope is created by this call). A vTPM's owner hierarchy has no auth.
	OwnerAuth []byte
}

// BranchVerification compares one branch's captured PCR values with the
// live ones.
type BranchVerification struct {
	// Match reports whether the branch's pcr condition, if it has one,
	// still holds its captured values, and Mismatched lists the PCRs that do
	// not, ascending.
	Match      bool
	Mismatched []uint

	// Approved reports whether the branch holds an approval at the scope
	// counter's current value, so it can be satisfied.
	Approved bool
}

// Verification compares a policy's captured PCR values with the live ones.
// It is an advisory, read-only check: the TPM itself enforces the policy
// when an object is used.
type Verification struct {
	// Policy is the verified policy's name.
	Policy string

	// Branches reports each branch, index-aligned with the policy's.
	Branches []BranchVerification

	// Match reports whether every branch matches.
	Match bool

	// Approved reports whether every branch holds an approval at the scope
	// counter's current value.
	Approved bool
}

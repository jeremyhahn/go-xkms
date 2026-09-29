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

// Package tpmpolicy manages named, TPM-authorized policies that many TPM keys
// and sealed objects share, the registry of which object uses which policy,
// and each tenant's TPM scope (tpm.mode none, shared or vtpm).
//
// An object bound to a named policy carries
// PolicyOR(PolicyAuthorizeNV(the policy's NV index), PolicyAuthValue) as its
// authPolicy. The index holds PolicyAuthorize(the scope's authority,
// policyRef), and the authority signs approvals of PolicyPCR(the policy's
// captured PCRs) plus PolicyNV(the scope's counter == epoch). Updating a
// policy re-captures its PCRs and re-signs it; revoking bumps the counter;
// rotating the authority rewrites the indices. None of these re-keys an
// object. See docs/tpm-policies/architecture.md.
package tpmpolicy

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

// indexMarker is the value of a by-policy index entry; only its key matters.
var indexMarker = []byte("1")

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

// Approval is the authority's signed approval of a policy's PCR state at an
// epoch.
type Approval struct {
	Epoch               uint64    `json:"epoch"`
	AuthorityGeneration uint64    `json:"authority_generation"`
	Signature           []byte    `json:"signature"`
	ApprovedAt          time.Time `json:"approved_at"`
}

// Policy is a named, reusable TPM policy: a PCR selection and the values
// captured from the TPM, bound to an NV index objects authorize through.
type Policy struct {
	Name string `json:"name"`

	// Bank is the PCR bank ("sha256", ...) and PCRs the selected indices.
	Bank string `json:"bank"`
	PCRs []uint `json:"pcrs"`

	// PCRValues are the values captured when the policy was created or last
	// updated, and PCRDigest the PolicyPCR digest over them.
	PCRValues map[uint][]byte `json:"pcr_values"`
	PCRDigest []byte          `json:"pcr_digest"`

	// Index is the policy's NV index and IndexName its TPM Name, which
	// every object bound to the policy commits to.
	Index     uint32 `json:"index"`
	IndexName []byte `json:"index_name"`

	// PolicyRef binds approvals to this policy and no other.
	PolicyRef []byte `json:"policy_ref"`

	// Approval is the current approval; nil after a revoke until the next
	// update.
	Approval *Approval `json:"approval,omitempty"`

	// AutoUnseal marks the policy barrier auto-unseal uses; at most one
	// policy per scope carries it.
	AutoUnseal bool `json:"auto_unseal,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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

// CreatePolicyRequest describes a named policy to create. The PCR values are
// never supplied by the caller: they are read from the scope's TPM.
type CreatePolicyRequest struct {
	// Name is the policy's name, unique within the scope.
	Name string

	// Bank is the PCR bank: sha1, sha256, sha384 or sha512.
	Bank string

	// PCRs are the selected PCR indices, 0 through 23, without duplicates.
	PCRs []uint

	// AutoUnseal marks the policy barrier auto-unseal uses, clearing the
	// mark from any other policy of the scope.
	AutoUnseal bool

	// OwnerAuth authorizes defining the policy's NV index under the
	// physical TPM's owner hierarchy (and the scope's counter, when the
	// scope is created by this call). A vTPM's owner hierarchy has no auth.
	OwnerAuth []byte
}

// Verification compares a policy's captured PCR values with the live ones.
// It is an advisory, read-only check: the TPM itself enforces the policy
// when an object is used.
type Verification struct {
	// Policy is the verified policy's name.
	Policy string

	// Match reports whether every selected PCR still holds its captured
	// value, and Mismatched lists those that do not, ascending.
	Match      bool
	Mismatched []uint

	// Approved reports whether the policy has an approval at the scope
	// counter's current value, so its approved branch can be satisfied.
	Approved bool
}

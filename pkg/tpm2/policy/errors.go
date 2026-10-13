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

package policy

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNilScope, ErrNilPolicy and ErrNilAssignment are returned for a nil
	// record argument.
	ErrNilScope      = errors.New("tpmpolicy: scope is nil")
	ErrNilPolicy     = errors.New("tpmpolicy: policy is nil")
	ErrNilAssignment = errors.New("tpmpolicy: assignment is nil")

	// ErrScopeNotFound is returned when a tenant has no TPM scope yet.
	ErrScopeNotFound = errors.New("tpmpolicy: TPM scope not found")

	// ErrPolicyNotFound is returned for an unknown policy name.
	ErrPolicyNotFound = errors.New("tpmpolicy: policy not found")

	// ErrPolicyExists is returned when creating a policy whose name is taken.
	ErrPolicyExists = errors.New("tpmpolicy: policy already exists")

	// ErrReservedPolicy is returned for any attempt to create, update or
	// delete the built-in platform policy.
	ErrReservedPolicy = errors.New("tpmpolicy: the built-in platform policy cannot be changed")

	// ErrNotAssigned is returned when an object has no recorded policy.
	ErrNotAssigned = errors.New("tpmpolicy: object has no recorded policy")

	// ErrNilRegistry, ErrNilTPM, ErrNilPlatformSRK, ErrNilKeys,
	// ErrNilTenantKeys and ErrNilSealer are returned by NewService for a
	// missing Config field.
	ErrNilRegistry    = errors.New("tpmpolicy: Config.Registry is required")
	ErrNilTPM         = errors.New("tpmpolicy: Config.TPM is required")
	ErrNilPlatformSRK = errors.New("tpmpolicy: Config.PlatformSRK is required")
	ErrNilKeys        = errors.New("tpmpolicy: Config.Keys is required")
	ErrNilTenantKeys  = errors.New("tpmpolicy: Config.TenantKeys is required")
	ErrNilSealer      = errors.New("tpmpolicy: Config.Sealer is required")

	// ErrTPMModeNone is returned for any TPM object or policy operation of a
	// tenant whose TPM mode is none.
	ErrTPMModeNone = errors.New("tpmpolicy: the tenant's TPM mode is none")

	// ErrVTPMUnavailable is returned when a tenant needs a vTPM and the
	// service was configured without one.
	ErrVTPMUnavailable = errors.New("tpmpolicy: vTPM mode is not available on this node")

	// ErrNotVTPMMode is returned by vTPM lifecycle calls for a tenant whose
	// TPM mode is not vtpm.
	ErrNotVTPMMode = errors.New("tpmpolicy: the tenant's TPM mode is not vtpm")

	// ErrSystemScopeMode is returned by SetMode for the system scope, which
	// always uses the physical TPM.
	ErrSystemScopeMode = errors.New("tpmpolicy: the system scope's TPM mode cannot be changed")

	// ErrPolicyRevoked is returned for a policy whose approval has been
	// revoked: its objects answer only to their password branch until the
	// policy is updated.
	ErrPolicyRevoked = errors.New("tpmpolicy: the policy's approval has been revoked")

	// ErrEmptyPCRSelection is returned for a pcr condition that selects no
	// PCR.
	ErrEmptyPCRSelection = errors.New("tpmpolicy: a pcr condition must select at least one PCR")

	// ErrEmptyLocalitySelection is returned for a locality condition that
	// allows no locality.
	ErrEmptyLocalitySelection = errors.New("tpmpolicy: a locality condition must allow at least one locality")

	// ErrNoBranches is returned for a policy without branches.
	ErrNoBranches = errors.New("tpmpolicy: a policy must have at least one branch")

	// ErrEmptyBranch is returned for a branch without conditions.
	ErrEmptyBranch = errors.New("tpmpolicy: a policy branch must have at least one condition")

	// ErrPCRValuesSupplied is returned for a condition that carries PCR
	// values or a PCR digest: they are captured from the TPM, never
	// supplied.
	ErrPCRValuesSupplied = errors.New("tpmpolicy: PCR values are captured from the TPM and cannot be supplied")

	// ErrMalformedSecrets is returned when a scope's unsealed secrets do not
	// have the sealed layout.
	ErrMalformedSecrets = errors.New("tpmpolicy: malformed scope secrets")

	// ErrUnexpectedTPM is returned when a vTPM connection does not open as
	// a *tpm2.TPM2, which the authorized-policy primitives require.
	ErrUnexpectedTPM = errors.New("tpmpolicy: the vTPM did not open as a pkg/tpm2 TPM")
)

// InvalidTenantError reports a tenant ID that cannot name a scope.
type InvalidTenantError struct {
	Tenant string
	Err    error
}

// Error implements the error interface.
func (e *InvalidTenantError) Error() string {
	return fmt.Sprintf("tpmpolicy: invalid tenant %q: %v", e.Tenant, e.Err)
}

// Unwrap returns the underlying cause.
func (e *InvalidTenantError) Unwrap() error { return e.Err }

// InvalidNameError reports a policy or object name that cannot be stored.
type InvalidNameError struct {
	Name string
}

// Error implements the error interface.
func (e *InvalidNameError) Error() string {
	return fmt.Sprintf("tpmpolicy: invalid name %q", e.Name)
}

// InvalidModeError reports an unknown tpm.mode value.
type InvalidModeError struct {
	Mode string
}

// Error implements the error interface.
func (e *InvalidModeError) Error() string {
	return fmt.Sprintf("tpmpolicy: invalid TPM mode %q (want none, shared or vtpm)", e.Mode)
}

// StoreError wraps a registry storage failure.
type StoreError struct {
	Op  string
	Key string
	Err error
}

// Error implements the error interface.
func (e *StoreError) Error() string {
	return fmt.Sprintf("tpmpolicy: registry %s %q: %v", e.Op, e.Key, e.Err)
}

// Unwrap returns the underlying cause.
func (e *StoreError) Unwrap() error { return e.Err }

// PolicyInUseError is returned when deleting a policy objects still use. It
// lists them, because the TPM cannot say which objects are bound to a policy.
type PolicyInUseError struct {
	Policy  string
	Objects []string
}

// Error implements the error interface.
func (e *PolicyInUseError) Error() string {
	return fmt.Sprintf("tpmpolicy: policy %q is assigned to %d object(s): %s",
		e.Policy, len(e.Objects), strings.Join(e.Objects, ", "))
}

// ScopeInUseError is returned when a tenant's TPM scope still holds objects
// or policies, which cannot move to another TPM -- so its mode cannot change
// and it cannot be removed.
type ScopeInUseError struct {
	Tenant   string
	Objects  []string
	Policies []string
}

// Error implements the error interface.
func (e *ScopeInUseError) Error() string {
	return fmt.Sprintf("tpmpolicy: tenant %q still has %d TPM object(s) and %d policy(ies)",
		e.Tenant, len(e.Objects), len(e.Policies))
}

// InvalidPCRBankError reports a PCR bank other than sha1, sha256, sha384 or
// sha512.
type InvalidPCRBankError struct {
	Bank string
}

// Error implements the error interface.
func (e *InvalidPCRBankError) Error() string {
	return fmt.Sprintf("tpmpolicy: invalid PCR bank %q (want sha1, sha256, sha384 or sha512)", e.Bank)
}

// InvalidPCRError reports a PCR index above 23, or selected twice.
type InvalidPCRError struct {
	PCR       uint
	Duplicate bool
}

// Error implements the error interface.
func (e *InvalidPCRError) Error() string {
	if e.Duplicate {
		return fmt.Sprintf("tpmpolicy: PCR %d is selected more than once", e.PCR)
	}
	return fmt.Sprintf("tpmpolicy: invalid PCR %d (want 0 through %d)", e.PCR, maxPCR)
}

// InvalidLocalityError reports a locality above 4, or allowed twice.
type InvalidLocalityError struct {
	Locality  uint
	Duplicate bool
}

// Error implements the error interface.
func (e *InvalidLocalityError) Error() string {
	if e.Duplicate {
		return fmt.Sprintf("tpmpolicy: locality %d is allowed more than once", e.Locality)
	}
	return fmt.Sprintf("tpmpolicy: invalid locality %d (want 0 through %d)", e.Locality, maxLocality)
}

// UnknownConditionTypeError reports a condition type other than pcr,
// auth_value or locality.
type UnknownConditionTypeError struct {
	Type ConditionType
}

// Error implements the error interface.
func (e *UnknownConditionTypeError) Error() string {
	return fmt.Sprintf("tpmpolicy: unknown condition type %q (want pcr, auth_value or locality)", e.Type)
}

// DuplicateConditionError reports a branch with two conditions of one type.
type DuplicateConditionError struct {
	Type ConditionType
}

// Error implements the error interface.
func (e *DuplicateConditionError) Error() string {
	return fmt.Sprintf("tpmpolicy: a branch has more than one %s condition", e.Type)
}

// ConditionOperandError reports a condition carrying an operand of another
// condition type.
type ConditionOperandError struct {
	Type    ConditionType
	Operand string
}

// Error implements the error interface.
func (e *ConditionOperandError) Error() string {
	return fmt.Sprintf("tpmpolicy: a %s condition takes no %s", e.Type, e.Operand)
}

// InvalidBranchError reports why branch Branch (counted from 0) of a policy
// request is invalid.
type InvalidBranchError struct {
	Branch int
	Err    error
}

// Error implements the error interface.
func (e *InvalidBranchError) Error() string {
	return fmt.Sprintf("tpmpolicy: branch %d: %v", e.Branch, e.Err)
}

// Unwrap returns the reason.
func (e *InvalidBranchError) Unwrap() error { return e.Err }

// DescriptionTooLongError reports a policy description longer than Max
// bytes.
type DescriptionTooLongError struct {
	Length int
	Max    int
}

// Error implements the error interface.
func (e *DescriptionTooLongError) Error() string {
	return fmt.Sprintf("tpmpolicy: description is %d bytes (at most %d)", e.Length, e.Max)
}

// PCRBankUnavailableError reports that the TPM did not return the selected
// PCRs in the requested bank, usually because the bank is not allocated.
type PCRBankUnavailableError struct {
	Bank string
}

// Error implements the error interface.
func (e *PCRBankUnavailableError) Error() string {
	return fmt.Sprintf("tpmpolicy: the TPM has no allocated %s PCR bank for the selection", e.Bank)
}

// UnknownAuthorityError reports an approval signed by an authority
// generation the scope no longer records.
type UnknownAuthorityError struct {
	Scope      string
	Generation uint64
}

// Error implements the error interface.
func (e *UnknownAuthorityError) Error() string {
	return fmt.Sprintf("tpmpolicy: scope %q has no policy authority of generation %d", e.Scope, e.Generation)
}

// CounterRollbackError reports a revocation counter below the epoch the
// scope's approvals were signed at: the counter was redefined or the scope
// record belongs to another TPM.
type CounterRollbackError struct {
	Scope   string
	Counter uint64
	Epoch   uint64
}

// Error implements the error interface.
func (e *CounterRollbackError) Error() string {
	return fmt.Sprintf("tpmpolicy: scope %q counter is %d, below its recorded epoch %d", e.Scope, e.Counter, e.Epoch)
}

// TPMError wraps a TPM failure with the scope and operation it occurred in.
type TPMError struct {
	Scope string
	Op    string
	Err   error
}

// Error implements the error interface.
func (e *TPMError) Error() string {
	return fmt.Sprintf("tpmpolicy: scope %q: %s: %v", e.Scope, e.Op, e.Err)
}

// Unwrap returns the underlying cause.
func (e *TPMError) Unwrap() error { return e.Err }

// SecretsError wraps a failure creating, sealing or unsealing a scope's
// secrets.
type SecretsError struct {
	Scope string
	Op    string
	Err   error
}

// Error implements the error interface.
func (e *SecretsError) Error() string {
	return fmt.Sprintf("tpmpolicy: scope %q secrets: %s: %v", e.Scope, e.Op, e.Err)
}

// Unwrap returns the underlying cause.
func (e *SecretsError) Unwrap() error { return e.Err }

// VTPMError wraps a failure starting, stopping or connecting to a tenant's
// vTPM.
type VTPMError struct {
	Tenant string
	Op     string
	Err    error
}

// Error implements the error interface.
func (e *VTPMError) Error() string {
	return fmt.Sprintf("tpmpolicy: vTPM of tenant %q: %s: %v", e.Tenant, e.Op, e.Err)
}

// Unwrap returns the underlying cause.
func (e *VTPMError) Unwrap() error { return e.Err }

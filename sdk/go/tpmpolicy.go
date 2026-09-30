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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TPM policy service (pkg/tpmpolicy) re-exports. A connected client reaches
// the TPM policy API through Client (TPMPolicyCreate, TPMPolicyList, ...); a
// process that owns its TPM -- xKey's local mode -- runs the same service
// in-process over its own TPM with these.

// TPMPolicyService manages named TPM policies, the registry of which TPM
// object uses which policy, and each tenant's TPM scope.
type TPMPolicyService = tpmpolicy.Service

// TPMPolicyConfig configures a TPMPolicyService.
type TPMPolicyConfig = tpmpolicy.Config

// TPMPolicyRegistry persists TPM scopes, named policies and assignments.
type TPMPolicyRegistry = tpmpolicy.Registry

// TPMScopeTPM is where a scope's TPM objects live: its TPM, storage parent
// and key store. The caller closes it after use.
type TPMScopeTPM = tpmpolicy.ScopeTPM

// TPMPolicyDefinition is a stored named TPM policy: its description, its
// branches with their captured values, and their current approvals.
type TPMPolicyDefinition = tpmpolicy.Policy

// TPMPolicyCreateParams describes a named TPM policy to create in-process.
type TPMPolicyCreateParams = tpmpolicy.CreatePolicyRequest

// TPMPolicyDefinitionBranch is one branch of a stored policy: the AND of its
// conditions.
type TPMPolicyDefinitionBranch = tpmpolicy.Branch

// TPMPolicyDefinitionCondition is one condition of a stored policy branch.
type TPMPolicyDefinitionCondition = tpmpolicy.Condition

// TPMPolicyConditionType is the kind of a stored policy condition.
type TPMPolicyConditionType = tpmpolicy.ConditionType

// TPMPolicyVerificationBranch compares one branch's captured PCR values
// with the live ones.
type TPMPolicyVerificationBranch = tpmpolicy.BranchVerification

// TPMPolicyVerification compares a policy's captured PCR values with the
// live ones.
type TPMPolicyVerification = tpmpolicy.Verification

// TPMPolicyAssignment records the TPM policy an object was created under.
type TPMPolicyAssignment = tpmpolicy.Assignment

// TPMPolicyScope is a tenant's TPM scope record.
type TPMPolicyScope = tpmpolicy.Scope

// TPMPolicyAuthority identifies a scope's policy-authority signing key.
type TPMPolicyAuthority = tpmpolicy.Authority

// TPMPolicyApproval is the authority's signed approval of a policy.
type TPMPolicyApproval = tpmpolicy.Approval

// TPMMode is a tenant's TPM mode.
type TPMMode = tpmpolicy.Mode

// TPMObjectKind distinguishes the TPM objects a policy is assigned to.
type TPMObjectKind = tpmpolicy.ObjectKind

// TPMVTPMConfig configures the per-tenant vTPM supervisor.
type TPMVTPMConfig = vtpm.Config

// TPMVTPMStatus describes one tenant's vTPM.
type TPMVTPMStatus = vtpm.Status

// TPMPolicyParams are the dependencies of BuildTPMPolicyService.
type TPMPolicyParams = compose.TPMPolicyParams

// TenantTPMPolicies serves the tenant-level TPM policy operations
// (TPMPolicyCreate ... TPMPolicyRotateAuthority) for one fixed tenant over a
// TPMPolicyService, in the API's types. It is the conversion xkmsd serves
// the TPM policy API through; a process that owns its TPM uses it with the
// system scope ("").
type TenantTPMPolicies = pkgxkms.TenantTPMPolicies

// InvalidTPMObjectKindError reports a TPM object kind other than "key" or
// "sealed".
type InvalidTPMObjectKindError = pkgxkms.InvalidTPMObjectKindError

// TPMPolicyInUseError is returned when deleting a policy objects still use;
// it lists them.
type TPMPolicyInUseError = tpmpolicy.PolicyInUseError

// TPMScopeInUseError is returned when a tenant's TPM mode cannot change
// because its scope still holds objects or policies.
type TPMScopeInUseError = tpmpolicy.ScopeInUseError

// TPM modes and object kinds.
const (
	TPMModeNone    = tpmpolicy.ModeNone
	TPMModeShared  = tpmpolicy.ModeShared
	TPMModeVTPM    = tpmpolicy.ModeVTPM
	TPMDefaultMode = tpmpolicy.DefaultMode

	TPMObjectKey    = tpmpolicy.ObjectKey
	TPMObjectSealed = tpmpolicy.ObjectSealed

	// TPMPolicyPlatform is the built-in policy every scope has.
	TPMPolicyPlatform = tpmpolicy.PlatformPolicy

	// TPMObjectKindKey and TPMObjectKindSealed are the object kinds a
	// TPMObjectPolicyRequest names.
	TPMObjectKindKey    = transport.TPMObjectKindKey
	TPMObjectKindSealed = transport.TPMObjectKindSealed

	// TPMPolicyConditionPCR, TPMPolicyConditionAuthValue and
	// TPMPolicyConditionLocality are the condition types a policy branch
	// ANDs together.
	TPMPolicyConditionPCR       = transport.TPMPolicyConditionPCR
	TPMPolicyConditionAuthValue = transport.TPMPolicyConditionAuthValue
	TPMPolicyConditionLocality  = transport.TPMPolicyConditionLocality

	// DefaultTPMPolicyBank is the bank a branch spec's pcr condition
	// selects when it names none.
	DefaultTPMPolicyBank = transport.DefaultTPMPolicyBank
)

var (
	// NewTPMPolicyService returns a TPMPolicyService over a TPMPolicyConfig.
	NewTPMPolicyService = tpmpolicy.NewService

	// NewTPMPolicyRegistry returns a TPMPolicyRegistry over a storage
	// backend.
	NewTPMPolicyRegistry = tpmpolicy.NewRegistry

	// BuildTPMPolicyService builds a TPMPolicyService over a TPM2 key
	// backend, as xkmsd does, and installs it as the backend's scope
	// provider.
	BuildTPMPolicyService = compose.BuildTPMPolicyService

	// ParseTPMMode returns the TPMMode a string names.
	ParseTPMMode = tpmpolicy.ParseMode

	// TPMPolicyObjectID returns the registry ID of a TPM object.
	TPMPolicyObjectID = tpmpolicy.ObjectID

	// NewTenantTPMPolicies returns the TenantTPMPolicies of a tenant ("" is
	// the system scope) over a TPMPolicyService.
	NewTenantTPMPolicies = pkgxkms.NewTenantTPMPolicies

	// ParseTPMObjectKind returns the TPMObjectKind an API object kind
	// ("key", "" or "sealed") names, or *InvalidTPMObjectKindError.
	ParseTPMObjectKind = pkgxkms.ParseTPMObjectKind

	// TPMPolicyScopeName normalizes a tenant ID to its scope name ("" and
	// the system tenant are "system"); it is the xkms-wide scope.TenantName.
	TPMPolicyScopeName = scope.TenantName

	// TPMPolicyPCRBranch returns an API branch holding one pcr condition:
	// the whole of a policy that approves one PCR state.
	TPMPolicyPCRBranch = transport.TPMPolicyPCRBranch

	// ParseTPMPolicyBranch parses a branch spec, the command-line form of
	// one policy branch: "pcr=[BANK:]LIST", "auth_value" and
	// "locality=LIST" joined by ";".
	ParseTPMPolicyBranch = transport.ParseTPMPolicyBranch

	// TPMPolicyBranches returns the branches a command line describes: the
	// parsed branch specs, or the one pcr branch of a PCR selection.
	TPMPolicyBranches = transport.TPMPolicyBranches

	// NewTPMPolicyPCRBranch returns an in-process branch holding one pcr
	// condition.
	NewTPMPolicyPCRBranch = tpmpolicy.PCRBranch
)

// TPM policy service errors.
var (
	ErrTPMPolicyNotFound    = tpmpolicy.ErrPolicyNotFound
	ErrTPMPolicyExists      = tpmpolicy.ErrPolicyExists
	ErrTPMPolicyReserved    = tpmpolicy.ErrReservedPolicy
	ErrTPMPolicyNotAssigned = tpmpolicy.ErrNotAssigned
	ErrTPMPolicyRevoked     = tpmpolicy.ErrPolicyRevoked
	ErrTPMScopeNotFound     = tpmpolicy.ErrScopeNotFound
	ErrTPMModeNone          = tpmpolicy.ErrTPMModeNone
	ErrTPMVTPMUnavailable   = tpmpolicy.ErrVTPMUnavailable
	ErrTPMNotVTPMMode       = tpmpolicy.ErrNotVTPMMode

	// Policy structure errors.
	ErrTPMPolicyNoBranches        = tpmpolicy.ErrNoBranches
	ErrTPMPolicyEmptyBranch       = tpmpolicy.ErrEmptyBranch
	ErrTPMPolicyEmptyPCRSelection = tpmpolicy.ErrEmptyPCRSelection
	ErrTPMPolicyEmptyLocalities   = tpmpolicy.ErrEmptyLocalitySelection
	ErrTPMPolicyPCRValuesSupplied = tpmpolicy.ErrPCRValuesSupplied

	// Branch spec errors (ParseTPMPolicyBranch).
	ErrTPMPolicyBranchEmpty      = transport.ErrTPMPolicyBranchEmpty
	ErrTPMPolicyConditionUnknown = transport.ErrTPMPolicyConditionUnknown
	ErrTPMPolicyConditionValue   = transport.ErrTPMPolicyConditionValue
	ErrTPMPolicyNoSelection      = transport.ErrTPMPolicyNoSelection
	ErrTPMPolicyPCRsAndBranches  = transport.ErrTPMPolicyPCRsAndBranches
)

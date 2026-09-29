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
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
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

// TPMPolicyDefinition is a stored named TPM policy: its PCR selection, the
// captured values and its current approval.
type TPMPolicyDefinition = tpmpolicy.Policy

// TPMPolicyCreateParams describes a named TPM policy to create in-process.
type TPMPolicyCreateParams = tpmpolicy.CreatePolicyRequest

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

	// TPMPolicyScopeName normalizes a tenant ID to its scope name.
	TPMPolicyScopeName = tpmpolicy.ScopeName
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
)

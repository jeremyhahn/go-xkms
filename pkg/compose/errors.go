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

package compose

import "errors"

// ErrUnsupportedTPM is returned by BuildTPMPolicyService when the TPM2
// backend's TPM is not a pkg/tpm2 TPM, whose authorized-policy primitives
// the TPM policy service needs.
var ErrUnsupportedTPM = errors.New("compose: the TPM2 backend's TPM is not a pkg/tpm2 TPM")

// Feature names a store-backed subsystem this package composes.
type Feature string

// The features Build composes, in construction order.
const (
	// FeaturePasswords is the Password Manager store (pkg/staticpw).
	FeaturePasswords Feature = "passwords"

	// FeatureTenantPasswords is the per-tenant Password Manager routing
	// over the tenant barrier registry.
	FeatureTenantPasswords Feature = "tenant-passwords"

	// FeaturePIN is the PIN backend: the user PIN that opens a tenant
	// Password Manager session, and the PIN management surface.
	FeaturePIN Feature = "pin"

	// FeaturePlatformStore is the platform sealed-secret store.
	FeaturePlatformStore Feature = "platform-store"

	// FeatureCredentials is the backend credential service.
	FeatureCredentials Feature = "credentials"

	// FeatureSSH is the SSH key, host-pin and authorized-keys subsystem.
	FeatureSSH Feature = "ssh"

	// FeatureCA is the Certificate Authority.
	FeatureCA Feature = "ca"

	// FeatureTPMPolicies is the TPM policy service: named TPM policies,
	// the registry of which TPM object uses which, and each tenant's TPM
	// scope (pkg/tpmpolicy).
	FeatureTPMPolicies Feature = "tpm-policies"

	// FeatureKeyVersions is the key-version record store: which versions
	// each rotated key has and which one is current (pkg/keyversion).
	FeatureKeyVersions Feature = "key-versions"

	// FeatureOIDCCredentials is the server-side OIDC credential service
	// (pkg/oidc/credential) and its refresh scheduler.
	FeatureOIDCCredentials Feature = "oidc-credentials"

	// FeatureBarrier is the system barrier served by the barrier routes.
	FeatureBarrier Feature = "barrier"

	// FeatureCustody is Shamir share custody: custodian groups and share
	// collection over the qrdb node.
	FeatureCustody Feature = "custody"

	// FeatureInvite is the enrollment-invitation store (go-xkms#1294 part B).
	FeatureInvite Feature = "invite"

	// FeatureBackup is whole-node backup/restore over the qrdb node's
	// shard-snapshot capability (go-xkms#728).
	FeatureBackup Feature = "backup"
)

// FeatureDisabledError reports a feature left off because a dependency it
// needs was not supplied. It is informational, not a failure: the rest of
// the composition proceeds without the feature.
type FeatureDisabledError struct {
	// Feature is the feature left off.
	Feature Feature

	// Missing names the dependency that was not supplied.
	Missing string
}

// Error implements the error interface.
func (e *FeatureDisabledError) Error() string {
	return "compose: " + string(e.Feature) + " is off: no " + e.Missing + " was supplied"
}

// FeatureBuildError reports a feature whose construction failed with its
// dependencies present.
type FeatureBuildError struct {
	// Feature is the feature that failed to build.
	Feature Feature

	// Err is the construction failure.
	Err error
}

// Error implements the error interface.
func (e *FeatureBuildError) Error() string {
	return "compose: " + string(e.Feature) + " failed to build: " + e.Err.Error()
}

// Unwrap exposes the construction failure for errors.Is/errors.As.
func (e *FeatureBuildError) Unwrap() error { return e.Err }

// NilServiceError is returned by Build when Deps carries no XKMSService:
// there is nothing to compose the stores into.
type NilServiceError struct{}

// Error implements the error interface.
func (e *NilServiceError) Error() string {
	return "compose: Build requires a non-nil XKMSService"
}

// NilDependencyError reports a required argument missing from a Build*
// call — a composition error in the caller, as opposed to an optional
// dependency a host chose not to supply (FeatureDisabledError).
type NilDependencyError struct {
	// Feature is the feature being built.
	Feature Feature

	// Dependency names the missing argument.
	Dependency string
}

// Error implements the error interface.
func (e *NilDependencyError) Error() string {
	return "compose: building " + string(e.Feature) + " requires a non-nil " + e.Dependency
}

// CANoIdentitiesError is returned by BuildCA for a CA configuration that
// declares no identity to issue from.
type CANoIdentitiesError struct{}

// Error implements the error interface.
func (e *CANoIdentitiesError) Error() string {
	return "compose: CA configuration has no identities"
}

// CAOperationError reports a failed step of CA construction, naming the
// step so an operator can tell a missing keystore from a corrupt persisted
// CA.
type CAOperationError struct {
	// Operation is the step that failed.
	Operation string

	// Err is the step's failure.
	Err error
}

// Error implements the error interface.
func (e *CAOperationError) Error() string {
	return "compose: CA " + e.Operation + " failed: " + e.Err.Error()
}

// Unwrap exposes the step's failure for errors.Is/errors.As.
func (e *CAOperationError) Unwrap() error { return e.Err }

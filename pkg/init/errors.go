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

package initialize

import qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

// --- Re-exported errors from go-qrdb/sdk/go ceremony ---

var (
	// ErrNilConfig is returned when a nil configuration is provided.
	ErrNilConfig = qrdbsdk.ErrCeremonyNilConfig

	// ErrNilBarrier is returned when a nil barrier is provided.
	ErrNilBarrier = qrdbsdk.ErrCeremonyNilBarrier

	// ErrNilLogger is returned when a nil logger is provided.
	ErrNilLogger = qrdbsdk.ErrCeremonyNilLogger

	// ErrAlreadyInitialized is returned when the initialization ceremony
	// has already been completed.
	ErrAlreadyInitialized = qrdbsdk.ErrCeremonyAlreadyInitialized

	// ErrNotInEnrollingState is returned when an operation requires the
	// system to be in the enrolling state.
	ErrNotInEnrollingState = qrdbsdk.ErrCeremonyNotInEnrollingState

	// ErrNotInOperationalState is returned when an operation requires the
	// system to be in the operational state.
	ErrNotInOperationalState = qrdbsdk.ErrCeremonyNotInOperationalState

	// ErrInvalidSOPIN is returned when the SO PIN is empty or invalid.
	ErrInvalidSOPIN = qrdbsdk.ErrCeremonyInvalidSOPIN

	// ErrInvalidUserPIN is returned when the user PIN is empty or invalid.
	ErrInvalidUserPIN = qrdbsdk.ErrCeremonyInvalidUserPIN

	// ErrInvalidThreshold is returned when the threshold value is less than 2
	// or exceeds the number of officers.
	ErrInvalidThreshold = qrdbsdk.ErrCeremonyInvalidThreshold

	// ErrNoOfficers is returned when M-of-N initialization is requested but
	// no officers are specified.
	ErrNoOfficers = qrdbsdk.ErrCeremonyNoOfficers

	// ErrInvalidCSR is returned when CSR validation fails.
	ErrInvalidCSR = qrdbsdk.ErrCeremonyInvalidCSR

	// ErrDuplicateUsername is returned when an officer username already exists.
	ErrDuplicateUsername = qrdbsdk.ErrCeremonyDuplicateUsername

	// ErrPendingCertNotFound is returned when no pending certificate is found
	// for the specified username.
	ErrPendingCertNotFound = qrdbsdk.ErrCeremonyPendingCertNotFound

	// ErrCertAlreadyClaimed is returned when a certificate has already been
	// claimed by a security officer.
	ErrCertAlreadyClaimed = qrdbsdk.ErrCeremonyCertAlreadyClaimed

	// ErrShareAlreadyClaimed is returned when a share has already been claimed
	// by a security officer.
	ErrShareAlreadyClaimed = qrdbsdk.ErrCeremonyShareAlreadyClaimed

	// ErrShareNotFound is returned when no share is found for the specified
	// security officer.
	ErrShareNotFound = qrdbsdk.ErrCeremonyShareNotFound

	// ErrChallengeVerificationFailed is returned when nonce signature
	// verification fails during the claim process.
	ErrChallengeVerificationFailed = qrdbsdk.ErrCeremonyChallengeVerificationFailed

	// ErrUserNotFound is returned when a user is not found during the claim
	// process.
	ErrUserNotFound = qrdbsdk.ErrCeremonyUserNotFound

	// ErrThresholdNotSupported is returned when the HSM does not support
	// native threshold operations.
	ErrThresholdNotSupported = qrdbsdk.ErrCeremonyThresholdNotSupported

	// ErrVendorNotRegistered is returned when the vendor name is not found
	// in the threshold registry.
	ErrVendorNotRegistered = qrdbsdk.ErrCeremonyVendorNotRegistered

	// ErrVendorNotAvailable is returned when the vendor's hardware or library
	// is not present on the system.
	ErrVendorNotAvailable = qrdbsdk.ErrCeremonyVendorNotAvailable

	// ErrInitFailed is returned when initialization fails. This error is
	// intended to be wrapped with the underlying cause.
	ErrInitFailed = qrdbsdk.ErrCeremonyInitFailed

	// ErrNotImplemented is returned when an operation is not yet implemented.
	ErrNotImplemented = qrdbsdk.ErrCeremonyNotImplemented

	// ErrSOPINMismatch is returned when the provided SO PIN does not match
	// the configured SO PIN during CSR signing.
	ErrSOPINMismatch = qrdbsdk.ErrCeremonySOPINMismatch

	// ErrCANotInitialized is returned when a CA operation is attempted
	// before the CA has been initialized via the ceremony.
	ErrCANotInitialized = qrdbsdk.ErrCeremonyCANotInitialized

	// ErrMissingCSRPEM is returned when the CSR PEM field is empty in a
	// sign-csr request.
	ErrMissingCSRPEM = qrdbsdk.ErrCeremonyMissingCSRPEM

	// ErrMissingUsername is returned when the username field is empty in a
	// sign-csr request.
	ErrMissingUsername = qrdbsdk.ErrCeremonyMissingUsername

	// ErrMissingRole is returned when the role field is empty in a
	// sign-csr request.
	ErrMissingRole = qrdbsdk.ErrCeremonyMissingRole

	// ErrInvalidRole is returned when an unrecognized role is specified
	// in a sign-csr request.
	ErrInvalidRole = qrdbsdk.ErrCeremonyInvalidRole

	// ErrCSRSigningFailed is returned when the CA fails to sign a CSR
	// during the init ceremony.
	ErrCSRSigningFailed = qrdbsdk.ErrCeremonyCSRSigningFailed

	// ErrNotInitializedOrEnrolling is returned when a sign-csr operation
	// is attempted outside of the enrolling or operational states.
	ErrNotInitializedOrEnrolling = qrdbsdk.ErrCeremonyNotInitializedOrEnrolling

	// ErrNilCredentialService is returned when a nil credential service
	// is provided.
	ErrNilCredentialService = qrdbsdk.ErrCeremonyNilCredentialService

	// ErrChallengeExpired is returned when a challenge nonce has expired.
	ErrChallengeExpired = qrdbsdk.ErrCeremonyChallengeExpired

	// ErrChallengeNotFound is returned when no active challenge exists
	// for the given username.
	ErrChallengeNotFound = qrdbsdk.ErrCeremonyChallengeNotFound
)

// --- Re-exported error types from go-qrdb/sdk/go ceremony ---

// ShamirSplitError wraps an error from the Shamir split operation.
type ShamirSplitError = qrdbsdk.CeremonyShamirSplitError

// CSRParseError wraps an error from CSR parsing.
type CSRParseError = qrdbsdk.CeremonyCSRParseError

// CertEncodeError wraps an error from certificate encoding.
type CertEncodeError = qrdbsdk.CeremonyCertEncodeError

// ShareStoreError wraps an error from share storage operations.
type ShareStoreError = qrdbsdk.CeremonyShareStoreError

// CABundleError wraps an error from CA bundle operations.
type CABundleError = qrdbsdk.CeremonyCABundleError

// SPKIPinError wraps an error from SPKI pin computation.
type SPKIPinError = qrdbsdk.CeremonySPKIPinError

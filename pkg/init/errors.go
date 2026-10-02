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

import (
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

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

	// ErrCertThumbprintMismatch is returned when the caller's mTLS certificate
	// thumbprint does not match the thumbprint recorded for the officer at
	// enrollment. This is the refusal that keeps anyone who merely knows an
	// enrolled officer's username from taking that officer's Shamir share.
	ErrCertThumbprintMismatch = qrdbsdk.ErrCeremonyCertThumbprintMismatch

	// ErrOfficerNotFound is returned when no officer is enrolled under the
	// requested username.
	ErrOfficerNotFound = qrdbsdk.ErrCeremonyOfficerNotFound

	// ErrNoPendingShare is returned when the officer has no unclaimed share.
	ErrNoPendingShare = qrdbsdk.ErrCeremonyNoPendingShare

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

// ErrNoLocalFIDO2Ceremony indicates a passkey factor was planned but this
// build has no attached-authenticator driver wired. It surfaces at preflight,
// before the ceremony changes any state.
var ErrNoLocalFIDO2Ceremony = errors.New("init: no local FIDO2 ceremony is available to enroll a passkey")

// ErrPasskeyRPIDRequired indicates a passkey enrollment was attempted without
// a WebAuthn relying-party ID. A credential enrolled against the wrong RP ID
// verifies at enrollment and fails at every subsequent login, so it is refused
// rather than guessed.
var ErrPasskeyRPIDRequired = errors.New("init: WebAuthn relying-party ID is required to enroll a passkey")

// ErrAdminCertRequired indicates an mTLS factor was planned but no
// administrator certificate was supplied to bind it to. Enrolling the factor
// without one would record a login credential nobody holds.
var ErrAdminCertRequired = errors.New("init: administrator certificate is required to enroll the mtls factor")

// ErrRandomSource indicates the system random source failed.
var ErrRandomSource = errors.New("init: random source failed")

// RandomSourceError wraps a failure reading the system random source. A
// ceremony that cannot generate a fresh challenge must abort rather than reuse
// or weaken one.
type RandomSourceError struct {
	Err error
}

// Error describes the random-source failure.
func (e *RandomSourceError) Error() string {
	return ErrRandomSource.Error() + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *RandomSourceError) Unwrap() error { return e.Err }

// Is reports RandomSourceError as ErrRandomSource for errors.Is.
func (e *RandomSourceError) Is(target error) bool { return target == ErrRandomSource }

// ErrAdminKeyGeneration indicates the administrator's key pair or CSR could
// not be produced during first-boot Path A (generate-and-distribute).
var ErrAdminKeyGeneration = errors.New("init: administrator key generation failed")

// AdminKeyGenerationError wraps a failure generating the administrator's
// key pair, building its CSR, or encoding the key during first-boot Path A.
type AdminKeyGenerationError struct {
	Err error
}

// Error describes the key-generation failure.
func (e *AdminKeyGenerationError) Error() string {
	return ErrAdminKeyGeneration.Error() + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *AdminKeyGenerationError) Unwrap() error { return e.Err }

// Is reports AdminKeyGenerationError as ErrAdminKeyGeneration for errors.Is.
func (e *AdminKeyGenerationError) Is(target error) bool { return target == ErrAdminKeyGeneration }

// ErrNilSignOptions is returned by CAAdapter.SignCSR when go-qrdb passes no
// SignCSROptions: without them there is no registered holder and no tenant
// to name, and signing would fall back to whatever the CSR asked for.
var ErrNilSignOptions = errors.New("init: holder certificate signing requires the ceremony's sign options")

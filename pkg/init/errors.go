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

// HSM threshold errors, re-exported from go-qrdb/sdk/go.
var (
	// ErrThresholdNotSupported is returned when the HSM does not support
	// native threshold operations.
	ErrThresholdNotSupported = qrdbsdk.ErrCeremonyThresholdNotSupported

	// ErrVendorNotRegistered is returned when the vendor name is not found
	// in the threshold registry.
	ErrVendorNotRegistered = qrdbsdk.ErrCeremonyVendorNotRegistered

	// ErrVendorNotAvailable is returned when the vendor's hardware or library
	// is not present on the system.
	ErrVendorNotAvailable = qrdbsdk.ErrCeremonyVendorNotAvailable
)

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

// ErrNoSPIFFETrustDomain is returned when a CAAdapter built without a SPIFFE
// trust domain is asked for a login certificate. go-qrdb binds a login's
// tenant only through the certificate's SPIFFE ID SAN, so a certificate
// issued without one could never authenticate.
var ErrNoSPIFFETrustDomain = errors.New("init: login certificate issuance requires a SPIFFE trust domain")

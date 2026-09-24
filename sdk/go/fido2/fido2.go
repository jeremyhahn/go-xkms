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

// Package fido2 is the SDK re-export of the canonical FIDO2 CTAP2
// implementation (pkg/fido2). Client binaries import this package instead of
// pkg/fido2 so they depend only on the SDK, with no change to call sites.
package fido2

import pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"

// Re-exported types.
type (
	Authenticator                 = pkgfido2.Authenticator
	Config                        = pkgfido2.Config
	CTAPHIDDevice                 = pkgfido2.CTAPHIDDevice
	Device                        = pkgfido2.Device
	EnrollmentResult              = pkgfido2.EnrollmentResult
	Handler                       = pkgfido2.Handler
	FIDO2Handler                  = pkgfido2.FIDO2Handler
	HIDDevice                     = pkgfido2.HIDDevice
	HIDDeviceEnumerator           = pkgfido2.HIDDeviceEnumerator
	RelyingParty                  = pkgfido2.RelyingParty
	User                          = pkgfido2.User
	WebAuthnAssertion             = pkgfido2.WebAuthnAssertion
	WebAuthnAssertionRequest      = pkgfido2.WebAuthnAssertionRequest
	WebAuthnAttestation           = pkgfido2.WebAuthnAttestation
	WebAuthnAuthenticationOptions = pkgfido2.WebAuthnAuthenticationOptions
	WebAuthnRegistrationOptions   = pkgfido2.WebAuthnRegistrationOptions
	EnrollmentConfig              = pkgfido2.EnrollmentConfig
	AuthenticationConfig          = pkgfido2.AuthenticationConfig
	DerivationMode                = pkgfido2.DerivationMode
)

// Re-exported hmac-secret derivation modes.
const (
	// DerivationModeCTAP2 is the only mode: the hmac-secret output is
	// extracted from the authenticator data extension map and decrypted
	// with the PIN/UV auth shared secret.
	DerivationModeCTAP2 = pkgfido2.DerivationModeCTAP2
)

// Re-exported request-authorization error sentinels and the retry-annotated
// PIN failure.
//
// A caller driving a ceremony has to tell "this key needs a PIN and none was
// given" from "the PIN was wrong" from "this key has no PIN set" in order to
// say anything useful to an operator, and docs/00 forbids reaching into pkg/
// for them. ErrInvalidOption joins them because it reports a defect in the
// request the caller itself built — most often asking for the uv option on a
// key that verifies by PIN — rather than anything the operator did.
var (
	ErrPINRequired           = pkgfido2.ErrPINRequired
	ErrInvalidPIN            = pkgfido2.ErrInvalidPIN
	ErrPINBlocked            = pkgfido2.ErrPINBlocked
	ErrPINNotSet             = pkgfido2.ErrPINNotSet
	ErrPINAuthInvalid        = pkgfido2.ErrPINAuthInvalid
	ErrPINAuthBlocked        = pkgfido2.ErrPINAuthBlocked
	ErrPINRetriesUnavailable = pkgfido2.ErrPINRetriesUnavailable
	ErrInvalidOption         = pkgfido2.ErrInvalidOption
)

// PINAttemptsError is the retry-annotated PIN failure: a wrong PIN carrying
// the attempts the authenticator will still accept before it locks out.
type PINAttemptsError = pkgfido2.PINAttemptsError

// Re-exported constructors, defaults, and helpers.
var (
	DefaultConfig                    = pkgfido2.DefaultConfig
	NewAuthenticator                 = pkgfido2.NewAuthenticator
	NewCTAPHIDDevice                 = pkgfido2.NewCTAPHIDDevice
	NewDefaultEnumerator             = pkgfido2.NewDefaultEnumerator
	NewHandler                       = pkgfido2.NewHandler
	DefaultEnrollmentConfig          = pkgfido2.DefaultEnrollmentConfig
	DefaultAuthenticationConfig      = pkgfido2.DefaultAuthenticationConfig
	ParseWebAuthnRegistrationOptions = pkgfido2.ParseWebAuthnRegistrationOptions
)

// Re-exported registration-options parsing error sentinels.
var (
	ErrRegistrationOptionsRequired  = pkgfido2.ErrRegistrationOptionsRequired
	ErrRegistrationChallengeMissing = pkgfido2.ErrRegistrationChallengeMissing
	ErrRegistrationRPIDMissing      = pkgfido2.ErrRegistrationRPIDMissing
)

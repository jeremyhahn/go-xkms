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
	WebAuthnAttestation           = pkgfido2.WebAuthnAttestation
	WebAuthnAuthenticationOptions = pkgfido2.WebAuthnAuthenticationOptions
	WebAuthnRegistrationOptions   = pkgfido2.WebAuthnRegistrationOptions
	EnrollmentConfig              = pkgfido2.EnrollmentConfig
	AuthenticationConfig          = pkgfido2.AuthenticationConfig
)

// Re-exported constructors, defaults, and helpers.
var (
	DefaultConfig               = pkgfido2.DefaultConfig
	NewAuthenticator            = pkgfido2.NewAuthenticator
	NewCTAPHIDDevice            = pkgfido2.NewCTAPHIDDevice
	NewDefaultEnumerator        = pkgfido2.NewDefaultEnumerator
	NewHandler                  = pkgfido2.NewHandler
	DefaultEnrollmentConfig     = pkgfido2.DefaultEnrollmentConfig
	DefaultAuthenticationConfig = pkgfido2.DefaultAuthenticationConfig
)

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

// Package webauthnclient is the SDK re-export of the canonical headless
// WebAuthn ceremony driver (pkg/webauthn/client). pkg/webauthn/client is the
// single ceremony driver in go-xkms — the "browser" half of a WebAuthn
// registration or authentication ceremony, bridging a RelyingParty (the
// server side: HTTPRelyingParty for the browser-shaped pkg/webauthn/http
// routes, or TransportRelyingParty for the SDK transport routes) and an
// AuthenticatorAdapter (the authenticator side: HardwareAdapter for a real
// CTAP2 authenticator over HID, or SoftwareAdapter for headless testing).
// Client binaries (xkey, xkmsctl) and downstream composers (go-quicbaas)
// import this package instead of pkg/webauthn/client so they depend only on
// the SDK, with no change to call sites.
package webauthnclient

import pkgclient "github.com/jeremyhahn/go-xkms/pkg/webauthn/client"

// Re-exported types.
type (
	// Client is the headless WebAuthn ceremony driver.
	Client = pkgclient.Client

	// Config configures a Client: the RelyingParty (or the ServerURL/
	// HTTPClient/TLSConfig/Timeout to build the default HTTPRelyingParty),
	// the AuthenticatorAdapter, and the WebAuthn Origin.
	Config = pkgclient.Config

	// RegistrationRequest carries a registration ceremony's inputs.
	RegistrationRequest = pkgclient.RegistrationRequest

	// RegistrationResult carries a successful registration's outputs.
	RegistrationResult = pkgclient.RegistrationResult

	// AuthenticationRequest carries an authentication ceremony's inputs.
	AuthenticationRequest = pkgclient.AuthenticationRequest

	// AuthenticationResult carries a successful authentication's outputs.
	AuthenticationResult = pkgclient.AuthenticationResult

	// CeremonyOptions carries one AuthenticatorAdapter call's inputs: the
	// RelyingParty's JSON options, the WebAuthn origin, and the
	// authenticator's CTAP2 PIN.
	CeremonyOptions = pkgclient.CeremonyOptions

	// AuthenticatorAdapter bridges Client to a local authenticator:
	// HardwareAdapter or SoftwareAdapter.
	AuthenticatorAdapter = pkgclient.AuthenticatorAdapter

	// RelyingParty is the server-side seam of a ceremony: HTTPRelyingParty
	// or TransportRelyingParty.
	RelyingParty = pkgclient.RelyingParty

	// BeginResult carries a RelyingParty's answer to a begin call.
	BeginResult = pkgclient.BeginResult

	// AvailabilityChecker is a RelyingParty's optional server-reachability
	// capability.
	AvailabilityChecker = pkgclient.AvailabilityChecker

	// HTTPRelyingParty speaks the browser-shaped pkg/webauthn/http routes.
	HTTPRelyingParty = pkgclient.HTTPRelyingParty

	// TransportClient is the SDK transport subset a TransportRelyingParty
	// drives: the four WebAuthn ceremony RPCs. sdk/go's own Client (any
	// protocol) satisfies it directly.
	TransportClient = pkgclient.TransportClient

	// TransportRelyingParty speaks the SDK transport routes
	// (/api/v1/webauthn/sdk/...) through a TransportClient.
	TransportRelyingParty = pkgclient.TransportRelyingParty

	// SoftwareAdapter is a software-only CTAP2 authenticator for headless
	// testing and CI.
	SoftwareAdapter = pkgclient.SoftwareAdapter

	// HardwareAdapter drives a real CTAP2 authenticator over HID, including
	// xkey's virtual "xkey fido2" uhid authenticator.
	HardwareAdapter = pkgclient.HardwareAdapter

	// ClientError wraps an error with the Client operation that failed.
	ClientError = pkgclient.ClientError

	// ServerError reports an HTTP error from an HTTPRelyingParty's server.
	ServerError = pkgclient.ServerError

	// RelyingPartyRejection reports a ceremony a TransportRelyingParty's
	// server completed but declined.
	RelyingPartyRejection = pkgclient.RelyingPartyRejection
)

// Re-exported constructors.
var (
	// NewClient constructs a Client.
	NewClient = pkgclient.NewClient

	// NewHTTPRelyingParty constructs a RelyingParty over the browser-shaped
	// pkg/webauthn/http routes.
	NewHTTPRelyingParty = pkgclient.NewHTTPRelyingParty

	// NewTransportRelyingParty constructs a RelyingParty over an
	// already-connected SDK transport client.
	NewTransportRelyingParty = pkgclient.NewTransportRelyingParty

	// NewSoftwareAdapter constructs the software-only CTAP2 authenticator.
	NewSoftwareAdapter = pkgclient.NewSoftwareAdapter

	// NewHardwareAdapter opens the local CTAP2 authenticator over HID.
	NewHardwareAdapter = pkgclient.NewHardwareAdapter
)

// Re-exported error sentinels.
var (
	ErrServerURLRequired       = pkgclient.ErrServerURLRequired
	ErrUsernameRequired        = pkgclient.ErrUsernameRequired
	ErrRegistrationFailed      = pkgclient.ErrRegistrationFailed
	ErrAuthenticationFailed    = pkgclient.ErrAuthenticationFailed
	ErrServerUnavailable       = pkgclient.ErrServerUnavailable
	ErrInvalidServerResponse   = pkgclient.ErrInvalidServerResponse
	ErrAuthenticatorNotFound   = pkgclient.ErrAuthenticatorNotFound
	ErrCTAPOperationFailed     = pkgclient.ErrCTAPOperationFailed
	ErrNilConfig               = pkgclient.ErrNilConfig
	ErrInvalidChallenge        = pkgclient.ErrInvalidChallenge
	ErrSessionExpired          = pkgclient.ErrSessionExpired
	ErrNilHTTPClient           = pkgclient.ErrNilHTTPClient
	ErrNilRequest              = pkgclient.ErrNilRequest
	ErrNilAuthenticatorAdapter = pkgclient.ErrNilAuthenticatorAdapter
	ErrNilTransportClient      = pkgclient.ErrNilTransportClient
	ErrPINRequired             = pkgclient.ErrPINRequired
)

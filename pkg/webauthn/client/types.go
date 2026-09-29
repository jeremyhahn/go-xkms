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

package client

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// Config configures the WebAuthn client.
type Config struct {
	// ServerURL is the base URL of the WebAuthn relying party server.
	// Example: "https://xkms.company.com:8443". Required unless
	// RelyingParty is set directly, and always used (when non-empty) to
	// derive the default WebAuthn Origin.
	ServerURL string

	// HTTPClient is the HTTP client the default HTTPRelyingParty uses. If
	// nil, a default client with TLSConfig is created. Ignored when
	// RelyingParty is set directly.
	HTTPClient *http.Client

	// TLSConfig is used when HTTPClient is nil to create the default
	// client. Ignored when RelyingParty is set directly.
	TLSConfig *tls.Config

	// Timeout is the timeout for HTTP requests. Default: 30s. Ignored when
	// RelyingParty is set directly.
	Timeout time.Duration

	// Origin is the WebAuthn origin bound into clientDataJSON. Empty
	// derives it from ServerURL's scheme and host (OriginFromURL); if no
	// origin can be derived NewClient refuses with fido2.ErrOriginRequired.
	// The origin is never derived from the server-supplied rpId.
	Origin string

	// AuthenticatorAdapter bridges to the local CTAP2 authenticator:
	// SoftwareAdapter for headless testing/CI, or HardwareAdapter for a
	// real authenticator reachable over HID.
	AuthenticatorAdapter AuthenticatorAdapter

	// RelyingParty is the server-side seam of the ceremony. Nil builds the
	// default HTTPRelyingParty from ServerURL/HTTPClient/TLSConfig/Timeout,
	// speaking the browser-shaped pkg/webauthn/http routes. Set it to a
	// TransportRelyingParty to drive the ceremony over the SDK transport
	// routes instead.
	RelyingParty RelyingParty
}

// Validate checks the configuration for required fields.
func (c *Config) Validate() error {
	if c.RelyingParty == nil && c.ServerURL == "" {
		return ErrServerURLRequired
	}
	if c.AuthenticatorAdapter == nil {
		return ErrNilAuthenticatorAdapter
	}
	return nil
}

// SetDefaults applies default values to unset configuration fields.
func (c *Config) SetDefaults() {
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
}

// RegistrationRequest contains parameters for WebAuthn registration.
type RegistrationRequest struct {
	// Username is the user's email or identifier (required).
	Username string `json:"username"`

	// DisplayName is the user's display name (optional, defaults to username).
	DisplayName string `json:"display_name,omitempty"`

	// AuthToken is a JWT or setup token for authenticating the registration
	// request with the RP server. HTTPRelyingParty sends it as a bearer
	// token; TransportRelyingParty ignores it because the transport
	// connection already carries its own authentication.
	AuthToken string `json:"auth_token,omitempty"`

	// PIN is the authenticator's CTAP2 PIN, consumed by HardwareAdapter. An
	// authenticator with a PIN set refuses the ceremony outright
	// (CTAP2_ERR_PIN_REQUIRED) unless it is supplied. Nil is correct for an
	// authenticator with no PIN configured, and is ignored by
	// SoftwareAdapter, which never has one.
	PIN *secure.Secret `json:"-"`
}

// Validate checks the registration request for required fields.
func (r *RegistrationRequest) Validate() error {
	if r.Username == "" {
		return ErrUsernameRequired
	}
	return nil
}

// RegistrationResult contains the result of a successful registration.
type RegistrationResult struct {
	// UserID is the server-assigned user identifier (base64-encoded).
	// Populated by HTTPRelyingParty; empty for TransportRelyingParty, which
	// does not return one.
	UserID string `json:"user_id,omitempty"`

	// CredentialID is the registered credential identifier (base64-encoded).
	CredentialID string `json:"credential_id,omitempty"`

	// JWT is a post-registration token if the server provides one.
	JWT string `json:"jwt,omitempty"`
}

// AuthenticationRequest contains parameters for WebAuthn authentication.
type AuthenticationRequest struct {
	// Username is the user's email or identifier (required for
	// non-discoverable flow).
	Username string `json:"username"`

	// AuthToken is an optional pre-authentication token. See
	// RegistrationRequest.AuthToken.
	AuthToken string `json:"auth_token,omitempty"`

	// PIN is the authenticator's CTAP2 PIN. See RegistrationRequest.PIN.
	PIN *secure.Secret `json:"-"`
}

// Validate checks the authentication request for required fields.
func (r *AuthenticationRequest) Validate() error {
	if r.Username == "" {
		return ErrUsernameRequired
	}
	return nil
}

// AuthenticationResult contains the result of a successful authentication.
type AuthenticationResult struct {
	// UserID is the authenticated user identifier: HTTPRelyingParty's
	// server-assigned base64 user ID, or TransportRelyingParty's resolved
	// username (its FinishAuthenticationResponse carries one, not the
	// other).
	UserID string `json:"user_id"`

	// JWT is the authentication token for API access.
	JWT string `json:"jwt"`
}

// CeremonyOptions carries one AuthenticatorAdapter call's inputs: the
// relying party's JSON options plus the two things those options cannot
// carry — the WebAuthn origin, which a browser takes from its security
// context, and the authenticator's CTAP2 PIN, which a browser prompts for.
//
// The fields are named rather than positional because Origin and a PIN's
// string form are easy to confuse: a positional signature carrying values
// this similar side by side would let a transposition send the PIN to the
// relying party as an origin.
type CeremonyOptions struct {
	// OptionsJSON is the JSON-encoded PublicKeyCredentialCreationOptions or
	// PublicKeyCredentialRequestOptions from the RelyingParty's begin call.
	OptionsJSON []byte

	// Origin is the WebAuthn origin to bind into clientDataJSON. It is
	// required, and the options' rpId must be its effective domain or a
	// registrable suffix of it (fido2.ValidateRPID).
	Origin string

	// PIN is the authenticator's CTAP2 PIN. Nil is correct for an
	// authenticator with no PIN configured.
	PIN *secure.Secret
}

// AuthenticatorAdapter bridges the WebAuthn client to a local authenticator.
// Two implementations ship in this package: SoftwareAdapter, a software-only
// CTAP2 authenticator for headless testing and CI, and HardwareAdapter, which
// drives a real CTAP2 authenticator over HID.
type AuthenticatorAdapter interface {
	// MakeCredential creates a new credential using the authenticator and
	// returns the JSON-encoded WebAuthn attestation response.
	MakeCredential(ctx context.Context, opts *CeremonyOptions) ([]byte, error)

	// GetAssertion gets an assertion using the authenticator and returns
	// the JSON-encoded WebAuthn assertion response.
	GetAssertion(ctx context.Context, opts *CeremonyOptions) ([]byte, error)

	// Available checks if the authenticator is available and ready.
	Available() bool
}

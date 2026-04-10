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
	"crypto/tls"
	"net/http"
	"time"
)

// Config configures the WebAuthn client.
type Config struct {
	// ServerURL is the base URL of the WebAuthn relying party server.
	// Example: "https://xkms.company.com:8443"
	ServerURL string

	// HTTPClient is the HTTP client to use for requests. If nil, a default
	// client with TLS configuration is created.
	HTTPClient *http.Client

	// TLSConfig is used when HTTPClient is nil to create the default client.
	TLSConfig *tls.Config

	// Timeout is the timeout for HTTP requests. Default: 30s.
	Timeout time.Duration

	// AuthenticatorAdapter bridges to the local CTAP2 authenticator.
	AuthenticatorAdapter AuthenticatorAdapter
}

// Validate checks the configuration for required fields.
func (c *Config) Validate() error {
	if c.ServerURL == "" {
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
	// request with the RP server.
	AuthToken string `json:"auth_token,omitempty"`
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
	UserID string `json:"user_id"`

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

	// AuthToken is an optional pre-authentication token.
	AuthToken string `json:"auth_token,omitempty"`
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
	// UserID is the authenticated user identifier (base64-encoded).
	UserID string `json:"user_id"`

	// JWT is the authentication token for API access.
	JWT string `json:"jwt"`
}

// AuthenticatorAdapter bridges the WebAuthn client to a local authenticator.
// Implementations can use IPC to communicate with xkey, wrap hardware
// tokens, or provide a software-only implementation for testing.
type AuthenticatorAdapter interface {
	// MakeCredential creates a new credential using the authenticator.
	// The options parameter contains the JSON-encoded PublicKeyCredentialCreationOptions
	// from the server's BeginRegistration response.
	// Returns the JSON-encoded attestation response.
	MakeCredential(options []byte) ([]byte, error)

	// GetAssertion gets an assertion using the authenticator.
	// The options parameter contains the JSON-encoded PublicKeyCredentialRequestOptions
	// from the server's BeginLogin response.
	// Returns the JSON-encoded assertion response.
	GetAssertion(options []byte) ([]byte, error)

	// Available checks if the authenticator is available and ready.
	Available() bool
}

// beginRegistrationRequest is the request body for the registration/begin endpoint.
type beginRegistrationRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
}

// beginLoginRequest is the request body for the login/begin endpoint.
type beginLoginRequest struct {
	Email string `json:"email,omitempty"`
}

// authResponse is the response from the server after successful registration or login.
type authResponse struct {
	Token  string `json:"token"`
	UserID string `json:"user_id"`
}

// errorResponse is the error response format from the server.
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

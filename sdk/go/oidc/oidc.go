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

// Package oidc re-exports the client side of go-xkms pkg/oidc: the provider
// templates, the authorization-code, device and import login flows, PKCE,
// DPoP, the loopback callback listener and the token stores. xkey and
// xkmsctl reach the OIDC core through this package, never through pkg/oidc
// directly (the architecture gates of CI's Preflight job enforce it).
//
// Every identifier is an alias of its pkg/oidc counterpart, so values cross
// freely between the two and errors.Is/errors.As see the same sentinels.
package oidc

import pkg "github.com/jeremyhahn/go-xkms/pkg/oidc"

// Provider templates.
type (
	// ProviderTemplate describes a known identity provider and the flows a
	// login for it can be obtained by.
	ProviderTemplate = pkg.ProviderTemplate
	// Flow names a way a login is obtained.
	Flow = pkg.Flow
)

const (
	// FlowAuthorizationCode is the browser authorization-code flow (PKCE).
	FlowAuthorizationCode = pkg.FlowAuthorizationCode
	// FlowDevice is the RFC 8628 device authorization flow.
	FlowDevice = pkg.FlowDevice
	// FlowImport imports a login obtained elsewhere.
	FlowImport = pkg.FlowImport
)

var (
	// BuiltinTemplates is the catalog of known provider templates, by name.
	BuiltinTemplates = pkg.BuiltinTemplates
	// ListTemplates returns the names of the built-in templates.
	ListTemplates = pkg.ListTemplates
	// GetTemplate returns the named built-in template.
	GetTemplate = pkg.GetTemplate
)

// Providers and clients.
type (
	// Provider is a discovered (or manually configured) OIDC provider.
	Provider = pkg.Provider
	// ProviderConfig configures a Provider and the Client built on it.
	ProviderConfig = pkg.ProviderConfig
	// Client runs the login flows and token refresh against a Provider.
	Client = pkg.Client
	// AuthCodeOptions tunes an authorization-code request.
	AuthCodeOptions = pkg.AuthCodeOptions
	// TokenResponse is a token endpoint response.
	TokenResponse = pkg.TokenResponse
	// TokenEncoding selects how a token request body is encoded.
	TokenEncoding = pkg.TokenEncoding
	// TokenRequestError reports a token endpoint error response.
	TokenRequestError = pkg.TokenRequestError
)

// TokenEncodingForm encodes a token request as
// application/x-www-form-urlencoded.
const TokenEncodingForm = pkg.TokenEncodingForm

var (
	// NewProvider discovers and builds a Provider from config.
	NewProvider = pkg.NewProvider
	// NewClient builds a Client over provider.
	NewClient = pkg.NewClient
	// EncodeTokenRequestBody encodes a token request body.
	EncodeTokenRequestBody = pkg.EncodeTokenRequestBody
	// SanitizeProviderText bounds and cleans provider-supplied text before
	// it is shown to a user.
	SanitizeProviderText = pkg.SanitizeProviderText
)

// PKCE, state and DPoP.
type (
	// DPoPKey is a DPoP proof-of-possession key.
	DPoPKey = pkg.DPoPKey
	// DPoPProofOptions tunes a DPoP proof.
	DPoPProofOptions = pkg.DPoPProofOptions
)

var (
	// GeneratePKCEParams returns a fresh PKCE verifier and challenge.
	GeneratePKCEParams = pkg.GeneratePKCEParams
	// GenerateCodeVerifier returns a fresh PKCE code verifier.
	GenerateCodeVerifier = pkg.GenerateCodeVerifier
	// GenerateCodeChallenge derives the S256 challenge for verifier.
	GenerateCodeChallenge = pkg.GenerateCodeChallenge
	// GenerateState returns a fresh OAuth state value.
	GenerateState = pkg.GenerateState
	// GenerateDPoPKey returns a fresh DPoP key.
	GenerateDPoPKey = pkg.GenerateDPoPKey
	// DeserializeDPoPKey parses a PEM-encoded DPoP key.
	DeserializeDPoPKey = pkg.DeserializeDPoPKey
)

// The loopback redirect listener.
type (
	// Callback is the result an authorization-code redirect delivers.
	Callback = pkg.Callback
	// CallbackPage is the page shown to the browser after a redirect.
	CallbackPage = pkg.CallbackPage
)

// AWSRedirectPath is the redirect path the AWS sign-in flow uses.
const AWSRedirectPath = pkg.AWSRedirectPath

var (
	// BindCallback binds the loopback callback listeners.
	BindCallback = pkg.BindCallback
	// ServeCallback serves server on listeners, reporting errors on errChan.
	ServeCallback = pkg.ServeCallback
	// ExactPathHandler serves handler only on exactly path.
	ExactPathHandler = pkg.ExactPathHandler
	// WriteCallbackPage writes page to w.
	WriteCallbackPage = pkg.WriteCallbackPage
)

// Token stores.

// TokenStore persists tokens by key.
type TokenStore = pkg.TokenStore

// DAOStore is a TokenStore of go-qrdb entities on an injected DAO factory.
type DAOStore = pkg.DAOStore

// DatabaseName is the go-qrdb database DAOStore's entities live in.
const DatabaseName = pkg.DatabaseName

// NewDAOStore returns a DAOStore on a DAO factory that serves DatabaseName.
var NewDAOStore = pkg.NewDAOStore

// Sentinel errors.
var (
	// ErrInvalidState reports a redirect whose state does not match.
	ErrInvalidState = pkg.ErrInvalidState
	// ErrInvalidCodeVerifier reports a malformed PKCE code verifier.
	ErrInvalidCodeVerifier = pkg.ErrInvalidCodeVerifier
	// ErrMissingRefreshToken reports a refresh with no refresh token.
	ErrMissingRefreshToken = pkg.ErrMissingRefreshToken
	// ErrTokenNotFound reports a token store miss.
	ErrTokenNotFound = pkg.ErrTokenNotFound
)

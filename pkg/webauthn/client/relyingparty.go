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

import "context"

// BeginResult carries a RelyingParty's answer to a begin call: the options
// to hand the authenticator, plus whatever correlation state the same
// RelyingParty needs back to finish the ceremony. The fields beyond
// OptionsJSON and SessionID are deliberately opaque to Client — each
// RelyingParty implementation reads only what its own wire protocol needs.
type BeginResult struct {
	// OptionsJSON is the JSON-encoded PublicKeyCredentialCreationOptions
	// (registration) or PublicKeyCredentialRequestOptions (authentication)
	// the RelyingParty returned.
	OptionsJSON []byte

	// SessionID is the opaque server-side session identifier that must be
	// echoed back to the matching finish call to correlate the ceremony.
	SessionID string
}

// RelyingParty is the server-side seam of a WebAuthn ceremony: it begins and
// finishes registration and authentication. Two implementations ship in
// this package: HTTPRelyingParty, which speaks the browser-shaped
// pkg/webauthn/http routes, and TransportRelyingParty, which speaks the SDK
// transport routes through a pkg/api/transport.Client (any protocol: REST,
// gRPC, QUIC, Unix, MCP).
type RelyingParty interface {
	// BeginRegistration starts a registration ceremony and returns the
	// creation options to hand the authenticator.
	BeginRegistration(ctx context.Context, req *RegistrationRequest) (*BeginResult, error)

	// FinishRegistration completes a registration ceremony with the
	// authenticator's attestation response.
	FinishRegistration(ctx context.Context, begin *BeginResult, req *RegistrationRequest, attestation []byte) (*RegistrationResult, error)

	// BeginAuthentication starts an authentication ceremony and returns the
	// request options to hand the authenticator.
	BeginAuthentication(ctx context.Context, req *AuthenticationRequest) (*BeginResult, error)

	// FinishAuthentication completes an authentication ceremony with the
	// authenticator's assertion response.
	FinishAuthentication(ctx context.Context, begin *BeginResult, req *AuthenticationRequest, assertion []byte) (*AuthenticationResult, error)
}

// AvailabilityChecker is an optional capability a RelyingParty implements to
// report server reachability. Client.Available consults it when present and
// otherwise assumes the relying party is reachable.
type AvailabilityChecker interface {
	// Available reports whether the relying party server can be reached.
	Available(ctx context.Context) bool
}

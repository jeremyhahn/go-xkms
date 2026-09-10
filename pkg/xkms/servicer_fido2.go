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

package xkms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	xkmswebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

// NewFIDO2Servicer wraps a WebAuthn relying-party service in the canonical
// FIDO2 transport-servicer adapter — the same ceremony adaptation the
// XKMSService singleton performs (options marshaling, attestation/assertion
// parsing, user resolution). It exists for downstream composers (e.g.
// go-quicbaas) that manage per-tenant *webauthn.Service instances and need
// the transport wire shape without initializing the XKMSService singleton.
func NewFIDO2Servicer(w *xkmswebauthn.Service) transport.FIDO2Servicer {
	s := &XKMSService{}
	s.SetWebAuthn(w)
	return s
}

// BeginRegistration begins a WebAuthn registration ceremony by delegating to
// the wired WebAuthn relying-party service. It mirrors the browser ceremony
// served by pkg/webauthn/http: the full registration options are returned as
// JSON together with an opaque session ID that FinishRegistration echoes back.
// Returns ErrNotConfigured until a WebAuthn subsystem is wired into the service.
// Implements the FIDO2Servicer interface.
func (s *XKMSService) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.webauthnService == nil {
		return nil, ErrNotConfigured
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Email
	}

	options, sessionID, err := s.webauthnService.BeginRegistration(ctx, req.Email, displayName)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "begin registration", Err: err}
	}

	optsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "marshal options", Err: err}
	}

	return &transport.BeginRegistrationResponse{
		SessionID:   sessionID,
		OptionsJSON: string(optsJSON),
	}, nil
}

// FinishRegistration completes a WebAuthn registration ceremony. It parses the
// authenticator attestation JSON, validates it against the session created in
// BeginRegistration, and persists the resulting credential via the WebAuthn
// service. The returned token is the relying party's post-registration token
// (JWT when configured, otherwise the base64 user ID).
// Returns ErrNotConfigured until a WebAuthn subsystem is wired into the service.
// Implements the FIDO2Servicer interface.
func (s *XKMSService) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.webauthnService == nil {
		return nil, ErrNotConfigured
	}

	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(req.AttestationJSON))
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "parse attestation", Err: err}
	}

	token, _, err := s.webauthnService.FinishRegistration(ctx, req.SessionID, parsed)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "finish registration", Err: err}
	}

	return &transport.FinishRegistrationResponse{
		Success:      true,
		CredentialID: base64.RawURLEncoding.EncodeToString(parsed.RawID),
		Token:        token,
	}, nil
}

// BeginAuthentication begins a WebAuthn authentication (login) ceremony by
// delegating to the wired WebAuthn relying-party service. It mirrors
// BeginRegistration: the username is resolved to the user's WebAuthn ID, the
// relying party produces the assertion options, and the full options are
// returned as JSON together with an opaque session ID that FinishAuthentication
// echoes back.
// Returns ErrNotConfigured until a WebAuthn subsystem is wired into the service.
// Implements the FIDO2Servicer interface.
func (s *XKMSService) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.webauthnService == nil {
		return nil, ErrNotConfigured
	}

	user, err := s.webauthnService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "resolve user", Err: err}
	}

	assertion, sessionID, err := s.webauthnService.BeginLogin(ctx, user.WebAuthnID())
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "begin authentication", Err: err}
	}

	optsJSON, err := json.Marshal(assertion)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "marshal options", Err: err}
	}

	return &transport.BeginAuthenticationResponse{
		SessionID:   sessionID,
		OptionsJSON: string(optsJSON),
	}, nil
}

// FinishAuthentication completes a WebAuthn authentication (login) ceremony. It
// parses the authenticator assertion JSON, validates it against the session
// created in BeginAuthentication, and returns the relying party's
// post-authentication token (JWT when configured, otherwise the base64 user ID).
// Returns ErrNotConfigured until a WebAuthn subsystem is wired into the service.
// Implements the FIDO2Servicer interface.
func (s *XKMSService) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if s.webauthnService == nil {
		return nil, ErrNotConfigured
	}

	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(req.AssertionJSON))
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "parse assertion", Err: err}
	}

	user, err := s.webauthnService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "resolve user", Err: err}
	}

	token, loggedIn, err := s.webauthnService.FinishLogin(ctx, req.SessionID, user.WebAuthnID(), parsed)
	if err != nil {
		return nil, &ErrWebAuthnCeremony{Operation: "finish authentication", Err: err}
	}

	return &transport.FinishAuthenticationResponse{
		Success:  true,
		Token:    token,
		Username: loggedIn.WebAuthnName(),
	}, nil
}

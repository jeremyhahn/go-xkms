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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TransportClient is the subset of pkg/api/transport.Client — the SDK
// transport, in any of its protocol bindings (REST, gRPC, QUIC, Unix, MCP)
// — that a WebAuthn ceremony needs: the four SDK ceremony RPCs served at
// /api/v1/webauthn/sdk/.... A pkg/api/transport.Client value, including
// sdk/go's exported Client alias, satisfies it directly with no adapter.
type TransportClient interface {
	// BeginRegistration begins a WebAuthn registration flow.
	BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error)

	// FinishRegistration completes a WebAuthn registration flow.
	FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error)

	// BeginAuthentication begins a WebAuthn authentication flow.
	BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error)

	// FinishAuthentication completes a WebAuthn authentication flow.
	FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error)
}

// TransportRelyingParty is the SDK-transport RelyingParty implementation: it
// drives the ceremony over an already-connected pkg/api/transport.Client
// (sdk/go's Client), whichever protocol it was constructed with. It is what
// xkey and xkmsctl use: both connect over the SDK transport first, so the
// auth token and TLS live on the transport connection rather than being
// carried per WebAuthn request, unlike HTTPRelyingParty's AuthToken header.
type TransportRelyingParty struct {
	client TransportClient
}

var _ RelyingParty = (*TransportRelyingParty)(nil)

// NewTransportRelyingParty constructs a RelyingParty over an
// already-connected SDK transport client.
func NewTransportRelyingParty(client TransportClient) (*TransportRelyingParty, error) {
	if client == nil {
		return nil, ErrNilTransportClient
	}
	return &TransportRelyingParty{client: client}, nil
}

// BeginRegistration begins the ceremony over BeginRegistration.
func (rp *TransportRelyingParty) BeginRegistration(ctx context.Context, req *RegistrationRequest) (*BeginResult, error) {
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}

	resp, err := rp.client.BeginRegistration(ctx, &transport.BeginRegistrationRequest{
		Email:       req.Username,
		DisplayName: displayName,
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrServerUnavailable, Cause: err}
	}

	return &BeginResult{
		OptionsJSON: []byte(resp.OptionsJSON),
		SessionID:   resp.SessionID,
	}, nil
}

// FinishRegistration completes the ceremony over FinishRegistration.
func (rp *TransportRelyingParty) FinishRegistration(ctx context.Context, begin *BeginResult, req *RegistrationRequest, attestation []byte) (*RegistrationResult, error) {
	resp, err := rp.client.FinishRegistration(ctx, &transport.FinishRegistrationRequest{
		SessionID:       begin.SessionID,
		AttestationJSON: string(attestation),
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrRegistrationFailed, Cause: err}
	}
	if !resp.Success {
		return nil, &RelyingPartyRejection{Err: ErrRegistrationFailed, Message: resp.Message}
	}

	return &RegistrationResult{
		CredentialID: resp.CredentialID,
		JWT:          resp.Token,
	}, nil
}

// BeginAuthentication begins the ceremony over BeginAuthentication.
func (rp *TransportRelyingParty) BeginAuthentication(ctx context.Context, req *AuthenticationRequest) (*BeginResult, error) {
	resp, err := rp.client.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{
		Email: req.Username,
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrServerUnavailable, Cause: err}
	}

	return &BeginResult{
		OptionsJSON: []byte(resp.OptionsJSON),
		SessionID:   resp.SessionID,
	}, nil
}

// FinishAuthentication completes the ceremony over FinishAuthentication.
func (rp *TransportRelyingParty) FinishAuthentication(ctx context.Context, begin *BeginResult, req *AuthenticationRequest, assertion []byte) (*AuthenticationResult, error) {
	resp, err := rp.client.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{
		SessionID:     begin.SessionID,
		Email:         req.Username,
		AssertionJSON: string(assertion),
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrAuthenticationFailed, Cause: err}
	}
	if !resp.Success {
		return nil, &RelyingPartyRejection{Err: ErrAuthenticationFailed, Message: resp.Message}
	}

	return &AuthenticationResult{
		UserID: resp.Username,
		JWT:    resp.Token,
	}, nil
}

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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// BeginRegistration begins a WebAuthn registration ceremony.
// Returns ErrNotConfigured until a WebAuthn subsystem is wired into the service.
// Implements the FIDO2Servicer interface.
func (s *XKMSService) BeginRegistration(ctx context.Context, req *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return nil, ErrNotConfigured
}

// FinishRegistration completes a WebAuthn registration ceremony.
// Returns ErrNotConfigured until a WebAuthn subsystem is wired into the service.
// Implements the FIDO2Servicer interface.
func (s *XKMSService) FinishRegistration(ctx context.Context, req *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return nil, ErrNotConfigured
}

// BeginAuthentication begins a WebAuthn authentication ceremony.
// Returns ErrNotConfigured until a WebAuthn subsystem is wired into the service.
// Implements the FIDO2Servicer interface.
func (s *XKMSService) BeginAuthentication(ctx context.Context, req *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return nil, ErrNotConfigured
}

// FinishAuthentication completes a WebAuthn authentication ceremony.
// Returns ErrNotConfigured until a WebAuthn subsystem is wired into the service.
// Implements the FIDO2Servicer interface.
func (s *XKMSService) FinishAuthentication(ctx context.Context, req *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return nil, ErrNotConfigured
}

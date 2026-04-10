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

// GetInitStatus returns the current init ceremony state.
// Returns ErrNotConfigured if the ceremony service is not wired.
func (s *XKMSService) GetInitStatus(ctx context.Context) (*transport.InitStatusResponse, error) {
	cs, err := s.getCeremonyServicer()
	if err != nil {
		return nil, err
	}
	return cs.GetInitStatus(ctx)
}

// ClaimCertBegin begins the certificate claim process for an officer.
// Returns ErrNotConfigured if the ceremony service is not wired.
func (s *XKMSService) ClaimCertBegin(ctx context.Context, req *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	cs, err := s.getCeremonyServicer()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return cs.ClaimCertBegin(ctx, req)
}

// ClaimCertComplete completes the certificate claim by verifying the officer's
// signature over the challenge nonce.
// Returns ErrNotConfigured if the ceremony service is not wired.
func (s *XKMSService) ClaimCertComplete(ctx context.Context, req *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	cs, err := s.getCeremonyServicer()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return cs.ClaimCertComplete(ctx, req)
}

// ClaimShare retrieves the Shamir share for the named officer.
// Returns ErrNotConfigured if the ceremony service is not wired.
func (s *XKMSService) ClaimShare(ctx context.Context, req *transport.ClaimShareRequest) (*transport.ClaimShareResponse, error) {
	cs, err := s.getCeremonyServicer()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return cs.ClaimShare(ctx, req)
}

// SignCSRInit signs a CSR during initialization with SO authorization (dual auth).
// Returns ErrNotConfigured if the ceremony service is not wired.
func (s *XKMSService) SignCSRInit(ctx context.Context, req *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	cs, err := s.getCeremonyServicer()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return cs.SignCSRInit(ctx, req)
}

// getCeremonyServicer type-asserts the stored ceremony service to the
// transport.InitCeremonyService interface. The ceremony service is stored
// as any to break the import cycle (xkms → init → ca → xkms).
// Returns ErrNotConfigured if nil or wrong type.
func (s *XKMSService) getCeremonyServicer() (transport.InitCeremonyService, error) {
	if s.ceremonyService == nil {
		return nil, ErrNotConfigured
	}
	cs, ok := s.ceremonyService.(transport.InitCeremonyService)
	if !ok {
		return nil, ErrNotConfigured
	}
	return cs, nil
}

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

package xkms

import (
	"context"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// UserAuthFactorServicer defines the user-side N-factor operations xkms
// presents on its own API.
//
// Factor state belongs to qrdb — xkms stores none of it and adds no rules of
// its own. The surface exists here so an operator, the CLI, and the console
// all reach identity through the same endpoint they already use for keys,
// rather than needing a second connection to the qrdb node directly.
//
// Hardware verification (FIDO2 / PIV / mTLS) is the caller's job; these
// operations only resolve and persist the (Type, LookupKey) mapping.
type UserAuthFactorServicer interface {
	AddAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error)
	ListAuthFactors(ctx context.Context, req *qrdbtransport.AuthFactorListRequest) (*qrdbtransport.AuthFactorListResponse, error)
	GetAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorGetRequest) (*qrdbtransport.AuthFactorGetResponse, error)
	RemoveAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error)
	RotateAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error)
	RelabelAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRelabelRequest) (*qrdbtransport.AuthFactorRelabelResponse, error)
	LoginAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorLoginRequest) (*qrdbtransport.AuthFactorLoginResponse, error)
}

// AddAuthFactor persists a new factor for a user.
func (s *XKMSService) AddAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorAddRequest) (*qrdbtransport.AuthFactorAddResponse, error) {
	if s.userAuthFactors == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.userAuthFactors.AddAuthFactor(ctx, req)
}

// ListAuthFactors returns every factor, active and revoked, owned by a user.
func (s *XKMSService) ListAuthFactors(ctx context.Context, req *qrdbtransport.AuthFactorListRequest) (*qrdbtransport.AuthFactorListResponse, error) {
	if s.userAuthFactors == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.userAuthFactors.ListAuthFactors(ctx, req)
}

// GetAuthFactor returns a single factor by ID.
func (s *XKMSService) GetAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorGetRequest) (*qrdbtransport.AuthFactorGetResponse, error) {
	if s.userAuthFactors == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.userAuthFactors.GetAuthFactor(ctx, req)
}

// RemoveAuthFactor soft-deletes a factor. The last-active-factor guard lives
// in qrdb, which is why the force flag is passed through untouched rather
// than being second-guessed here.
func (s *XKMSService) RemoveAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRemoveRequest) (*qrdbtransport.AuthFactorRemoveResponse, error) {
	if s.userAuthFactors == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.userAuthFactors.RemoveAuthFactor(ctx, req)
}

// RotateAuthFactor atomically adds a replacement factor and revokes the old
// one.
func (s *XKMSService) RotateAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRotateRequest) (*qrdbtransport.AuthFactorRotateResponse, error) {
	if s.userAuthFactors == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.userAuthFactors.RotateAuthFactor(ctx, req)
}

// RelabelAuthFactor updates a factor's display label.
func (s *XKMSService) RelabelAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorRelabelRequest) (*qrdbtransport.AuthFactorRelabelResponse, error) {
	if s.userAuthFactors == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.userAuthFactors.RelabelAuthFactor(ctx, req)
}

// LoginAuthFactor resolves an inbound (Type, LookupKey) pair to a principal.
//
// This performs the database mapping only. The hardware proof — a FIDO2
// assertion, a PIV signature, an mTLS handshake — must already have been
// verified by the caller: reaching this call is not evidence that it was.
func (s *XKMSService) LoginAuthFactor(ctx context.Context, req *qrdbtransport.AuthFactorLoginRequest) (*qrdbtransport.AuthFactorLoginResponse, error) {
	if s.userAuthFactors == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.userAuthFactors.LoginAuthFactor(ctx, req)
}

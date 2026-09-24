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

package mcp

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
)

// ErrXKMSServiceUnavailable is returned when the xkms service is not available.
var ErrXKMSServiceUnavailable = errors.New("xkms service unavailable")

// ErrClientCertRequired is returned when a share-claim method is invoked over
// a session that carries no verified mTLS peer certificate. The officer's
// certificate thumbprint is the authentication for these methods.
var ErrClientCertRequired = errors.New("client certificate required")

// handleGetInitStatus handles the init.getStatus method.
func (s *Server) handleGetInitStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, ErrXKMSServiceUnavailable
	}
	return svc.GetInitStatus(ctx)
}

// handleClaimCertBegin handles the init.claimCertBegin method.
func (s *Server) handleClaimCertBegin(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.ClaimCertBeginRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	return svc.ClaimCertBegin(ctx, &params)
}

// handleClaimCertComplete handles the init.claimCertComplete method.
func (s *Server) handleClaimCertComplete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.ClaimCertCompleteRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	return svc.ClaimCertComplete(ctx, &params)
}

// callerCertThumbprint derives the caller's certificate thumbprint from the
// verified mTLS peer chain carried on the connection context by the MCP
// server's handshake path. It fails closed with ErrClientCertRequired when the
// session carries no peer certificate, so the share-claim methods never fall
// back to trusting a username.
//
// The value is computed with initialize.CertThumbprint, the single canonical
// binding identifier the ceremony records for each officer at enrollment.
func callerCertThumbprint(ctx context.Context) (string, error) {
	state := auth.TLSStateFromContext(ctx)
	if state == nil || len(state.PeerCertificates) == 0 {
		return "", ErrClientCertRequired
	}
	return initialize.CertThumbprint(state.PeerCertificates[0].Raw), nil
}

// handleClaimShareBegin handles the init.claimShareBegin method. The officer
// has no account yet; the certificate claim-cert issued them is their
// credential, and its thumbprint is the authentication here.
func (s *Server) handleClaimShareBegin(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, ErrXKMSServiceUnavailable
	}

	thumbprint, err := callerCertThumbprint(ctx)
	if err != nil {
		return nil, err
	}

	var params transport.ClaimShareBeginRequest
	if decErr := decodeParams(req, &params); decErr != nil {
		return nil, decErr
	}
	// Never from the wire: overwrite whatever decoding produced.
	params.CallerCertThumbprint = thumbprint

	return svc.ClaimShareBegin(ctx, &params)
}

// handleClaimShareComplete handles the init.claimShareComplete method,
// releasing the share exactly once after both the nonce signature and the
// caller certificate thumbprint verify.
func (s *Server) handleClaimShareComplete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, ErrXKMSServiceUnavailable
	}

	thumbprint, err := callerCertThumbprint(ctx)
	if err != nil {
		return nil, err
	}

	var params transport.ClaimShareCompleteRequest
	if decErr := decodeParams(req, &params); decErr != nil {
		return nil, decErr
	}
	params.CallerCertThumbprint = thumbprint

	return svc.ClaimShareComplete(ctx, &params)
}

// handleSignCSRInit handles the init.signCSR method.
func (s *Server) handleSignCSRInit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.SignCSRInitRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	return svc.SignCSRInit(ctx, &params)
}

// handleCredentialSubmit handles the credentials.submit method.
func (s *Server) handleCredentialSubmit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.CredentialSubmitRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	return svc.SubmitCredential(ctx, &params)
}

// handleCredentialStrategy handles the credentials.strategy method.
func (s *Server) handleCredentialStrategy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc := s.xkmsService
	if svc == nil {
		return nil, ErrXKMSServiceUnavailable
	}

	return svc.GetCredentialStrategy(ctx)
}

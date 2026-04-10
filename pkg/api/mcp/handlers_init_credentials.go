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
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ErrXKMSServiceUnavailable is returned when the xkms service singleton
// cannot be retrieved.
var ErrXKMSServiceUnavailable = errors.New("xkms service unavailable")

// handleGetInitStatus handles the init.getStatus method.
func (s *Server) handleGetInitStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}
	return svc.GetInitStatus(ctx)
}

// handleClaimCertBegin handles the init.claimCertBegin method.
func (s *Server) handleClaimCertBegin(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.ClaimCertBeginRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.ClaimCertBegin(ctx, &params)
}

// handleClaimCertComplete handles the init.claimCertComplete method.
func (s *Server) handleClaimCertComplete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.ClaimCertCompleteRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.ClaimCertComplete(ctx, &params)
}

// handleClaimShare handles the init.claimShare method.
func (s *Server) handleClaimShare(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.ClaimShareRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.ClaimShare(ctx, &params)
}

// handleSignCSRInit handles the init.signCSR method.
func (s *Server) handleSignCSRInit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.SignCSRInitRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.SignCSRInit(ctx, &params)
}

// handleCredentialSubmit handles the credentials.submit method.
func (s *Server) handleCredentialSubmit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	var params transport.CredentialSubmitRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, err
	}

	return svc.SubmitCredential(ctx, &params)
}

// handleCredentialStrategy handles the credentials.strategy method.
func (s *Server) handleCredentialStrategy(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	svc, err := xkms.Get()
	if err != nil {
		return nil, ErrXKMSServiceUnavailable
	}

	return svc.GetCredentialStrategy(ctx)
}

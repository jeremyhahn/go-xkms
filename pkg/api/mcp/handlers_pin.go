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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// pinSuccess is the uniform success envelope for a PIN mutation. It carries
// no return value beyond confirmation, matching the REST and gRPC PIN
// surfaces (SetSOPINHandler et al. return only a success message; gRPC
// returns emptypb.Empty).
var pinSuccess = map[string]interface{}{"success": true}

// handleSetSOPIN handles the xkms.setSOPIN method: sets the Security Officer
// PIN. Delegates entirely to the xkms service layer (XKMSService.SetSOPIN),
// which forwards to the composed qrdbsdk.PINBackend; the go-qrdb node's PIN
// domain errors (ErrPINAlreadySet, ErrPINTooShort, ...) propagate through
// mapPINError unchanged.
func (s *Server) handleSetSOPIN(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.SetSOPINRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.SetSOPIN(ctx, &params); err != nil {
		return nil, mapPINError(err, "set SO PIN")
	}

	return pinSuccess, nil
}

// handleSetUserPIN handles the xkms.setUserPIN method: sets the user PIN,
// authorized by the Security Officer PIN carried in the request.
func (s *Server) handleSetUserPIN(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.SetUserPINRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.SetUserPIN(ctx, &params); err != nil {
		return nil, mapPINError(err, "set user PIN")
	}

	return pinSuccess, nil
}

// handleChangeSOPIN handles the xkms.changeSOPIN method: changes the
// Security Officer PIN from its current value to a new one.
func (s *Server) handleChangeSOPIN(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.ChangeSOPINRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.ChangeSOPIN(ctx, &params); err != nil {
		return nil, mapPINError(err, "change SO PIN")
	}

	return pinSuccess, nil
}

// handleChangeUserPIN handles the xkms.changeUserPIN method: changes the
// user PIN from its current value to a new one.
func (s *Server) handleChangeUserPIN(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.ChangeUserPINRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.ChangeUserPIN(ctx, &params); err != nil {
		return nil, mapPINError(err, "change user PIN")
	}

	return pinSuccess, nil
}

// handleVerifySOPIN handles the xkms.verifySOPIN method: verifies a
// caller-supplied Security Officer PIN without changing it.
func (s *Server) handleVerifySOPIN(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.VerifySOPINRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.VerifySOPIN(ctx, &params); err != nil {
		return nil, mapPINError(err, "verify SO PIN")
	}

	return pinSuccess, nil
}

// handleVerifyUserPIN handles the xkms.verifyUserPIN method: verifies a
// caller-supplied user PIN without changing it.
func (s *Server) handleVerifyUserPIN(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.VerifyUserPINRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.VerifyUserPIN(ctx, &params); err != nil {
		return nil, mapPINError(err, "verify user PIN")
	}

	return pinSuccess, nil
}

// handleGetLockoutStatus handles the xkms.getLockoutStatus method: reports
// the current PIN lockout counters. Takes no params.
func (s *Server) handleGetLockoutStatus(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	resp, err := s.xkmsService.GetLockoutStatus(ctx)
	if err != nil {
		return nil, mapPINError(err, "get lockout status")
	}

	return resp, nil
}

// handleResetLockout handles the xkms.resetLockout method: resets the PIN
// lockout counter, authorized by the Security Officer PIN carried in the
// request.
func (s *Server) handleResetLockout(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.ResetLockoutRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if err := s.xkmsService.ResetLockout(ctx, &params); err != nil {
		return nil, mapPINError(err, "reset lockout")
	}

	return pinSuccess, nil
}

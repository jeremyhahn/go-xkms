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
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Invitation redemption (go-xkms#1294 part B): how an account CreateUser
// provisioned with zero credentials enrolls its first one.
//
// Only invite.get and invite.pivActivate are exposed here. The FIDO2 half
// (BeginInviteRegistration/FinishInviteRegistration) is NOT: it is a
// Begin/Finish WebAuthn ceremony, the exact shape go-xkms#193 already
// excluded from this transport (BeginRegistration/FinishRegistration in
// transport.go) because MCP holds no identity-ceremony state to correlate a
// Begin call with its matching Finish call, and an agent-facing tool-call
// surface must not mint sessions or enrol credentials. ActivateInvitePIV has
// no such problem — it verifies a presented certificate and activates the
// account in one call, with no ceremony state to correlate — so it is
// exposed like any other single-call method.

// mapInviteError classifies an XKMSService invite-redemption error into the
// JSON-RPC code every transport-agreed case gets. xkms.ErrInviteUnusable is
// the one opaque answer every unusable token gets (absent, expired, already
// redeemed, malformed) — mapped to the same not-found code REST's 404 and
// gRPC's NotFound carry, and Classified so its text reaches the caller
// (that text IS the opaque answer, not detail to withhold). A PIV
// certificate error carries its own detail, since it describes the
// caller's own input, not a probeable secret.
func mapInviteError(err error) error {
	if err == nil {
		return nil
	}
	var certDecode *xkms.ErrPIVCertDecode
	var certRejected *xkms.ErrPIVCertRejected
	switch {
	case errors.Is(err, xkms.ErrInviteUnusable):
		return &KeyOpError{Code: sdkssh.JSONRPCCodeNotFound, Err: err, Classified: true}
	case errors.As(err, &certDecode), errors.As(err, &certRejected):
		return &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	case errors.Is(err, xkms.ErrNotConfigured):
		return &KeyOpError{Code: ErrCodeInternalError, Err: err, Classified: true}
	default:
		return &KeyOpError{Code: ErrCodeInternalError, Err: err}
	}
}

// handleGetInvite handles the invite.get method: resolving a still-usable
// invitation's metadata without consuming it.
func (s *Server) handleGetInvite(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.GetInviteRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.GetInvite(ctx, &params)
	if err != nil {
		return nil, mapInviteError(err)
	}
	return resp, nil
}

// handleActivateInvitePIV handles the invite.pivActivate method: activating
// the account by verifying a presented PIV certificate.
func (s *Server) handleActivateInvitePIV(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.ActivateInvitePIVRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.ActivateInvitePIV(ctx, &params)
	if err != nil {
		return nil, mapInviteError(err)
	}
	return resp, nil
}

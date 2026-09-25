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
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// auditOperationError wraps an error from QueryAudit as a *KeyOpError
// carrying ErrCodeInternalError, mirroring pkg/api/grpc/service_audit.go's
// QueryAudit, which reports codes.Internal for any failure of the call
// unconditionally (its own "not configured" and "nil request" guards run
// before the call and are handled separately, exactly as this handler's own
// nil-check and decodeParams run before this wrapper is ever reached).
func auditOperationError(msg string, err error) error {
	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: msg, Err: err}}
}

// handleQueryAudit handles the xkms.queryAudit method. Audit state lives in
// the embedded go-qrdb node, reached through the XKMS service.
func (s *Server) handleQueryAudit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.AuditFilter
	if len(req.Params) > 0 {
		if err := decodeParams(req, &params); err != nil {
			return nil, err
		}
	}

	page, err := s.xkmsService.QueryAudit(ctx, &params)
	if err != nil {
		return nil, auditOperationError("failed to query audit", err)
	}

	return page, nil
}

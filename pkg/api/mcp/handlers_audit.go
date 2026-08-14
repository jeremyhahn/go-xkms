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
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// handleQueryAudit handles the xkms.queryAudit method. Audit state lives in
// the embedded go-qrdb node, reached through the XKMS service.
func (s *Server) handleQueryAudit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.AuditFilter
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, &errs.Wrapped{Msg: "invalid params", Err: err}
		}
	}

	page, err := s.xkmsService.QueryAudit(ctx, &params)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to query audit", Err: err}
	}

	return page, nil
}

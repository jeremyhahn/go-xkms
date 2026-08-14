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

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// handleAlgorithms handles the xkms.algorithms method. Like the REST route it
// mirrors, this is public discovery: the inventory is derived from the
// compiled-in backend registry and reads no state.
func (s *Server) handleAlgorithms(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	resp, err := s.xkmsService.Algorithms(ctx)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to discover algorithms", Err: err}
	}
	return resp, nil
}

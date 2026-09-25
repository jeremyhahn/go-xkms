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
)

// handleAlgorithms handles the xkms.algorithms method. Like the REST route it
// mirrors, this is public discovery: the inventory is derived from the
// compiled-in backend registry and reads no state. XKMSService.Algorithms
// never actually returns a non-nil error today, but the error is still
// routed through mapKeyOpError -- matching pkg/api/grpc/service.go's
// Algorithms, which does the same through its own mapKeyOpError -- rather
// than a bare wrap, so this handler stays correct if that ever changes.
func (s *Server) handleAlgorithms(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	resp, err := s.xkmsService.Algorithms(ctx)
	if err != nil {
		return nil, mapKeyOpError(err)
	}
	return resp, nil
}

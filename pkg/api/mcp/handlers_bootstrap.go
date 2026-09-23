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

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// handleBootstrapShowKeys handles the bootstrap.showKeys method. It reports
// the running trust-bootstrap listener's public static keys (go-xkms#632).
// Only public material is ever returned.
func (s *Server) handleBootstrapShowKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, xkms.ErrBootstrapListenerNotEnabled
	}
	return s.xkmsService.BootstrapListenerKeys(ctx)
}

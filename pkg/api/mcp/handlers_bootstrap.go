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
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// mapBootstrapError translates a trust-bootstrap listener error into the
// JSON-RPC code a caller can act on, mirroring
// pkg/api/grpc/service_bootstrap.go's mapBootstrapError:
// xkms.ErrBootstrapListenerNotEnabled is Service unavailable (gRPC's
// codes.Unavailable), matching this transport's own floor for an unwired
// subsystem elsewhere (errors_cert.go's mapCAError, handlers_share.go's
// mapShareError); anything else is an internal fault (gRPC's
// codes.Internal).
func mapBootstrapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, xkms.ErrBootstrapListenerNotEnabled) {
		return &KeyOpError{Code: ErrCodeServiceUnavailable, Err: err}
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// handleBootstrapShowKeys handles the bootstrap.showKeys method. It reports
// the running trust-bootstrap listener's public static keys (go-xkms#632).
// Only public material is ever returned.
func (s *Server) handleBootstrapShowKeys(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapBootstrapError(xkms.ErrBootstrapListenerNotEnabled)
	}
	resp, err := s.xkmsService.BootstrapListenerKeys(ctx)
	if err != nil {
		return nil, mapBootstrapError(err)
	}
	return resp, nil
}

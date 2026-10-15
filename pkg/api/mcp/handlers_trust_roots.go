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

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The trust.root.* handlers are the MCP server side of the platform
// trust-root store. They gate on the trust_roots resource (authz.go),
// matching the gRPC/REST/Unix TrustRoot* handlers.

// mapTrustRootError converts a trust-root store error into a *KeyOpError,
// classifying it through apierrors.TrustRootSentinelClasses, the table the
// gRPC server shares. Anything not in that table is an internal fault.
func mapTrustRootError(err error, _ string) error {
	if class, ok := apierrors.ClassOf(apierrors.TrustRootSentinelClasses, err); ok {
		return classified(jsonRPCCodeForClass(class), err)
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// trustRootCall decodes the request params, runs call and maps its error.
func trustRootCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	return servicerCall(s, ctx, req, op, mapTrustRootError, call)
}

// handleTrustRootList handles trust.root.list.
func (s *Server) handleTrustRootList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return trustRootCall(s, ctx, req, "trust root list", s.xkmsService.TrustRootList)
}

// handleTrustRootGet handles trust.root.get.
func (s *Server) handleTrustRootGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return trustRootCall(s, ctx, req, "trust root get", s.xkmsService.TrustRootGet)
}

// handleTrustRootImport handles trust.root.import.
func (s *Server) handleTrustRootImport(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return trustRootCall(s, ctx, req, "trust root import", s.xkmsService.TrustRootImport)
}

// handleTrustRootQuarantine handles trust.root.quarantine.
func (s *Server) handleTrustRootQuarantine(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return trustRootCall(s, ctx, req, "trust root quarantine", s.xkmsService.TrustRootQuarantine)
}

// handleTrustRootRemove handles trust.root.remove, answering with the
// removed fingerprint.
func (s *Server) handleTrustRootRemove(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return trustRootCall(s, ctx, req, "trust root remove", func(ctx context.Context, params *transport.TrustRootRequest) (map[string]string, error) {
		if err := s.xkmsService.TrustRootRemove(ctx, params); err != nil {
			return nil, err
		}
		return map[string]string{"fingerprint": params.Fingerprint}, nil
	})
}

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
)

// The xkms.ca.transparency-log.* handlers are the MCP server side of the CA
// transparency log's read verbs (docs/transparency-log). They gate on the
// vlog resource (server.go), matching the gRPC/REST/Unix handlers.

// mapTransparencyLogError converts a transparency-log read error into a
// *KeyOpError, classifying it through apierrors.TransparencyLogSentinelClasses,
// the table every transport shares. Anything not in that table is an internal
// fault.
func mapTransparencyLogError(err error, _ string) error {
	if class, ok := apierrors.ClassOf(apierrors.TransparencyLogSentinelClasses, err); ok {
		return classified(jsonRPCCodeForClass(class), err)
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// transparencyLogCall decodes the request params, runs call and maps its error.
func transparencyLogCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	return servicerCall(s, ctx, req, op, mapTransparencyLogError, call)
}

// handleTransparencyLogHead handles xkms.ca.transparency-log.head.
func (s *Server) handleTransparencyLogHead(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return transparencyLogCall(s, ctx, req, "transparency log head", s.xkmsService.GetTransparencyLogHead)
}

// handleTransparencyLogEntry handles xkms.ca.transparency-log.entry.
func (s *Server) handleTransparencyLogEntry(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return transparencyLogCall(s, ctx, req, "transparency log entry", s.xkmsService.GetTransparencyLogEntry)
}

// handleTransparencyLogInclusionProof handles
// xkms.ca.transparency-log.inclusion-proof.
func (s *Server) handleTransparencyLogInclusionProof(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return transparencyLogCall(s, ctx, req, "transparency log inclusion proof", s.xkmsService.GetTransparencyLogInclusionProof)
}

// handleTransparencyLogConsistencyProof handles
// xkms.ca.transparency-log.consistency-proof.
func (s *Server) handleTransparencyLogConsistencyProof(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return transparencyLogCall(s, ctx, req, "transparency log consistency proof", s.xkmsService.GetTransparencyLogConsistencyProof)
}

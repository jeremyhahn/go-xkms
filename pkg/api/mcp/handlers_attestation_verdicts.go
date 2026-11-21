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

// The attestation.verdict.* handlers are the MCP server side of the
// continuous attestation verdict verbs (go-xkms#2088). Each decodes a
// transport.AttestationVerdictRequest and delegates to XKMSService, which
// binds the call to the caller's tenant; they gate on the
// attestation_verdicts:* pairs in server.go's rpcMethods table.

// verdictCall decodes a P from req and runs call with it, mapping its error
// through the verdict classification.
func verdictCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	return servicerCall(s, ctx, req, op, mapVerdictError, call)
}

// mapVerdictError converts a verdict error into a *KeyOpError through
// apierrors.VerdictClassOf.
func mapVerdictError(err error, operation string) error {
	return mapClassifiedError(err, operation, apierrors.VerdictClassOf)
}

// handleVerdictList handles attestation.verdict.list.
func (s *Server) handleVerdictList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return verdictCall(s, ctx, req, "verdict list", s.xkmsService.ListAttestationVerdicts)
}

// handleVerdictLatest handles attestation.verdict.latest.
func (s *Server) handleVerdictLatest(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return verdictCall(s, ctx, req, "verdict latest", s.xkmsService.GetLatestAttestationVerdict)
}

// handleVerdictReattest handles attestation.verdict.reattest.
func (s *Server) handleVerdictReattest(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return verdictCall(s, ctx, req, "verdict reattest", s.xkmsService.ReattestDevice)
}

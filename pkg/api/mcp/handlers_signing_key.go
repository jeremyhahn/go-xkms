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

// The attestation.signing_key.* handlers are the MCP server side of the
// repository signing-key API (go-xkms#1697). Each decodes its parameters --
// the fields of the transport request -- and delegates to XKMSService, which
// binds the call to the caller's tenant; they gate on the
// attestation_signing_keys:* pairs in server.go's rpcMethods table.

// signingKeyCall decodes a P from req and runs call with it, mapping its
// error through the signing-key classification.
func signingKeyCall[P, R any](s *Server, ctx context.Context, req *JSONRPCRequest, op string, call func(context.Context, *P) (R, error)) (interface{}, error) {
	return servicerCall(s, ctx, req, op, mapSigningKeyError, call)
}

// mapSigningKeyError converts a signing-key API error into a *KeyOpError
// through apierrors.SigningKeyClassOf.
func mapSigningKeyError(err error, operation string) error {
	return mapClassifiedError(err, operation, apierrors.SigningKeyClassOf)
}

// handleSigningKeySet handles attestation.signing_key.set.
func (s *Server) handleSigningKeySet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return signingKeyCall(s, ctx, req, "signing key set", s.xkmsService.SetSigningKeyBinding)
}

// handleSigningKeyGet handles attestation.signing_key.get.
func (s *Server) handleSigningKeyGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return signingKeyCall(s, ctx, req, "signing key get", s.xkmsService.GetSigningKeyBinding)
}

// handleSigningKeyList handles attestation.signing_key.list, which takes no
// parameters.
func (s *Server) handleSigningKeyList(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return signingKeyCall(s, ctx, req, "signing key list", func(ctx context.Context, _ *struct{}) (*transport.ListSigningKeyBindingsResponse, error) {
		return s.xkmsService.ListSigningKeyBindings(ctx)
	})
}

// handleSigningKeyDelete handles attestation.signing_key.delete, answering
// with the request it removed.
func (s *Server) handleSigningKeyDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return signingKeyCall(s, ctx, req, "signing key delete", func(ctx context.Context, params *transport.DeleteSigningKeyBindingRequest) (*transport.DeleteSigningKeyBindingRequest, error) {
		if err := s.xkmsService.DeleteSigningKeyBinding(ctx, params); err != nil {
			return nil, err
		}
		return params, nil
	})
}

// handleSigningKeyResolve handles attestation.signing_key.resolve.
func (s *Server) handleSigningKeyResolve(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	return signingKeyCall(s, ctx, req, "signing key resolve", s.xkmsService.ResolveSigningKey)
}

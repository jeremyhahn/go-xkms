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
	"errors"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Authorization sentinels for the MCP JSON-RPC surface.
var (
	// ErrAuthorizerRequired is returned by NewServer when Config.EnableRBAC is
	// true but no usable Authorizer was supplied. The constructor refuses to
	// start a server that believes it enforces RBAC while every method would
	// in fact be allowed: enabling RBAC without a qrdb-backed authorizer is a
	// wiring bug, not a permissive deployment mode. Deployments that really
	// want an open gate leave EnableRBAC false.
	ErrAuthorizerRequired = errors.New("mcp: authorizer is required when rbac is enabled")

	// ErrPermissionDenied is the caller-facing denial for an authenticated
	// identity that lacks the qrdb role grant required by the invoked method.
	// The qrdb decision detail is logged, never returned, mirroring the REST
	// RBAC middleware's "Access denied: insufficient permissions" response.
	ErrPermissionDenied = errors.New("access denied: insufficient permissions")
)

// rpcMethod is one JSON-RPC method's registration: its handler and the
// qrdbsdk.Permission a caller must hold to invoke it, declared together at
// the registration site the way go-qrdb's HTTPRegistrar.Handle declares a
// module route's permission. A method without a permission is public;
// handlePublic is the only way to register one.
//
// xkms defines no permission vocabulary of its own: every permission is a
// go-qrdb resource:action pair built from pkg/auth constants, taken verbatim
// from the transport that already gates the equivalent operation
// (pkg/api/grpc's (qrdb.v1.permission) options and s.authorize calls,
// pkg/api/rest/routes.go's route decorators). This package's
// authz_golden_test.go pins every pair to the checked-in wire contract so the
// transports cannot drift apart silently (go-xkms#1232).
type rpcMethod struct {
	perm    qrdbsdk.Permission
	handler rpcHandler
}

// public reports whether the method is served without authorization.
func (m rpcMethod) public() bool { return m.perm == "" }

// handle registers a method gated on the resource:action permission.
func handle(resource, action string, handler rpcHandler) rpcMethod {
	return rpcMethod{perm: qrdbsdk.Permission(resource + ":" + action), handler: handler}
}

// handlePublic registers a method that carries no authorization requirement.
// Reserve it for methods that reach no caller data and that every other
// transport also serves unauthenticated.
func handlePublic(handler rpcHandler) rpcMethod {
	return rpcMethod{handler: handler}
}

// authorizeMethod gates a JSON-RPC method against the qrdb-backed authorizer.
//
// When RBAC is disabled the gate is a no-op: every authenticated caller may
// invoke every method. That matches the REST server (which registers its
// routes without the RBAC decorator when EnableRBAC is false) and the QUIC
// server (whose default authorizer has no RBAC client and therefore allows
// all). Authentication is still mandatory on every transport, RBAC or not.
//
// When RBAC is enabled the method's registered permission is enforced through
// the qrdbsdk.Authorizer contract: a missing identity is reported as
// ErrCodeUnauthorized and a denied grant as ErrCodeForbidden. A public or
// unknown method passes, the latter so the dispatcher answers it with "Method
// not found"; a dispatchable method without a permission cannot exist, since
// rpcMethods is built only from handle and handlePublic. Failures are returned as
// *KeyOpError so InvokeMethod's existing errors.As unwrapping selects the
// wire-level code.
func (s *Server) authorizeMethod(ctx context.Context, method string) error {
	if !s.rbacEnabled {
		return nil
	}

	entry, dispatchable := rpcMethods[method]
	if !dispatchable || entry.public() {
		return nil
	}
	resource := qrdbsdk.PermissionResource(entry.perm)
	action := qrdbsdk.PermissionAction(entry.perm)

	identity := auth.GetIdentity(ctx)
	if identity == nil {
		s.logger.WarnContext(ctx, "MCP authorization failed: no identity on request",
			slog.String("method", method),
			slog.String("resource", resource),
			slog.String("action", action))
		return &KeyOpError{Code: ErrCodeUnauthorized, Err: auth.ErrUnauthenticated}
	}

	if err := s.authorizer.Authorize(ctx, identity, resource, action); err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			return &KeyOpError{Code: ErrCodeUnauthorized, Err: err}
		}
		s.logger.WarnContext(ctx, "MCP authorization denied",
			slog.String("method", method),
			slog.String("subject", identity.Subject),
			slog.String("resource", resource),
			slog.String("action", action),
			slog.String("error", err.Error()))
		return &KeyOpError{Code: ErrCodeForbidden, Err: ErrPermissionDenied}
	}

	s.logger.DebugContext(ctx, "MCP authorization granted",
		slog.String("method", method),
		slog.String("subject", identity.Subject),
		slog.String("resource", resource),
		slog.String("action", action))

	return nil
}

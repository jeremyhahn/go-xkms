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

package server

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Permission is the canonical go-qrdb resource:action pair a gRPC method
// requires. The pairs below are identical to the ones the ACME admin REST
// routes and the MCP methods request, so the same grant means the same thing on
// every transport.
type Permission struct {
	Resource string
	Action   string
}

// MethodPermissions maps every gRPC AdminService method to the qrdb grant its
// caller must hold. A dispatchable method missing from this table is denied,
// not admitted — see UnaryAuthorizationInterceptor.
var MethodPermissions = map[string]Permission{
	// Tenant lifecycle.
	"/admin.v1.AdminService/CreateTenant": {auth.ResourceTenants, auth.ActionCreate},
	"/admin.v1.AdminService/UpdateTenant": {auth.ResourceTenants, auth.ActionUpdate},
	"/admin.v1.AdminService/DeleteTenant": {auth.ResourceTenants, auth.ActionDelete},
	"/admin.v1.AdminService/GetTenant":    {auth.ResourceTenants, auth.ActionRead},
	"/admin.v1.AdminService/ListTenants":  {auth.ResourceTenants, auth.ActionList},

	// External Account Bindings.
	"/admin.v1.AdminService/CreateEAB": {auth.ResourceACMEEAB, auth.ActionCreate},
	"/admin.v1.AdminService/DeleteEAB": {auth.ResourceACMEEAB, auth.ActionDelete},
	"/admin.v1.AdminService/GetEAB":    {auth.ResourceACMEEAB, auth.ActionRead},
	"/admin.v1.AdminService/ListEABs":  {auth.ResourceACMEEAB, auth.ActionList},

	// Role management.
	"/admin.v1.AdminService/CreateTenantRole": {auth.ResourceRoles, auth.ActionCreate},
	"/admin.v1.AdminService/UpdateTenantRole": {auth.ResourceRoles, auth.ActionUpdate},
	"/admin.v1.AdminService/DeleteTenantRole": {auth.ResourceRoles, auth.ActionDelete},
	"/admin.v1.AdminService/GetTenantRole":    {auth.ResourceRoles, auth.ActionRead},
	"/admin.v1.AdminService/ListTenantRoles":  {auth.ResourceRoles, auth.ActionList},

	// User management.
	"/admin.v1.AdminService/CreateTenantUser": {auth.ResourceUsers, auth.ActionCreate},
	"/admin.v1.AdminService/UpdateTenantUser": {auth.ResourceUsers, auth.ActionUpdate},
	"/admin.v1.AdminService/DeleteTenantUser": {auth.ResourceUsers, auth.ActionDelete},
	"/admin.v1.AdminService/GetTenantUser":    {auth.ResourceUsers, auth.ActionRead},
	"/admin.v1.AdminService/ListTenantUsers":  {auth.ResourceUsers, auth.ActionList},

	// Certificates.
	"/admin.v1.AdminService/RevokeCertificate": {auth.ResourceCerts, auth.ActionRevoke},
	"/admin.v1.AdminService/GetCertificate":    {auth.ResourceCerts, auth.ActionRead},
	"/admin.v1.AdminService/ListCertificates":  {auth.ResourceCerts, auth.ActionList},

	// Server status.
	"/admin.v1.AdminService/GetStatus": {auth.ResourceAdmin, auth.ActionStatus},
	"/admin.v1.AdminService/GetStats":  {auth.ResourceAdmin, auth.ActionStatus},
}

// UnaryAuthorizationInterceptor returns a gRPC unary server interceptor that
// authorizes every AdminService call through the qrdb-backed PermissionGate —
// the same seam the ACME admin REST routes and the MCP surface use.
//
// The identity is resolved in this order:
//
//  1. An identity already on the context, published by an upstream
//     authenticating interceptor (UnaryMTLSIdentityInterceptor for TLS/TCP).
//  2. Unix peer credentials (SO_PEERCRED), mapped to canonical qrdb role names
//     by roleMapping. The kernel supplies these and the peer cannot forge them.
//
// A call with neither is Unauthenticated. This replaces the previous behavior
// where a connection without peer credentials — every TCP connection — was
// passed straight through to the handler on the assumption that "TLS client
// certificate authentication handles authorization at a different layer". No
// such layer existed, so the entire ACME admin gRPC TCP surface was
// unauthenticated and unauthorized.
func UnaryAuthorizationInterceptor(roleMapping *RoleMapping, gate *admin.PermissionGate, logger *slog.Logger) grpc.UnaryServerInterceptor {
	if roleMapping == nil {
		roleMapping = DefaultRoleMapping()
	}
	if logger == nil {
		logger = slog.Default()
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		perm, mapped := MethodPermissions[info.FullMethod]
		if !mapped {
			logger.ErrorContext(ctx, "ACME admin gRPC method has no permission mapping; denying",
				slog.String("method", info.FullMethod))
			return nil, status.Error(codes.PermissionDenied, admin.ErrOperationUnmapped.Error())
		}

		ctx = withResolvedIdentity(ctx, roleMapping)

		if err := gate.Authorize(ctx, perm.Resource, perm.Action); err != nil {
			if errors.Is(err, auth.ErrUnauthenticated) {
				return nil, status.Errorf(codes.Unauthenticated,
					"authentication required for %s", info.FullMethod)
			}
			return nil, status.Errorf(codes.PermissionDenied,
				"permission denied: %s requires %s:%s", info.FullMethod, perm.Resource, perm.Action)
		}

		return handler(ctx, req)
	}
}

// withResolvedIdentity returns a context carrying the caller's canonical
// identity. An identity published upstream (mTLS) wins; otherwise Unix peer
// credentials are mapped to qrdb role names. When neither is available the
// context is returned unchanged and the gate denies for want of an identity.
func withResolvedIdentity(ctx context.Context, roleMapping *RoleMapping) context.Context {
	if auth.GetIdentity(ctx) != nil {
		return ctx
	}
	creds := GetPeerCredentials(ctx)
	if creds == nil {
		return ctx
	}
	return auth.WithIdentity(ctx, roleMapping.Identity(creds))
}

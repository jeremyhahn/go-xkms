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

	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
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
//
// Keyed by the generated adminv1.AdminService_*_FullMethodName constants
// (api/proto/admin/v1/admin_grpc.pb.go), never by hand-written string
// literals: the real FullMethod a gRPC call carries is
// "/trustedca.admin.v1.AdminService/...", not "/admin.v1.AdminService/...",
// and a literal that drifted from the generated value would silently deny
// every call to the method it named (go-xkms#743).
var MethodPermissions = map[string]Permission{
	// Tenant lifecycle.
	adminv1.AdminService_CreateTenant_FullMethodName: {auth.ResourceTenants, auth.ActionCreate},
	adminv1.AdminService_UpdateTenant_FullMethodName: {auth.ResourceTenants, auth.ActionUpdate},
	adminv1.AdminService_DeleteTenant_FullMethodName: {auth.ResourceTenants, auth.ActionDelete},
	adminv1.AdminService_GetTenant_FullMethodName:    {auth.ResourceTenants, auth.ActionRead},
	adminv1.AdminService_ListTenants_FullMethodName:  {auth.ResourceTenants, auth.ActionList},

	// External Account Bindings.
	adminv1.AdminService_CreateEAB_FullMethodName: {auth.ResourceACMEEAB, auth.ActionCreate},
	adminv1.AdminService_DeleteEAB_FullMethodName: {auth.ResourceACMEEAB, auth.ActionDelete},
	adminv1.AdminService_GetEAB_FullMethodName:    {auth.ResourceACMEEAB, auth.ActionRead},
	adminv1.AdminService_ListEABs_FullMethodName:  {auth.ResourceACMEEAB, auth.ActionList},

	// Role management.
	adminv1.AdminService_CreateTenantRole_FullMethodName: {auth.ResourceRoles, auth.ActionCreate},
	adminv1.AdminService_UpdateTenantRole_FullMethodName: {auth.ResourceRoles, auth.ActionUpdate},
	adminv1.AdminService_DeleteTenantRole_FullMethodName: {auth.ResourceRoles, auth.ActionDelete},
	adminv1.AdminService_GetTenantRole_FullMethodName:    {auth.ResourceRoles, auth.ActionRead},
	adminv1.AdminService_ListTenantRoles_FullMethodName:  {auth.ResourceRoles, auth.ActionList},

	// User management.
	adminv1.AdminService_CreateTenantUser_FullMethodName: {auth.ResourceUsers, auth.ActionCreate},
	adminv1.AdminService_UpdateTenantUser_FullMethodName: {auth.ResourceUsers, auth.ActionUpdate},
	adminv1.AdminService_DeleteTenantUser_FullMethodName: {auth.ResourceUsers, auth.ActionDelete},
	adminv1.AdminService_GetTenantUser_FullMethodName:    {auth.ResourceUsers, auth.ActionRead},
	adminv1.AdminService_ListTenantUsers_FullMethodName:  {auth.ResourceUsers, auth.ActionList},

	// Certificates.
	adminv1.AdminService_RevokeCertificate_FullMethodName: {auth.ResourceCerts, auth.ActionRevoke},
	adminv1.AdminService_GetCertificate_FullMethodName:    {auth.ResourceCerts, auth.ActionRead},
	adminv1.AdminService_ListCertificates_FullMethodName:  {auth.ResourceCerts, auth.ActionList},

	// ACME accounts. Mirrors the REST admin routes (pkg/acme/admin/handlers.go)
	// and the MCP method table (MCPMethodPermissions) exactly.
	adminv1.AdminService_ListAccounts_FullMethodName:   {auth.ResourceACMEAccounts, auth.ActionList},
	adminv1.AdminService_GetAccount_FullMethodName:     {auth.ResourceACMEAccounts, auth.ActionRead},
	adminv1.AdminService_DisableAccount_FullMethodName: {auth.ResourceACMEAccounts, auth.ActionDisable},

	// Server status.
	adminv1.AdminService_GetStatus_FullMethodName: {auth.ResourceAdmin, auth.ActionStatus},
	adminv1.AdminService_GetStats_FullMethodName:  {auth.ResourceAdmin, auth.ActionStatus},
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

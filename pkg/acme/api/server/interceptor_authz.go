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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MethodRoles maps gRPC method full names to their required roles.
// Methods not in this map default to requiring viewer role for Unix socket
// connections and are allowed for TLS-authenticated TCP connections.
var MethodRoles = map[string]Role{
	// Tenant management - admin only
	"/admin.v1.AdminService/CreateTenant": RoleAdmin,
	"/admin.v1.AdminService/UpdateTenant": RoleAdmin,
	"/admin.v1.AdminService/DeleteTenant": RoleAdmin,

	// Tenant viewing - operator and above
	"/admin.v1.AdminService/GetTenant":   RoleOperator,
	"/admin.v1.AdminService/ListTenants": RoleOperator,

	// EAB management - admin only
	"/admin.v1.AdminService/CreateEAB": RoleAdmin,
	"/admin.v1.AdminService/DeleteEAB": RoleAdmin,

	// EAB viewing - operator and above
	"/admin.v1.AdminService/GetEAB":   RoleOperator,
	"/admin.v1.AdminService/ListEABs": RoleOperator,

	// Role management (RBAC) - admin only
	"/admin.v1.AdminService/CreateTenantRole": RoleAdmin,
	"/admin.v1.AdminService/UpdateTenantRole": RoleAdmin,
	"/admin.v1.AdminService/DeleteTenantRole": RoleAdmin,

	// Role viewing - operator and above
	"/admin.v1.AdminService/GetTenantRole":   RoleOperator,
	"/admin.v1.AdminService/ListTenantRoles": RoleOperator,

	// User management (RBAC) - admin only
	"/admin.v1.AdminService/CreateTenantUser": RoleAdmin,
	"/admin.v1.AdminService/UpdateTenantUser": RoleAdmin,
	"/admin.v1.AdminService/DeleteTenantUser": RoleAdmin,

	// User viewing - operator and above
	"/admin.v1.AdminService/GetTenantUser":   RoleOperator,
	"/admin.v1.AdminService/ListTenantUsers": RoleOperator,

	// Certificate management - admin for revocation
	"/admin.v1.AdminService/RevokeCertificate": RoleAdmin,

	// Certificate viewing - viewer and above
	"/admin.v1.AdminService/GetCertificate":   RoleViewer,
	"/admin.v1.AdminService/ListCertificates": RoleViewer,

	// Status operations - viewer and above
	"/admin.v1.AdminService/GetStatus": RoleViewer,
	"/admin.v1.AdminService/GetStats":  RoleViewer,
}

// UnaryAuthorizationInterceptor returns a gRPC unary server interceptor that
// enforces role-based access control for Unix socket connections.
//
// For Unix socket connections (identified by peer credentials in context),
// this interceptor checks if the caller's role meets the required role for
// the requested method.
//
// For TCP connections (no peer credentials), this interceptor passes through,
// assuming that TLS client certificate authentication or other mechanisms
// handle authorization at a different layer.
func UnaryAuthorizationInterceptor(roleMapping *RoleMapping) grpc.UnaryServerInterceptor {
	if roleMapping == nil {
		roleMapping = DefaultRoleMapping()
	}

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Get peer credentials from context (set by PeerCredentialsInterceptor)
		creds := GetPeerCredentials(ctx)

		// If no credentials, this is likely a TCP connection
		// Allow it through - TCP uses TLS client certs for auth
		if creds == nil {
			return handler(ctx, req)
		}

		// Determine the user's role based on credentials
		userRole := roleMapping.GetRole(creds)

		// Look up the required role for this method
		requiredRole, exists := MethodRoles[info.FullMethod]
		if !exists {
			// Default to viewer for unlisted methods
			requiredRole = RoleViewer
		}

		// Check authorization
		if !CanPerform(userRole, requiredRole) {
			return nil, status.Errorf(codes.PermissionDenied,
				"permission denied: role %q cannot perform %s (requires %q)",
				userRole, info.FullMethod, requiredRole)
		}

		return handler(ctx, req)
	}
}

// authorizationContextKey is the context key for storing authorization info.
type authorizationContextKey struct{}

// AuthorizationInfo contains authorization details for the current request.
type AuthorizationInfo struct {
	// Role is the determined role of the caller
	Role Role
	// Method is the gRPC method being called
	Method string
	// RequiredRole is the role required for the method
	RequiredRole Role
}

// GetAuthorizationInfo retrieves authorization info from the context.
func GetAuthorizationInfo(ctx context.Context) *AuthorizationInfo {
	if info, ok := ctx.Value(authorizationContextKey{}).(*AuthorizationInfo); ok {
		return info
	}
	return nil
}

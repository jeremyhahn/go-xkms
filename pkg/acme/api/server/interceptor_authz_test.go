// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !integration

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMethodRoles_AllMethodsMapped(t *testing.T) {
	// Verify all expected methods have role mappings
	expectedMethods := []string{
		// Tenant management
		"/admin.v1.AdminService/CreateTenant",
		"/admin.v1.AdminService/UpdateTenant",
		"/admin.v1.AdminService/DeleteTenant",
		"/admin.v1.AdminService/GetTenant",
		"/admin.v1.AdminService/ListTenants",
		// EAB management
		"/admin.v1.AdminService/CreateEAB",
		"/admin.v1.AdminService/DeleteEAB",
		"/admin.v1.AdminService/GetEAB",
		"/admin.v1.AdminService/ListEABs",
		// Role management (RBAC)
		"/admin.v1.AdminService/CreateTenantRole",
		"/admin.v1.AdminService/UpdateTenantRole",
		"/admin.v1.AdminService/DeleteTenantRole",
		"/admin.v1.AdminService/GetTenantRole",
		"/admin.v1.AdminService/ListTenantRoles",
		// User management (RBAC)
		"/admin.v1.AdminService/CreateTenantUser",
		"/admin.v1.AdminService/UpdateTenantUser",
		"/admin.v1.AdminService/DeleteTenantUser",
		"/admin.v1.AdminService/GetTenantUser",
		"/admin.v1.AdminService/ListTenantUsers",
		// Certificate management
		"/admin.v1.AdminService/RevokeCertificate",
		"/admin.v1.AdminService/GetCertificate",
		"/admin.v1.AdminService/ListCertificates",
		// Status operations
		"/admin.v1.AdminService/GetStatus",
		"/admin.v1.AdminService/GetStats",
	}

	for _, method := range expectedMethods {
		t.Run(method, func(t *testing.T) {
			role, exists := MethodRoles[method]
			assert.True(t, exists, "Method %s should be in MethodRoles map", method)
			assert.NotEqual(t, RoleNone, role, "Method %s should have a non-none role", method)
		})
	}
}

func TestMethodRoles_AdminMethods(t *testing.T) {
	adminMethods := []string{
		"/admin.v1.AdminService/CreateTenant",
		"/admin.v1.AdminService/UpdateTenant",
		"/admin.v1.AdminService/DeleteTenant",
		"/admin.v1.AdminService/CreateEAB",
		"/admin.v1.AdminService/DeleteEAB",
		"/admin.v1.AdminService/CreateTenantRole",
		"/admin.v1.AdminService/UpdateTenantRole",
		"/admin.v1.AdminService/DeleteTenantRole",
		"/admin.v1.AdminService/CreateTenantUser",
		"/admin.v1.AdminService/UpdateTenantUser",
		"/admin.v1.AdminService/DeleteTenantUser",
		"/admin.v1.AdminService/RevokeCertificate",
	}

	for _, method := range adminMethods {
		t.Run(method, func(t *testing.T) {
			role, exists := MethodRoles[method]
			require.True(t, exists, "Method %s should exist", method)
			assert.Equal(t, RoleAdmin, role, "Method %s should require RoleAdmin", method)
		})
	}
}

func TestMethodRoles_OperatorMethods(t *testing.T) {
	operatorMethods := []string{
		"/admin.v1.AdminService/GetTenant",
		"/admin.v1.AdminService/ListTenants",
		"/admin.v1.AdminService/GetEAB",
		"/admin.v1.AdminService/ListEABs",
		"/admin.v1.AdminService/GetTenantRole",
		"/admin.v1.AdminService/ListTenantRoles",
		"/admin.v1.AdminService/GetTenantUser",
		"/admin.v1.AdminService/ListTenantUsers",
	}

	for _, method := range operatorMethods {
		t.Run(method, func(t *testing.T) {
			role, exists := MethodRoles[method]
			require.True(t, exists, "Method %s should exist", method)
			assert.Equal(t, RoleOperator, role, "Method %s should require RoleOperator", method)
		})
	}
}

func TestMethodRoles_ViewerMethods(t *testing.T) {
	viewerMethods := []string{
		"/admin.v1.AdminService/GetCertificate",
		"/admin.v1.AdminService/ListCertificates",
		"/admin.v1.AdminService/GetStatus",
		"/admin.v1.AdminService/GetStats",
	}

	for _, method := range viewerMethods {
		t.Run(method, func(t *testing.T) {
			role, exists := MethodRoles[method]
			require.True(t, exists, "Method %s should exist", method)
			assert.Equal(t, RoleViewer, role, "Method %s should require RoleViewer", method)
		})
	}
}

// mockUnaryHandler is a test handler that records invocations
type mockUnaryHandler struct {
	called   bool
	response interface{}
	err      error
}

func (h *mockUnaryHandler) Handler(ctx context.Context, req interface{}) (interface{}, error) {
	h.called = true
	return h.response, h.err
}

func TestUnaryAuthorizationInterceptor_NoCredentials(t *testing.T) {
	// No peer credentials = TCP connection, should pass through
	interceptor := UnaryAuthorizationInterceptor(nil)

	handler := &mockUnaryHandler{response: "success"}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/admin.v1.AdminService/CreateTenant", // Admin-only method
	}

	// Context without peer credentials (simulates TCP connection)
	ctx := context.Background()

	resp, err := interceptor(ctx, "request", info, handler.Handler)

	assert.NoError(t, err, "TCP connections should pass through")
	assert.True(t, handler.called, "Handler should be called")
	assert.Equal(t, "success", resp)
}

func TestUnaryAuthorizationInterceptor_AdminAccess(t *testing.T) {
	rm := DefaultRoleMapping()
	interceptor := UnaryAuthorizationInterceptor(rm)

	// Admin credentials (root user)
	creds := &PeerCredentials{PID: 1234, UID: 0, GID: 0}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	methods := []string{
		"/admin.v1.AdminService/CreateTenant",
		"/admin.v1.AdminService/GetTenant",
		"/admin.v1.AdminService/GetCertificate",
		"/admin.v1.AdminService/GetStatus",
		"/some/unknown/Method", // Unknown methods default to viewer
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			handler := &mockUnaryHandler{response: "success"}
			info := &grpc.UnaryServerInfo{FullMethod: method}

			resp, err := interceptor(ctx, "request", info, handler.Handler)

			assert.NoError(t, err, "Admin should have access to %s", method)
			assert.True(t, handler.called, "Handler should be called")
			assert.Equal(t, "success", resp)
		})
	}
}

func TestUnaryAuthorizationInterceptor_OperatorAccess(t *testing.T) {
	rm := DefaultRoleMapping()
	interceptor := UnaryAuthorizationInterceptor(rm)

	// Operator credentials (wheel group)
	creds := &PeerCredentials{PID: 1234, UID: 1000, GID: 10}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	t.Run("operator can access operator methods", func(t *testing.T) {
		handler := &mockUnaryHandler{response: "success"}
		info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/GetTenant"}

		resp, err := interceptor(ctx, "request", info, handler.Handler)

		assert.NoError(t, err)
		assert.True(t, handler.called)
		assert.Equal(t, "success", resp)
	})

	t.Run("operator can access viewer methods", func(t *testing.T) {
		handler := &mockUnaryHandler{response: "success"}
		info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/GetStatus"}

		resp, err := interceptor(ctx, "request", info, handler.Handler)

		assert.NoError(t, err)
		assert.True(t, handler.called)
		assert.Equal(t, "success", resp)
	})

	t.Run("operator cannot access admin methods", func(t *testing.T) {
		handler := &mockUnaryHandler{response: "success"}
		info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/CreateTenant"}

		resp, err := interceptor(ctx, "request", info, handler.Handler)

		assert.Error(t, err)
		assert.False(t, handler.called, "Handler should not be called when permission denied")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})
}

func TestUnaryAuthorizationInterceptor_ViewerAccess(t *testing.T) {
	rm := DefaultRoleMapping()
	interceptor := UnaryAuthorizationInterceptor(rm)

	// Viewer credentials (regular user)
	creds := &PeerCredentials{PID: 1234, UID: 1000, GID: 1000}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	t.Run("viewer can access viewer methods", func(t *testing.T) {
		handler := &mockUnaryHandler{response: "success"}
		info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/GetStatus"}

		resp, err := interceptor(ctx, "request", info, handler.Handler)

		assert.NoError(t, err)
		assert.True(t, handler.called)
		assert.Equal(t, "success", resp)
	})

	t.Run("viewer cannot access operator methods", func(t *testing.T) {
		handler := &mockUnaryHandler{response: "success"}
		info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/GetTenant"}

		_, err := interceptor(ctx, "request", info, handler.Handler)

		assert.Error(t, err)
		assert.False(t, handler.called)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})

	t.Run("viewer cannot access admin methods", func(t *testing.T) {
		handler := &mockUnaryHandler{response: "success"}
		info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/CreateTenant"}

		_, err := interceptor(ctx, "request", info, handler.Handler)

		assert.Error(t, err)
		assert.False(t, handler.called)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})
}

func TestUnaryAuthorizationInterceptor_PermissionDenied(t *testing.T) {
	rm := DefaultRoleMapping()
	interceptor := UnaryAuthorizationInterceptor(rm)

	// Regular viewer
	creds := &PeerCredentials{PID: 1234, UID: 1000, GID: 1000}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	handler := &mockUnaryHandler{response: "success"}
	info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/CreateTenant"}

	resp, err := interceptor(ctx, "request", info, handler.Handler)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.False(t, handler.called)

	// Verify it's a proper gRPC status error
	st, ok := status.FromError(err)
	require.True(t, ok, "Error should be a gRPC status")
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "permission denied")
	assert.Contains(t, st.Message(), "viewer")
	assert.Contains(t, st.Message(), "admin")
}

func TestUnaryAuthorizationInterceptor_UnknownMethod(t *testing.T) {
	rm := DefaultRoleMapping()
	interceptor := UnaryAuthorizationInterceptor(rm)

	// Viewer should be able to access unknown methods (default to viewer)
	creds := &PeerCredentials{PID: 1234, UID: 1000, GID: 1000}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	handler := &mockUnaryHandler{response: "success"}
	info := &grpc.UnaryServerInfo{FullMethod: "/some.service/UnknownMethod"}

	resp, err := interceptor(ctx, "request", info, handler.Handler)

	assert.NoError(t, err, "Unknown methods should default to viewer role requirement")
	assert.True(t, handler.called)
	assert.Equal(t, "success", resp)
}

func TestUnaryAuthorizationInterceptor_NilRoleMapping(t *testing.T) {
	// Passing nil should use default mapping
	interceptor := UnaryAuthorizationInterceptor(nil)

	// Root user should get admin role with default mapping
	creds := &PeerCredentials{PID: 1234, UID: 0, GID: 0}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	handler := &mockUnaryHandler{response: "success"}
	info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/CreateTenant"}

	resp, err := interceptor(ctx, "request", info, handler.Handler)

	assert.NoError(t, err, "Root user should have admin access with default mapping")
	assert.True(t, handler.called)
	assert.Equal(t, "success", resp)
}

func TestUnaryAuthorizationInterceptor_HandlerError(t *testing.T) {
	rm := DefaultRoleMapping()
	interceptor := UnaryAuthorizationInterceptor(rm)

	creds := &PeerCredentials{PID: 1234, UID: 0, GID: 0}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	expectedErr := status.Error(codes.Internal, "handler error")
	handler := &mockUnaryHandler{response: nil, err: expectedErr}
	info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/GetStatus"}

	resp, err := interceptor(ctx, "request", info, handler.Handler)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err, "Handler error should be propagated")
	assert.True(t, handler.called)
	assert.Nil(t, resp)
}

func TestGetAuthorizationInfo_NotInContext(t *testing.T) {
	ctx := context.Background()
	info := GetAuthorizationInfo(ctx)
	assert.Nil(t, info, "GetAuthorizationInfo should return nil when not in context")
}

func TestGetAuthorizationInfo_InContext(t *testing.T) {
	authInfo := &AuthorizationInfo{
		Role:         RoleOperator,
		Method:       "/admin.v1.AdminService/GetTenant",
		RequiredRole: RoleOperator,
	}

	ctx := context.WithValue(context.Background(), authorizationContextKey{}, authInfo)
	info := GetAuthorizationInfo(ctx)

	require.NotNil(t, info)
	assert.Equal(t, RoleOperator, info.Role)
	assert.Equal(t, "/admin.v1.AdminService/GetTenant", info.Method)
	assert.Equal(t, RoleOperator, info.RequiredRole)
}

func TestGetAuthorizationInfo_WrongType(t *testing.T) {
	// Wrong type in context should return nil
	ctx := context.WithValue(context.Background(), authorizationContextKey{}, "not an AuthorizationInfo")
	info := GetAuthorizationInfo(ctx)
	assert.Nil(t, info, "GetAuthorizationInfo should return nil for wrong type")
}

func TestUnaryAuthorizationInterceptor_CustomRoleMapping(t *testing.T) {
	// Custom mapping where UID 1000 is admin
	rm := &RoleMapping{
		AdminUIDs: []uint32{1000},
	}
	interceptor := UnaryAuthorizationInterceptor(rm)

	creds := &PeerCredentials{PID: 1234, UID: 1000, GID: 1000}
	ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

	handler := &mockUnaryHandler{response: "success"}
	info := &grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/CreateTenant"}

	resp, err := interceptor(ctx, "request", info, handler.Handler)

	assert.NoError(t, err, "Custom admin should have access")
	assert.True(t, handler.called)
	assert.Equal(t, "success", resp)
}

func TestUnaryAuthorizationInterceptor_AllMethodRoles(t *testing.T) {
	// Test each method in MethodRoles with appropriate role
	rm := DefaultRoleMapping()

	testCases := []struct {
		method    string
		role      Role
		canAccess bool
	}{
		// Admin methods - viewer cannot access
		{"/admin.v1.AdminService/CreateTenant", RoleViewer, false},
		{"/admin.v1.AdminService/UpdateTenant", RoleViewer, false},
		{"/admin.v1.AdminService/DeleteTenant", RoleViewer, false},
		{"/admin.v1.AdminService/CreateEAB", RoleViewer, false},
		{"/admin.v1.AdminService/DeleteEAB", RoleViewer, false},
		{"/admin.v1.AdminService/CreateTenantRole", RoleViewer, false},
		{"/admin.v1.AdminService/UpdateTenantRole", RoleViewer, false},
		{"/admin.v1.AdminService/DeleteTenantRole", RoleViewer, false},
		{"/admin.v1.AdminService/CreateTenantUser", RoleViewer, false},
		{"/admin.v1.AdminService/UpdateTenantUser", RoleViewer, false},
		{"/admin.v1.AdminService/DeleteTenantUser", RoleViewer, false},
		{"/admin.v1.AdminService/RevokeCertificate", RoleViewer, false},

		// Operator methods - viewer cannot access
		{"/admin.v1.AdminService/GetTenant", RoleViewer, false},
		{"/admin.v1.AdminService/ListTenants", RoleViewer, false},
		{"/admin.v1.AdminService/GetEAB", RoleViewer, false},
		{"/admin.v1.AdminService/ListEABs", RoleViewer, false},
		{"/admin.v1.AdminService/GetTenantRole", RoleViewer, false},
		{"/admin.v1.AdminService/ListTenantRoles", RoleViewer, false},
		{"/admin.v1.AdminService/GetTenantUser", RoleViewer, false},
		{"/admin.v1.AdminService/ListTenantUsers", RoleViewer, false},

		// Viewer methods - viewer can access
		{"/admin.v1.AdminService/GetCertificate", RoleViewer, true},
		{"/admin.v1.AdminService/ListCertificates", RoleViewer, true},
		{"/admin.v1.AdminService/GetStatus", RoleViewer, true},
		{"/admin.v1.AdminService/GetStats", RoleViewer, true},
	}

	for _, tc := range testCases {
		t.Run(tc.method+"_"+string(tc.role), func(t *testing.T) {
			interceptor := UnaryAuthorizationInterceptor(rm)

			var creds *PeerCredentials
			switch tc.role {
			case RoleAdmin:
				creds = &PeerCredentials{PID: 1234, UID: 0, GID: 0}
			case RoleOperator:
				creds = &PeerCredentials{PID: 1234, UID: 1000, GID: 10}
			case RoleViewer:
				creds = &PeerCredentials{PID: 1234, UID: 1000, GID: 1000}
			}
			ctx := context.WithValue(context.Background(), peerCredentialsKey{}, creds)

			handler := &mockUnaryHandler{response: "success"}
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}

			resp, err := interceptor(ctx, "request", info, handler.Handler)

			if tc.canAccess {
				assert.NoError(t, err)
				assert.True(t, handler.called)
				assert.Equal(t, "success", resp)
			} else {
				assert.Error(t, err)
				assert.False(t, handler.called)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, codes.PermissionDenied, st.Code())
			}
		})
	}
}

func TestAuthorizationInfo_Fields(t *testing.T) {
	info := &AuthorizationInfo{
		Role:         RoleAdmin,
		Method:       "/test/Method",
		RequiredRole: RoleOperator,
	}

	assert.Equal(t, RoleAdmin, info.Role)
	assert.Equal(t, "/test/Method", info.Method)
	assert.Equal(t, RoleOperator, info.RequiredRole)
}

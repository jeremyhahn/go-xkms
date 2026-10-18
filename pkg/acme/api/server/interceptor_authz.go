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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbv1 "github.com/jeremyhahn/go-qrdb/sdk/go/proto/qrdb/v1"

	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// adminRPCPermissions maps every AdminService full method name
// ("/trustedca.admin.v1.AdminService/CreateTenant") to the permission its
// descriptor declares with the go-qrdb method option (qrdb.v1.permission,
// api/proto/admin.proto). It is read once from the generated descriptor, so
// the proto is the one place a method's permission is written; the ACME admin
// REST routes and MCP methods request the same permissions, so a grant means
// the same thing on every transport.
var adminRPCPermissions = descriptorPermissions(adminv1.File_api_proto_admin_proto)

// descriptorPermissions returns the qrdb.v1.permission option of every method
// of every service in file, keyed by the method's gRPC full method name. A
// method without the option is left out, so the interceptor denies it.
func descriptorPermissions(file protoreflect.FileDescriptor) map[string]qrdbsdk.Permission {
	perms := map[string]qrdbsdk.Permission{}
	services := file.Services()
	for i := 0; i < services.Len(); i++ {
		service := services.Get(i)
		methods := service.Methods()
		for j := 0; j < methods.Len(); j++ {
			method := methods.Get(j)
			if perm, ok := methodPermission(method); ok {
				perms["/"+string(service.FullName())+"/"+string(method.Name())] = perm
			}
		}
	}
	return perms
}

// methodPermission returns the permission method declares with the
// qrdb.v1.permission option, and false when it declares none.
func methodPermission(method protoreflect.MethodDescriptor) (qrdbsdk.Permission, bool) {
	opts, ok := method.Options().(*descriptorpb.MethodOptions)
	if !ok || !proto.HasExtension(opts, qrdbv1.E_Permission) {
		return "", false
	}
	perm, ok := proto.GetExtension(opts, qrdbv1.E_Permission).(string)
	if !ok || perm == "" {
		return "", false
	}
	return qrdbsdk.Permission(perm), true
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
		perm, mapped := adminRPCPermissions[info.FullMethod]
		if !mapped {
			logger.ErrorContext(ctx, "ACME admin gRPC method has no permission mapping; denying",
				slog.String("method", info.FullMethod))
			return nil, status.Error(codes.PermissionDenied, admin.ErrOperationUnmapped.Error())
		}

		ctx = withResolvedIdentity(ctx, roleMapping)

		if err := gate.Authorize(ctx, qrdbsdk.PermissionResource(perm), qrdbsdk.PermissionAction(perm),
			slog.String("method", info.FullMethod)); err != nil {
			if errors.Is(err, auth.ErrUnauthenticated) {
				return nil, status.Errorf(codes.Unauthenticated,
					"authentication required for %s", info.FullMethod)
			}
			return nil, status.Errorf(codes.PermissionDenied,
				"permission denied: %s requires %s", info.FullMethod, perm)
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

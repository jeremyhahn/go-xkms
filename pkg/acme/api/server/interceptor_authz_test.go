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

//go:build !integration

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// unprivilegedRole names a role that is not a canonical go-qrdb role and so
// holds no permission. Every canonical role carries admin:status since
// go-qrdb v0.40, so the status routes need a non-canonical caller to prove the
// gate still refuses one without the grant.
const unprivilegedRole = "unprivileged"

// errTestDenied is the deny sentinel the test RBAC client returns, standing in
// for qrdb's PermissionDeniedError.
var errTestDenied = errors.New("test: permission denied")

// qrdbRoleRBAC resolves authorization exactly as go-qrdb's canonical built-in
// roles define it. Using the real role definitions means these tests fail if a
// grant is ever dropped from qrdb's admin, operator, or auditor role.
type qrdbRoleRBAC struct {
	requested []string
}

func (q *qrdbRoleRBAC) Authorize(_ context.Context, id *qrdbtransport.Identity, resource, action string) error {
	want := resource + ":" + action
	q.requested = append(q.requested, want)

	if id == nil {
		return errTestDenied
	}
	held := make(map[string]struct{}, len(id.Roles))
	for _, r := range id.Roles {
		held[r] = struct{}{}
	}
	for _, r := range qrdbsdk.BuiltInRoles(id.TenantID) {
		if _, ok := held[r.Name]; !ok {
			continue
		}
		for _, p := range r.Permissions {
			if string(p) == want {
				return nil
			}
			if strings.HasSuffix(string(p), ":*") && strings.TrimSuffix(string(p), ":*") == resource {
				return nil
			}
		}
	}
	return errTestDenied
}

func (q *qrdbRoleRBAC) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func (q *qrdbRoleRBAC) ListOwnPermissions(ctx context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return q.ListPermissions(ctx, nil)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestGate returns a PermissionGate backed by qrdb's canonical role
// definitions, plus the recording client behind it.
func newTestGate() (*admin.PermissionGate, *qrdbRoleRBAC) {
	client := &qrdbRoleRBAC{}
	return admin.NewPermissionGate(auth.NewAuthorizer(client), testLogger()), client
}

// okHandler records that the handler ran.
func okHandler(ran *bool) grpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		*ran = true
		return "ok", nil
	}
}

// TestAdminRPCPermissions_EveryRPCDeclaresItsPermission is the table test over
// the AdminService descriptor: every RPC carries a well-formed
// (qrdb.v1.permission) option with exactly the grant it should require. An RPC
// added without the option is denied at runtime; this test makes that visible
// at build time.
func TestAdminRPCPermissions_EveryRPCDeclaresItsPermission(t *testing.T) {
	expected := map[string]qrdbsdk.Permission{
		adminv1.AdminService_CreateTenant_FullMethodName:      "tenants:create",
		adminv1.AdminService_UpdateTenant_FullMethodName:      "tenants:update",
		adminv1.AdminService_DeleteTenant_FullMethodName:      "tenants:delete",
		adminv1.AdminService_GetTenant_FullMethodName:         "tenants:read",
		adminv1.AdminService_ListTenants_FullMethodName:       "tenants:list",
		adminv1.AdminService_CreateEAB_FullMethodName:         "acme_eab:create",
		adminv1.AdminService_DeleteEAB_FullMethodName:         "acme_eab:delete",
		adminv1.AdminService_GetEAB_FullMethodName:            "acme_eab:read",
		adminv1.AdminService_ListEABs_FullMethodName:          "acme_eab:list",
		adminv1.AdminService_CreateTenantRole_FullMethodName:  "roles:create",
		adminv1.AdminService_UpdateTenantRole_FullMethodName:  "roles:update",
		adminv1.AdminService_DeleteTenantRole_FullMethodName:  "roles:delete",
		adminv1.AdminService_GetTenantRole_FullMethodName:     "roles:read",
		adminv1.AdminService_ListTenantRoles_FullMethodName:   "roles:list",
		adminv1.AdminService_CreateTenantUser_FullMethodName:  "users:create",
		adminv1.AdminService_UpdateTenantUser_FullMethodName:  "users:update",
		adminv1.AdminService_DeleteTenantUser_FullMethodName:  "users:delete",
		adminv1.AdminService_GetTenantUser_FullMethodName:     "users:read",
		adminv1.AdminService_ListTenantUsers_FullMethodName:   "users:list",
		adminv1.AdminService_RevokeCertificate_FullMethodName: "certs:revoke",
		adminv1.AdminService_GetCertificate_FullMethodName:    "certs:read",
		adminv1.AdminService_ListCertificates_FullMethodName:  "certs:list",
		adminv1.AdminService_ListAccounts_FullMethodName:      "acme_accounts:list",
		adminv1.AdminService_GetAccount_FullMethodName:        "acme_accounts:read",
		adminv1.AdminService_DisableAccount_FullMethodName:    "acme_accounts:disable",
		adminv1.AdminService_GetStatus_FullMethodName:         "admin:status",
		adminv1.AdminService_GetStats_FullMethodName:          "admin:status",
	}

	for full, want := range expected {
		t.Run(full, func(t *testing.T) {
			got, ok := adminRPCPermissions[full]
			require.True(t, ok, "method %s declares no (qrdb.v1.permission)", full)
			assert.Equal(t, want, got)
			_, err := qrdbsdk.ParsePermission(string(got))
			assert.NoError(t, err, "method %s declares a malformed permission", full)
		})
	}
	assert.Len(t, adminRPCPermissions, len(expected))
}

// TestAdminRPCPermissions_MatchesServiceDescriptorExactly verifies the
// permissions derived from the descriptor cover every method and stream the
// generated AdminService_ServiceDesc actually dispatches, and nothing else, so
// the dispatch table and the descriptor the permissions are read from cannot
// drift apart.
func TestAdminRPCPermissions_MatchesServiceDescriptorExactly(t *testing.T) {
	serviceName := adminv1.AdminService_ServiceDesc.ServiceName

	declared := make(map[string]struct{})
	for _, m := range adminv1.AdminService_ServiceDesc.Methods {
		declared["/"+serviceName+"/"+m.MethodName] = struct{}{}
	}
	for _, s := range adminv1.AdminService_ServiceDesc.Streams {
		declared["/"+serviceName+"/"+s.StreamName] = struct{}{}
	}
	require.NotEmpty(t, declared, "service descriptor must declare at least one method")

	for full := range declared {
		perm, ok := adminRPCPermissions[full]
		assert.True(t, ok, "service method %s declares no (qrdb.v1.permission)", full)
		assert.NotEmpty(t, qrdbsdk.PermissionResource(perm), "method %s has an empty resource", full)
		assert.NotEmpty(t, qrdbsdk.PermissionAction(perm), "method %s has an empty action", full)
	}

	for full := range adminRPCPermissions {
		assert.Contains(t, declared, full, "adminRPCPermissions has an entry for %s, which the service descriptor does not declare", full)
	}
}

// TestDescriptorPermissions_SkipsMethodsWithoutTheOption verifies a method
// that declares no (qrdb.v1.permission) is left out of the derived table, so
// the interceptor denies it rather than admitting it with an empty grant. The
// gRPC health service declares Check and Watch without the option.
func TestDescriptorPermissions_SkipsMethodsWithoutTheOption(t *testing.T) {
	require.Equal(t, 1, healthpb.File_grpc_health_v1_health_proto.Services().Len())
	assert.Empty(t, descriptorPermissions(healthpb.File_grpc_health_v1_health_proto))
}

// grpcAuthzCase pairs a gRPC method with the grant it must request and with a
// canonical qrdb role that does and does not hold it.
type grpcAuthzCase struct {
	method      string
	resource    string
	action      string
	allowedRole string
	deniedRole  string
}

var grpcAuthzCases = []grpcAuthzCase{
	{adminv1.AdminService_CreateTenant_FullMethodName, auth.ResourceTenants, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{adminv1.AdminService_UpdateTenant_FullMethodName, auth.ResourceTenants, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{adminv1.AdminService_DeleteTenant_FullMethodName, auth.ResourceTenants, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{adminv1.AdminService_GetTenant_FullMethodName, auth.ResourceTenants, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{adminv1.AdminService_ListTenants_FullMethodName, auth.ResourceTenants, auth.ActionList, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},

	{adminv1.AdminService_CreateEAB_FullMethodName, auth.ResourceACMEEAB, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{adminv1.AdminService_DeleteEAB_FullMethodName, auth.ResourceACMEEAB, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{adminv1.AdminService_GetEAB_FullMethodName, auth.ResourceACMEEAB, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{adminv1.AdminService_ListEABs_FullMethodName, auth.ResourceACMEEAB, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},

	{adminv1.AdminService_CreateTenantRole_FullMethodName, auth.ResourceRoles, auth.ActionCreate, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{adminv1.AdminService_UpdateTenantRole_FullMethodName, auth.ResourceRoles, auth.ActionUpdate, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{adminv1.AdminService_DeleteTenantRole_FullMethodName, auth.ResourceRoles, auth.ActionDelete, qrdbsdk.RoleNameSO, qrdbsdk.RoleNameAdmin},
	{adminv1.AdminService_GetTenantRole_FullMethodName, auth.ResourceRoles, auth.ActionRead, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},
	{adminv1.AdminService_ListTenantRoles_FullMethodName, auth.ResourceRoles, auth.ActionList, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameUser},

	{adminv1.AdminService_CreateTenantUser_FullMethodName, auth.ResourceUsers, auth.ActionCreate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{adminv1.AdminService_UpdateTenantUser_FullMethodName, auth.ResourceUsers, auth.ActionUpdate, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{adminv1.AdminService_DeleteTenantUser_FullMethodName, auth.ResourceUsers, auth.ActionDelete, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},
	{adminv1.AdminService_GetTenantUser_FullMethodName, auth.ResourceUsers, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{adminv1.AdminService_ListTenantUsers_FullMethodName, auth.ResourceUsers, auth.ActionList, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},

	{adminv1.AdminService_RevokeCertificate_FullMethodName, auth.ResourceCerts, auth.ActionRevoke, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameAuditor},
	{adminv1.AdminService_GetCertificate_FullMethodName, auth.ResourceCerts, auth.ActionRead, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},
	{adminv1.AdminService_ListCertificates_FullMethodName, auth.ResourceCerts, auth.ActionList, qrdbsdk.RoleNameAuditor, qrdbsdk.RoleNameUser},

	{adminv1.AdminService_ListAccounts_FullMethodName, auth.ResourceACMEAccounts, auth.ActionList, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{adminv1.AdminService_GetAccount_FullMethodName, auth.ResourceACMEAccounts, auth.ActionRead, qrdbsdk.RoleNameOperator, qrdbsdk.RoleNameUser},
	{adminv1.AdminService_DisableAccount_FullMethodName, auth.ResourceACMEAccounts, auth.ActionDisable, qrdbsdk.RoleNameAdmin, qrdbsdk.RoleNameOperator},

	{adminv1.AdminService_GetStatus_FullMethodName, auth.ResourceAdmin, auth.ActionStatus, qrdbsdk.RoleNameOperator, unprivilegedRole},
	{adminv1.AdminService_GetStats_FullMethodName, auth.ResourceAdmin, auth.ActionStatus, qrdbsdk.RoleNameOperator, unprivilegedRole},
}

// TestUnaryAuthorizationInterceptor_RequestsExactPermission verifies each method
// asks the authorizer for exactly the resource:action its table entry declares.
func TestUnaryAuthorizationInterceptor_RequestsExactPermission(t *testing.T) {
	for _, tc := range grpcAuthzCases {
		t.Run(tc.method, func(t *testing.T) {
			gate, client := newTestGate()
			interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

			ctx := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "tester", TenantID: "t1", Roles: []string{tc.allowedRole},
			})

			ran := false
			_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: tc.method}, okHandler(&ran))

			require.NoError(t, err)
			assert.True(t, ran)
			assert.Equal(t, []string{tc.resource + ":" + tc.action}, client.requested)
		})
	}
}

// TestUnaryAuthorizationInterceptor_DeniesWithoutGrant verifies each method is
// refused when the caller's canonical role lacks its grant, and that the
// handler never runs.
func TestUnaryAuthorizationInterceptor_DeniesWithoutGrant(t *testing.T) {
	for _, tc := range grpcAuthzCases {
		t.Run(tc.method, func(t *testing.T) {
			gate, _ := newTestGate()
			interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

			ctx := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "tester", TenantID: "t1", Roles: []string{tc.deniedRole},
			})

			ran := false
			_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: tc.method}, okHandler(&ran))

			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.False(t, ran, "handler must not run on denial")
		})
	}
}

// TestUnaryAuthorizationInterceptor_TCPWithoutIdentityIsDenied is the fail-open
// regression test. The previous interceptor passed every call with no peer
// credentials — that is, every TCP call — straight to the handler, on the
// assumption that "TLS client certificate authentication handles authorization
// at a different layer". No such layer existed.
func TestUnaryAuthorizationInterceptor_TCPWithoutIdentityIsDenied(t *testing.T) {
	gate, _ := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	for _, method := range []string{
		adminv1.AdminService_DeleteTenant_FullMethodName,
		adminv1.AdminService_RevokeCertificate_FullMethodName,
		adminv1.AdminService_CreateTenantUser_FullMethodName,
		adminv1.AdminService_ListCertificates_FullMethodName,
	} {
		t.Run(method, func(t *testing.T) {
			ran := false
			_, err := interceptor(context.Background(), nil,
				&grpc.UnaryServerInfo{FullMethod: method}, okHandler(&ran))

			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
			assert.False(t, ran)
		})
	}
}

// TestUnaryAuthorizationInterceptor_UnixPeerCredentialsResolveIdentity verifies
// a Unix-socket caller's kernel-reported credentials are mapped to canonical
// qrdb roles and evaluated by the authorizer.
func TestUnaryAuthorizationInterceptor_UnixPeerCredentialsResolveIdentity(t *testing.T) {
	gate, client := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	// root -> admin, which holds certs:revoke.
	ctx := context.WithValue(context.Background(), peerCredentialsKey{},
		&PeerCredentials{PID: 1, UID: 0, GID: 0})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_RevokeCertificate_FullMethodName}, okHandler(&ran))

	require.NoError(t, err)
	assert.True(t, ran)
	assert.Equal(t, []string{"certs:revoke"}, client.requested)
}

// TestUnaryAuthorizationInterceptor_UnmappedPeerIsDenied verifies a local peer
// that matches no role mapping entry reaches nothing.
func TestUnaryAuthorizationInterceptor_UnmappedPeerIsDenied(t *testing.T) {
	gate, _ := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	ctx := context.WithValue(context.Background(), peerCredentialsKey{},
		&PeerCredentials{PID: 2, UID: 4242, GID: 4242})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_ListCertificates_FullMethodName}, okHandler(&ran))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, ran)
}

// TestUnaryAuthorizationInterceptor_UnmappedMethodIsDenied verifies a method
// with no permission mapping is denied rather than admitted. The previous
// interceptor defaulted an unlisted method to the viewer role and served it.
func TestUnaryAuthorizationInterceptor_UnmappedMethodIsDenied(t *testing.T) {
	gate, client := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "root", TenantID: "", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/admin.v1.AdminService/SomeFutureMethod"}, okHandler(&ran))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), admin.ErrOperationUnmapped.Error())
	assert.False(t, ran)
	assert.Empty(t, client.requested, "an unmapped method must not reach the authorizer")
}

// TestUnaryAuthorizationInterceptor_RealFullMethodIsAuthorized is the go-xkms#743
// regression: the hand-kept method table used to be keyed by
// "/admin.v1.AdminService/..." literals, but the FullMethod a real gRPC call carries is
// "/trustedca.admin.v1.AdminService/..." (the generated
// adminv1.AdminService_RevokeCertificate_FullMethodName). With the stale
// literal keys every admin gRPC call was denied regardless of the caller's
// role, because info.FullMethod never matched a table entry. This test drives
// the interceptor with the actual generated constant, not a hand-typed
// string, so a regression to the wrong key space fails here.
func TestUnaryAuthorizationInterceptor_RealFullMethodIsAuthorized(t *testing.T) {
	const wrongLegacyKey = "/admin.v1.AdminService/RevokeCertificate"
	require.NotEqual(t, wrongLegacyKey, adminv1.AdminService_RevokeCertificate_FullMethodName,
		"the generated FullMethodName must differ from the retired literal key space")

	gate, client := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "tester", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_RevokeCertificate_FullMethodName}, okHandler(&ran))

	require.NoError(t, err)
	assert.True(t, ran)
	assert.Equal(t, []string{"certs:revoke"}, client.requested)
}

// TestUnaryAuthorizationInterceptor_RealServiceUnknownMethodIsDenied verifies
// that a FullMethod on the real "trustedca.admin.v1.AdminService" service
// name, but naming a method the service does not implement, is still denied
// rather than admitted.
func TestUnaryAuthorizationInterceptor_RealServiceUnknownMethodIsDenied(t *testing.T) {
	gate, client := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "root", TenantID: "", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/trustedca.admin.v1.AdminService/SomeFutureMethod"}, okHandler(&ran))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, err.Error(), admin.ErrOperationUnmapped.Error())
	assert.False(t, ran)
	assert.Empty(t, client.requested, "an unmapped method must not reach the authorizer")
}

// TestUnaryAuthorizationInterceptor_NilRoleMappingUsesDefaults verifies the
// constructor substitutes the default mapping rather than leaving a nil deref
// or an implicit allow.
func TestUnaryAuthorizationInterceptor_NilRoleMappingUsesDefaults(t *testing.T) {
	gate, _ := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(nil, gate, nil)

	ctx := context.WithValue(context.Background(), peerCredentialsKey{},
		&PeerCredentials{PID: 1, UID: 0, GID: 0})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_ListCertificates_FullMethodName}, okHandler(&ran))

	require.NoError(t, err)
	assert.True(t, ran)
}

// TestUnaryAuthorizationInterceptor_NilGateDenies verifies an unwired gate fails
// closed rather than serving the whole admin surface.
func TestUnaryAuthorizationInterceptor_NilGateDenies(t *testing.T) {
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), nil, testLogger())

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "root", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_ListCertificates_FullMethodName}, okHandler(&ran))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, ran)
}

// TestUnaryAuthorizationInterceptor_HandlerErrorPropagates verifies an
// authorized call's handler error is returned unchanged.
func TestUnaryAuthorizationInterceptor_HandlerErrorPropagates(t *testing.T) {
	gate, _ := newTestGate()
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "root", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	sentinel := errors.New("handler failed")
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_ListCertificates_FullMethodName},
		func(context.Context, interface{}) (interface{}, error) { return nil, sentinel })

	require.ErrorIs(t, err, sentinel)
}

// TestUnaryAuthorizationInterceptor_QRDBAdminReachesGRPCSurface is the
// unification regression on the gRPC transport: a caller holding qrdb's
// canonical admin role reaches the ACME admin gRPC methods an Admin should
// reach, and revoking that role removes access.
func TestUnaryAuthorizationInterceptor_QRDBAdminReachesGRPCSurface(t *testing.T) {
	// SO-exclusive role mutation stays with the Security Officer.
	soOnly := map[string]bool{
		adminv1.AdminService_CreateTenantRole_FullMethodName: true,
		adminv1.AdminService_UpdateTenantRole_FullMethodName: true,
		adminv1.AdminService_DeleteTenantRole_FullMethodName: true,
	}

	for method := range adminRPCPermissions {
		if soOnly[method] {
			continue
		}
		t.Run(method, func(t *testing.T) {
			gate, _ := newTestGate()
			interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

			granted := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "someone", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAdmin},
			})
			ran := false
			_, err := interceptor(granted, nil, &grpc.UnaryServerInfo{FullMethod: method}, okHandler(&ran))
			require.NoError(t, err, "qrdb admin must reach %s", method)
			assert.True(t, ran)

			revoked := auth.WithIdentity(context.Background(), &auth.Identity{
				Subject: "someone", TenantID: "t1", Roles: nil,
			})
			ran = false
			_, err = interceptor(revoked, nil, &grpc.UnaryServerInfo{FullMethod: method}, okHandler(&ran))
			require.Error(t, err, "revoking the role must remove access to %s", method)
			assert.False(t, ran)
		})
	}
}

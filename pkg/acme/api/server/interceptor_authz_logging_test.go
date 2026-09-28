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
	"bytes"
	"context"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// bufferedGRPCGate returns a PermissionGate whose logger writes to buf,
// together with the recording RBAC client behind it.
func bufferedGRPCGate(buf *bytes.Buffer) (*admin.PermissionGate, *qrdbRoleRBAC) {
	client := &qrdbRoleRBAC{}
	logger := slog.New(slog.NewTextHandler(buf, nil))
	return admin.NewPermissionGate(auth.NewAuthorizer(client), logger), client
}

// TestUnaryAuthorizationInterceptor_LogsDenialCause is the go-xkms#1110
// regression on the gRPC admin transport: a denial is logged server-side with
// the identity, the requested grant, the full gRPC method, and the
// authorizer's cause, while the status the caller receives stays the fixed,
// generic message it always returned — it never carries the cause.
func TestUnaryAuthorizationInterceptor_LogsDenialCause(t *testing.T) {
	var buf bytes.Buffer
	gate, _ := bufferedGRPCGate(&buf)
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "tester", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAuditor},
	})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_RevokeCertificate_FullMethodName},
		okHandler(&ran))

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, ran)

	logs := buf.String()
	assert.Contains(t, logs, "ACME admin authorization denied")
	assert.Contains(t, logs, "subject=tester")
	assert.Contains(t, logs, "tenant=t1")
	assert.Contains(t, logs, "resource="+auth.ResourceCerts)
	assert.Contains(t, logs, "action="+auth.ActionRevoke)
	assert.Contains(t, logs, "method="+adminv1.AdminService_RevokeCertificate_FullMethodName)
	assert.Contains(t, logs, "error=\""+errTestDenied.Error()+"\"")

	assert.NotContains(t, status.Convert(err).Message(), errTestDenied.Error(),
		"the client-facing gRPC status must not carry the authorizer's cause")
}

// TestUnaryAuthorizationInterceptor_AllowedDoesNotLogDenial verifies a
// granted call never emits a denial log line.
func TestUnaryAuthorizationInterceptor_AllowedDoesNotLogDenial(t *testing.T) {
	var buf bytes.Buffer
	gate, _ := bufferedGRPCGate(&buf)
	interceptor := UnaryAuthorizationInterceptor(DefaultRoleMapping(), gate, testLogger())

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "tester", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	ran := false
	_, err := interceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: adminv1.AdminService_RevokeCertificate_FullMethodName},
		okHandler(&ran))

	require.NoError(t, err)
	assert.True(t, ran)
	assert.NotContains(t, buf.String(), "authorization denied")
	assert.NotContains(t, buf.String(), "authorization failed")
}

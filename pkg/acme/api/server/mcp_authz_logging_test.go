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

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// newBufferedAuthzTestServer is newAuthzTestServer, except the gate's logger
// writes to buf so a test can assert on the captured denial log line.
func newBufferedAuthzTestServer(t *testing.T, buf *bytes.Buffer) (*MultiProtocolServer, *qrdbRoleRBAC) {
	t.Helper()

	client := &qrdbRoleRBAC{}
	gate := admin.NewPermissionGate(auth.NewAuthorizer(client), slog.New(slog.NewTextHandler(buf, nil)))
	s := &MultiProtocolServer{
		config: DefaultConfig(),
		logger: testLogger(),
		gate:   gate,
	}
	s.initMCPHandlers()
	return s, client
}

// TestAuthorizeMCPMethod_LogsDenialCause is the go-xkms#1110 regression on the
// MCP admin transport: a denial is logged server-side with the identity, the
// requested grant, the JSON-RPC method, and the authorizer's cause. The
// function's returned error is exactly the authorizer's error, unchanged from
// before this logging was added, so the JSON-RPC response handleMCP builds
// from it is unaffected by this change.
func TestAuthorizeMCPMethod_LogsDenialCause(t *testing.T) {
	var buf bytes.Buffer
	s, _ := newBufferedAuthzTestServer(t, &buf)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "tester", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAuditor},
	})

	err := s.authorizeMCPMethod(ctx, "admin.revokeCertificate")
	require.Error(t, err)
	assert.ErrorIs(t, err, errTestDenied, "the returned error must be exactly the authorizer's error")

	logs := buf.String()
	assert.Contains(t, logs, "ACME admin authorization denied")
	assert.Contains(t, logs, "subject=tester")
	assert.Contains(t, logs, "tenant=t1")
	assert.Contains(t, logs, "resource="+auth.ResourceCerts)
	assert.Contains(t, logs, "action="+auth.ActionRevoke)
	assert.Contains(t, logs, "method=admin.revokeCertificate")
	assert.Contains(t, logs, "error=\""+errTestDenied.Error()+"\"")
}

// TestAuthorizeMCPMethod_AllowedDoesNotLogDenial verifies a granted MCP call
// never emits a denial log line.
func TestAuthorizeMCPMethod_AllowedDoesNotLogDenial(t *testing.T) {
	var buf bytes.Buffer
	s, _ := newBufferedAuthzTestServer(t, &buf)

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		Subject: "tester", TenantID: "t1", Roles: []string{qrdbsdk.RoleNameAdmin},
	})

	require.NoError(t, s.authorizeMCPMethod(ctx, "admin.revokeCertificate"))
	assert.NotContains(t, buf.String(), "authorization denied")
	assert.NotContains(t, buf.String(), "authorization failed")
}

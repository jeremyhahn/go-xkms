//go:build codec_json

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

package admin

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// bufferedGate returns a PermissionGate whose logger writes to buf, together
// with the recording RBAC client behind it, so a test can assert on both the
// captured log output and the authorization outcome.
func bufferedGate(buf *bytes.Buffer) (*PermissionGate, *qrdbRoleRBAC) {
	client := &qrdbRoleRBAC{}
	logger := slog.New(slog.NewTextHandler(buf, nil))
	return NewPermissionGate(auth.NewAuthorizer(client), logger), client
}

// TestPermissionGate_WrapLogsDenialCause is the go-xkms#1110 regression on the
// REST admin transport: a denial is logged server-side with the identity, the
// requested grant, the HTTP method/path, and the authorizer's cause, while the
// response body the caller receives stays the fixed, generic detail string —
// it never carries the cause.
func TestPermissionGate_WrapLogsDenialCause(t *testing.T) {
	var buf bytes.Buffer
	gate, _ := bufferedGate(&buf)

	served := false
	h := gate.Wrap(auth.ResourceACMEEAB, auth.ActionCreate, func(w http.ResponseWriter, r *http.Request) {
		served = true
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/tenant-a/eab", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identityWithRoles("tenant-a", qrdbsdk.RoleNameUser)))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, served, "the handler must not run on denial")

	logs := buf.String()
	assert.Contains(t, logs, "ACME admin authorization denied")
	assert.Contains(t, logs, "subject=test-subject")
	assert.Contains(t, logs, "tenant=tenant-a")
	assert.Contains(t, logs, "resource="+auth.ResourceACMEEAB)
	assert.Contains(t, logs, "action="+auth.ActionCreate)
	assert.Contains(t, logs, "method=POST")
	assert.Contains(t, logs, "path=/api/v1/tenants/tenant-a/eab")
	assert.Contains(t, logs, "error=\""+errTestDenied.Error()+"\"")

	body := rec.Body.String()
	assert.NotContains(t, body, errTestDenied.Error(), "the client response must not carry the authorizer's cause")
	assert.Contains(t, body, "Access denied: insufficient permissions")
}

// TestPermissionGate_WrapAllowedDoesNotLogDenial verifies a granted request
// never emits a denial log line — only the Debug-level "granted" line, which a
// production logger configured at Warn or above will not even emit.
func TestPermissionGate_WrapAllowedDoesNotLogDenial(t *testing.T) {
	var buf bytes.Buffer
	gate, _ := bufferedGate(&buf)

	served := false
	h := gate.Wrap(auth.ResourceACMEEAB, auth.ActionCreate, func(w http.ResponseWriter, r *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/tenant-a/eab", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identityWithRoles("tenant-a", qrdbsdk.RoleNameAdmin)))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, served)
	assert.NotContains(t, buf.String(), "authorization denied")
	assert.NotContains(t, buf.String(), "authorization failed")
}

// TestPermissionGate_AuthorizeLogsUnauthenticatedCause verifies the
// no-identity path also carries the caller's transport context (method/path)
// into the log line, matching the denied-with-identity path.
func TestPermissionGate_AuthorizeLogsUnauthenticatedCause(t *testing.T) {
	var buf bytes.Buffer
	gate, _ := bufferedGate(&buf)

	err := gate.Authorize(context.Background(), auth.ResourceCerts, auth.ActionList,
		slog.String("method", "GET"), slog.String("path", "/api/v1/certificates"))
	require.ErrorIs(t, err, auth.ErrUnauthenticated)

	logs := buf.String()
	assert.Contains(t, logs, "ACME admin authorization failed: no identity on request")
	assert.Contains(t, logs, "method=GET")
	assert.Contains(t, logs, "path=/api/v1/certificates")
}

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build qrdb_vlog

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tlogtest"
)

const appendCaller = "spiffe://acme/svc/billing"

// newAppendLog returns a real, empty transparency log.
func newAppendLog(t *testing.T) *tlogtest.Fixture {
	t.Helper()
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	return tlogtest.New(t, ca.Key, ca.Cert)
}

// newAppendServer returns an MCP server, RBAC disabled, whose xkms service
// appends to log; a nil log leaves the service without one.
func newAppendServer(t *testing.T, log *tlog.Log) *Server {
	t.Helper()
	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)
	if log != nil {
		svc.SetTransparencyLog(log)
	}
	s, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)
	return s
}

// appendAs invokes xkms.ca.transparency-log.append with payload for a
// system-tenant identity holding roles (none: ctx's own principal), over a mutual TLS connection whose
// verified client certificate carries uris; no uris means no TLS at all.
func appendAs(t *testing.T, ctx context.Context, s *Server, payload []byte, roles []string, uris ...string) *JSONRPCResponse {
	t.Helper()
	if roles != nil {
		ctx = auth.WithIdentity(ctx, &auth.Identity{Subject: "caller", TenantID: qrdbsdk.SystemTenantID, Roles: roles})
	}
	if uris != nil {
		state, err := testutil.VerifiedClientState(uris...)
		require.NoError(t, err)
		ctx = auth.WithTLSState(ctx, state)
	}
	params, err := json.Marshal(transport.AppendTransparencyLogExternalRequest{Payload: payload})
	require.NoError(t, err)
	return invokeRequest(s, ctx, &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.ca.transparency-log.append", Params: params, ID: 1})
}

func TestTransparencyLogAppend_RecordsTheCallersSPIFFEID(t *testing.T) {
	f := newAppendLog(t)
	s := newAppendServer(t, f.Log)

	resp := appendAs(t, f.Ctx, s, []byte("invoice 7"), nil, "https://acme.example/profile", appendCaller)
	require.Nil(t, resp.Error)
	appended, ok := resp.Result.(*transport.AppendTransparencyLogExternalResponse)
	require.True(t, ok, "result %T", resp.Result)
	require.Equal(t, uint64(0), appended.Index, "the first entry of an empty log")

	tlogtest.RequireOneEntry(f.Ctx, t, f.Log, appended.Index, tlog.External{SPIFFEID: appendCaller, Payload: []byte("invoice 7")})
}

func TestTransparencyLogAppend_NoLogIsServiceUnavailable(t *testing.T) {
	f := newAppendLog(t)
	s := newAppendServer(t, nil)

	resp := appendAs(t, f.Ctx, s, []byte("invoice 7"), nil, appendCaller)
	require.NotNil(t, resp.Error)
	require.Equal(t, ErrCodeServiceUnavailable, resp.Error.Code, resp.Error.Message)
}

// The unauthenticated class has no JSON-RPC member of its own: it renders
// as invalid params (classToJSONRPCCode), and the log records nothing.
func TestTransparencyLogAppend_NoSPIFFEIDIsRefused(t *testing.T) {
	f := newAppendLog(t)
	s := newAppendServer(t, f.Log)

	tests := map[string][]string{
		"no TLS":            nil,
		"no SPIFFE ID":      {"https://acme.example/profile"},
		"two SPIFFE IDs":    {appendCaller, "spiffe://acme/svc/payroll"},
		"no URI SAN at all": {},
	}
	for name, uris := range tests {
		t.Run(name, func(t *testing.T) {
			resp := appendAs(t, f.Ctx, s, []byte("invoice 7"), nil, uris...)
			require.NotNil(t, resp.Error)
			require.Equal(t, ErrCodeInvalidParams, resp.Error.Code, resp.Error.Message)
		})
	}
	require.Equal(t, uint64(0), tlogtest.Size(f.Ctx, t, f.Log), "a refused append records nothing")
}

func TestTransparencyLogAppend_InvalidPayloadIsInvalidParams(t *testing.T) {
	f := newAppendLog(t)
	s := newAppendServer(t, f.Log)

	tests := map[string][]byte{
		"empty":     nil,
		"oversized": make([]byte, 1<<16),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			resp := appendAs(t, f.Ctx, s, payload, nil, appendCaller)
			require.NotNil(t, resp.Error)
			require.Equal(t, ErrCodeInvalidParams, resp.Error.Code, resp.Error.Message)
		})
	}
	require.Equal(t, uint64(0), tlogtest.Size(f.Ctx, t, f.Log), "a refused append records nothing")
}

// go-qrdb seeds vlog:append on the User role and not on the Auditor role.
// On a seeded node whose service has no log, an Auditor is refused at the
// gate, and a User passes it and reaches the service, which reports the
// missing log.
func TestTransparencyLogAppend_SeededRolePlacement(t *testing.T) {
	s, n := newSeededRBACServer(t)
	userID, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameUser)
	require.NoError(t, err)
	auditorID, err := n.RoleID(qrdbsdk.SystemTenantID, qrdbsdk.RoleNameAuditor)
	require.NoError(t, err)

	resp := appendAs(t, context.Background(), s, []byte("invoice 7"), []string{auditorID}, appendCaller)
	require.NotNil(t, resp.Error)
	require.Equal(t, ErrCodeForbidden, resp.Error.Code, "an Auditor does not hold vlog:append")

	resp = appendAs(t, context.Background(), s, []byte("invoice 7"), []string{userID}, appendCaller)
	require.NotNil(t, resp.Error, "the fixture has no log, so an admitted request fails in the servicer")
	require.Equal(t, ErrCodeServiceUnavailable, resp.Error.Code, "a User holds vlog:append: %s", resp.Error.Message)
}

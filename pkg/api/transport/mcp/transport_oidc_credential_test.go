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

package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
)

// TestOIDCCredential_CallsTheTool proves the OIDC credential methods call
// their oidc.credential.* tools with the request as parameters and decode
// the result: the reference's tenant, scope, owner and name reach the
// server.
func TestOIDCCredential_CallsTheTool(t *testing.T) {
	addr, cleanup := newCatchAllMCPServer(t)
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()
	ctx := context.Background()
	ref := &transport.OIDCCredentialRef{TenantID: "acme", Scope: transport.OIDCCredentialScopeUser, Owner: "alice", Name: "codex"}

	c, err := tr.OIDCCredentialGet(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, *ref, c.OIDCCredentialRef)
	assert.Equal(t, transport.OIDCCredentialStatusActive, c.Status)

	tok, err := tr.OIDCCredentialGetAccessToken(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "at-alice", tok.AccessToken)

	for name, call := range oidccredentialtest.Calls(ctx, tr) {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, call(), "every method reaches its tool")
		})
	}
}

// TestOIDCCredential_ToolErrorReachesTheCaller proves a tool's error result
// is the method's error.
func TestOIDCCredential_ToolErrorReachesTheCaller(t *testing.T) {
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if strings.HasPrefix(req.Method, "oidc.credential.") {
			return jsonrpcResponse{ErrorText: "oidc credential: not found"}
		}
		return jsonrpcResponse{Result: json.RawMessage(`{"status":"ok","version":"1.0.0"}`)}
	})
	defer cleanup()
	tr := connectToMockServer(t, addr)
	defer tr.Close()

	_, err := tr.OIDCCredentialRefresh(context.Background(), &transport.OIDCCredentialRef{Scope: "tenant", Name: "ci"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	assert.Error(t, tr.OIDCCredentialDelete(context.Background(), &transport.OIDCCredentialRef{Scope: "tenant", Name: "ci"}))
}

// TestOIDCCredential_NotConnected proves every OIDC credential method
// refuses before it is connected.
func TestOIDCCredential_NotConnected(t *testing.T) {
	for name, call := range oidccredentialtest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}

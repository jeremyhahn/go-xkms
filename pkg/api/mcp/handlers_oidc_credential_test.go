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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest/offline"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// newOIDCCredentialMCP returns a Server whose XKMSService has a credential
// service holding the barriers of tenants acme and globex.
func newOIDCCredentialMCP(t *testing.T) *Server {
	t.Helper()
	server := createTestServer(t)
	server.xkmsService.SetOIDCCredentialService(offline.NewService(t, "acme", "globex"))
	return server
}

// invokeOIDC calls method as subject@tenant and decodes its result into
// out.
func invokeOIDC(t *testing.T, s *Server, tenant, subject, method string, params any, out any) error {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: subject, TenantID: tenant, Roles: []string{"admin"}})
	result, err := s.InvokeMethod(ctx, method, raw)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, out))
	return nil
}

// tenantRef names the tenant credential name.
func tenantRef(name string) transport.OIDCCredentialRef {
	return transport.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeTenant, Name: name}
}

// TestOIDCCredentialTools_Lifecycle proves the tools reach the credential
// service in the caller's tenant: a credential is created, listed, read,
// re-imported, serves its access token, and is deleted.
func TestOIDCCredentialTools_Lifecycle(t *testing.T) {
	s := newOIDCCredentialMCP(t)
	ref := tenantRef("ci")

	var created transport.OIDCCredential
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "oidc.credential.create", transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: ref, Config: oidccredentialtest.Config(), Tokens: oidccredentialtest.Tokens("at-0"),
	}, &created))
	assert.Equal(t, "acme", created.TenantID)
	assert.Equal(t, transport.OIDCCredentialStatusActive, created.Status)

	var list transport.OIDCCredentialListResponse
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "oidc.credential.list", transport.OIDCCredentialListRequest{}, &list))
	require.Len(t, list.Credentials, 1)

	var got transport.OIDCCredential
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "oidc.credential.get", ref, &got))
	assert.Equal(t, "ci", got.Name)

	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "oidc.credential.import", transport.OIDCCredentialImportRequest{
		OIDCCredentialRef: ref, Tokens: *oidccredentialtest.Tokens("at-1"),
	}, &got))

	var tok transport.OIDCAccessToken
	require.NoError(t, invokeOIDC(t, s, "acme", "bob", "oidc.credential.token", ref, &tok))
	assert.Equal(t, "at-1", tok.AccessToken)

	var deleted transport.OIDCCredentialRef
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "oidc.credential.delete", ref, &deleted))
	assert.Equal(t, "ci", deleted.Name)

	err := invokeOIDC(t, s, "acme", "alice", "oidc.credential.get", ref, &got)
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
}

// TestOIDCCredentialTools_MapErrors proves the service's errors reach the
// wire with the codes apierrors.OIDCCredentialClassOf assigns.
func TestOIDCCredentialTools_MapErrors(t *testing.T) {
	s := newOIDCCredentialMCP(t)
	var out map[string]any
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "oidc.credential.create", transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: tenantRef("ci"), Config: oidccredentialtest.Config(), Tokens: oidccredentialtest.Tokens("at"),
	}, &out))
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "oidc.credential.create", transport.OIDCCredentialCreateRequest{
		OIDCCredentialRef: transport.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeUser, Name: "mine"},
		Config:            oidccredentialtest.Config(), Tokens: oidccredentialtest.Tokens("at"),
	}, &out))
	// A failed precondition -- the credential's state refuses the call -- is
	// ErrCodeInternalError on this transport (wireExpectationForClass).
	failedPrecondition := ErrCodeInternalError

	tests := []struct {
		name, method string
		params       any
		code         int
	}{
		{"malformed params", "oidc.credential.get", "not an object", ErrCodeInvalidParams},
		{"invalid scope", "oidc.credential.get", transport.OIDCCredentialRef{Scope: "galaxy", Name: "ci"}, ErrCodeInvalidParams},
		{"no issuer", "oidc.credential.create", transport.OIDCCredentialCreateRequest{OIDCCredentialRef: tenantRef("x")}, ErrCodeInvalidParams},
		{"duplicate", "oidc.credential.create", transport.OIDCCredentialCreateRequest{OIDCCredentialRef: tenantRef("ci"), Config: oidccredentialtest.Config()}, sdkssh.JSONRPCCodeDuplicate},
		{"unknown", "oidc.credential.refresh", tenantRef("missing"), sdkssh.JSONRPCCodeNotFound},
		{"empty tokens", "oidc.credential.import", transport.OIDCCredentialImportRequest{OIDCCredentialRef: tenantRef("ci")}, ErrCodeInvalidParams},
		{"not refreshable", "oidc.credential.refresh", tenantRef("ci"), failedPrecondition},
		{"no device login", "oidc.credential.device.poll", tenantRef("ci"), failedPrecondition},
		{"device login without endpoints", "oidc.credential.device.start", tenantRef("ci"), ErrCodeInvalidParams},
		{"another user's credential", "oidc.credential.token", transport.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeUser, Owner: "alice", Name: "mine"}, ErrCodeForbidden},
		{"another tenant", "oidc.credential.list", transport.OIDCCredentialListRequest{TenantID: "globex"}, ErrCodeForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := invokeOIDC(t, s, "acme", "bob", tt.method, tt.params, &out)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code, "%v", err)
		})
	}
}

// TestOIDCCredentialTools_WithoutTheService proves every tool answers "not
// configured" on a server with no credential service.
func TestOIDCCredentialTools_WithoutTheService(t *testing.T) {
	s := createTestServer(t)
	for _, method := range []string{
		"oidc.credential.create", "oidc.credential.import", "oidc.credential.get",
		"oidc.credential.list", "oidc.credential.delete", "oidc.credential.refresh",
		"oidc.credential.token", "oidc.credential.device.start", "oidc.credential.device.poll",
	} {
		t.Run(method, func(t *testing.T) {
			var out map[string]any
			err := invokeOIDC(t, s, "acme", "alice", method, tenantRef("ci"), &out)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
		})
	}
}

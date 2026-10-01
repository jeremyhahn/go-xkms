// Copyright (c) 2026 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package wire

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestOIDCCredentialClient_Routes proves every method sends its request to
// the route the server registers: the method, the path (scope and name
// escaped into it), the tenant and owner in the query, and the body.
func TestOIDCCredentialClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := OIDCCredentialClient{Do: rec.do}
	ctx := context.Background()
	ref := transport.OIDCCredentialRef{TenantID: "acme", Scope: "user", Owner: "alice", Name: "a b"}
	expires := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		call   func() error
		method string
		path   string
		body   map[string]any
	}{
		{"create", func() error {
			_, err := c.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{
				OIDCCredentialRef: transport.OIDCCredentialRef{Scope: "tenant", Name: "ci"},
				Config:            transport.OIDCCredentialConfig{Template: "github"},
			})
			return err
		}, http.MethodPost, "/api/v1/oidc/credentials", map[string]any{
			"scope": "tenant", "name": "ci", "config": map[string]any{"template": "github"},
		}},
		{"import", func() error {
			_, err := c.OIDCCredentialImport(ctx, &transport.OIDCCredentialImportRequest{
				OIDCCredentialRef: ref,
				Tokens:            transport.OIDCCredentialTokens{AccessToken: "at", ExpiresAt: &expires},
			})
			return err
		}, http.MethodPost, "/api/v1/oidc/credentials/user/a%20b/import?owner=alice&tenant_id=acme", map[string]any{
			"tokens": map[string]any{"access_token": "at", "expires_at": "2026-09-30T12:00:00Z"},
		}},
		{"get", func() error { _, err := c.OIDCCredentialGet(ctx, &ref); return err },
			http.MethodGet, "/api/v1/oidc/credentials/user/a%20b?owner=alice&tenant_id=acme", nil},
		{"list", func() error {
			_, err := c.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{TenantID: "acme"})
			return err
		}, http.MethodGet, "/api/v1/oidc/credentials?tenant_id=acme", nil},
		{"delete", func() error {
			return c.OIDCCredentialDelete(ctx, &transport.OIDCCredentialRef{Scope: "tenant", Name: "ci"})
		}, http.MethodDelete, "/api/v1/oidc/credentials/tenant/ci", nil},
		{"refresh", func() error { _, err := c.OIDCCredentialRefresh(ctx, &ref); return err },
			http.MethodPost, "/api/v1/oidc/credentials/user/a%20b/refresh?owner=alice&tenant_id=acme", nil},
		{"token", func() error { _, err := c.OIDCCredentialGetAccessToken(ctx, &ref); return err },
			http.MethodPost, "/api/v1/oidc/credentials/user/a%20b/token?owner=alice&tenant_id=acme", nil},
		{"device start", func() error { _, err := c.OIDCCredentialDeviceStart(ctx, &ref); return err },
			http.MethodPost, "/api/v1/oidc/credentials/user/a%20b/device?owner=alice&tenant_id=acme", nil},
		{"device poll", func() error { _, err := c.OIDCCredentialDevicePoll(ctx, &ref); return err },
			http.MethodPost, "/api/v1/oidc/credentials/user/a%20b/device/poll?owner=alice&tenant_id=acme", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.call())
			got := rec.last()
			assert.Equal(t, tt.method, got.method)
			assert.Equal(t, tt.path, got.path)
			assert.Equal(t, tt.body, got.body)
		})
	}
}

// TestOIDCCredentialClient_DecodesResponses proves the server's JSON answer
// is decoded into the method's transport type.
func TestOIDCCredentialClient_DecodesResponses(t *testing.T) {
	rec := &recordingRequester{response: `{"tenant_id":"acme","scope":"tenant","name":"ci","config":{"issuer":"https://idp"},"status":"active","refreshable":true}`}
	c := OIDCCredentialClient{Do: rec.do}
	ref := &transport.OIDCCredentialRef{Scope: "tenant", Name: "ci"}
	got, err := c.OIDCCredentialGet(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, &transport.OIDCCredential{
		OIDCCredentialRef: transport.OIDCCredentialRef{TenantID: "acme", Scope: "tenant", Name: "ci"},
		Config:            transport.OIDCCredentialConfig{Issuer: "https://idp"},
		Status:            transport.OIDCCredentialStatusActive,
		Refreshable:       true,
	}, got)

	rec.response = `{"access_token":"at","token_type":"Bearer","id_token":"idt"}`
	tok, err := c.OIDCCredentialGetAccessToken(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, &transport.OIDCAccessToken{AccessToken: "at", TokenType: "Bearer", IDToken: "idt"}, tok)

	rec.response = `{"credentials":[{"scope":"tenant","name":"ci"}]}`
	list, err := c.OIDCCredentialList(context.Background(), &transport.OIDCCredentialListRequest{})
	require.NoError(t, err)
	require.Len(t, list.Credentials, 1)
	assert.Equal(t, "ci", list.Credentials[0].Name)
}

// TestOIDCCredentialClient_Failures proves a request failure passes through,
// an undecodable answer is a *DecodeError naming the path, and a nil request
// is refused without a request.
func TestOIDCCredentialClient_Failures(t *testing.T) {
	ctx := context.Background()
	ref := &transport.OIDCCredentialRef{Scope: "tenant", Name: "ci"}

	failing := OIDCCredentialClient{Do: (&recordingRequester{err: errRequestFailed}).do}
	_, err := failing.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{})
	require.ErrorIs(t, err, errRequestFailed)
	require.ErrorIs(t, failing.OIDCCredentialDelete(ctx, ref), errRequestFailed)
	_, err = failing.OIDCCredentialGetAccessToken(ctx, ref)
	require.ErrorIs(t, err, errRequestFailed)

	garbled := OIDCCredentialClient{Do: (&recordingRequester{response: "not json"}).do}
	_, err = garbled.OIDCCredentialRefresh(ctx, ref)
	var decodeErr *DecodeError
	require.ErrorAs(t, err, &decodeErr)
	assert.Equal(t, "/api/v1/oidc/credentials/tenant/ci/refresh", decodeErr.Path)

	rec := &recordingRequester{}
	c := OIDCCredentialClient{Do: rec.do}
	nilCalls := map[string]error{
		"create":       func() error { _, err := c.OIDCCredentialCreate(ctx, nil); return err }(),
		"import":       func() error { _, err := c.OIDCCredentialImport(ctx, nil); return err }(),
		"get":          func() error { _, err := c.OIDCCredentialGet(ctx, nil); return err }(),
		"list":         func() error { _, err := c.OIDCCredentialList(ctx, nil); return err }(),
		"delete":       c.OIDCCredentialDelete(ctx, nil),
		"refresh":      func() error { _, err := c.OIDCCredentialRefresh(ctx, nil); return err }(),
		"token":        func() error { _, err := c.OIDCCredentialGetAccessToken(ctx, nil); return err }(),
		"device start": func() error { _, err := c.OIDCCredentialDeviceStart(ctx, nil); return err }(),
		"device poll":  func() error { _, err := c.OIDCCredentialDevicePoll(ctx, nil); return err }(),
	}
	for name, err := range nilCalls {
		assert.ErrorIs(t, err, ErrNilRequest, name)
	}
	assert.Empty(t, rec.requests, "a nil request sends nothing")
}

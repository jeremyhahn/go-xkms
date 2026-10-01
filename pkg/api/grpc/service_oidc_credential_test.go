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

package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// errOIDCUnclassified stands in for an error no table classifies.
var errOIDCUnclassified = errors.New("test: unclassified")

// oidcRevokedRefreshToken is the refresh token the fake provider rejects
// with invalid_grant: the login must be redone.
const oidcRevokedRefreshToken = "rt-revoked"

// newOIDCProvider serves the token and device endpoints of an OAuth
// provider that grants every device login at once, rotates every refresh
// token but oidcRevokedRefreshToken, and returns its base URL.
func newOIDCProvider(t *testing.T) string {
	t.Helper()
	var srv *httptest.Server
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		assert.NoError(t, json.NewEncoder(w).Encode(v))
	}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			reply(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		switch {
		case r.URL.Path == "/device":
			reply(w, http.StatusOK, map[string]any{
				"device_code": "dev-1", "user_code": "USER-CODE",
				"verification_uri": srv.URL + "/activate", "expires_in": 600, "interval": 1,
			})
		case r.URL.Path == "/token" && r.PostForm.Get("refresh_token") == oidcRevokedRefreshToken:
			reply(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		case r.URL.Path == "/token":
			reply(w, http.StatusOK, map[string]any{
				"access_token": "at-" + r.PostForm.Get("grant_type"), "refresh_token": "rt-next",
				"id_token": "id-1", "token_type": "Bearer", "expires_in": 3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// newOIDCCredentialGRPC returns a Service over an XKMSService whose OIDC
// credential service holds the barriers of tenants acme and globex and
// reaches the fake provider, and that provider's base URL.
func newOIDCCredentialGRPC(t *testing.T) (*Service, string) {
	t.Helper()
	registry := barriertest.NewRegistry(t)
	barriertest.RegisterTenant(t, registry, "acme")
	barriertest.RegisterTenant(t, registry, "globex")
	issuer := newOIDCProvider(t)
	creds, err := credential.New(credential.RegistryBarriers(registry), credential.WithHTTPClient(http.DefaultClient))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, creds.Close()) })
	svc := &xkms.XKMSService{}
	svc.SetOIDCCredentialService(creds)
	return NewService(nil, nil, svc), issuer
}

// oidcProviderConfig configures the fake provider by explicit endpoints, so
// no discovery is needed.
func oidcProviderConfig(issuer string) *pb.OIDCCredentialConfig {
	return &pb.OIDCCredentialConfig{
		Issuer:                      issuer,
		ClientId:                    "client-1",
		Scopes:                      []string{"openid", "offline_access"},
		TokenEndpoint:               issuer + "/token",
		DeviceAuthorizationEndpoint: issuer + "/device",
	}
}

// sharedRef names a tenant-shared credential of the caller's tenant.
func sharedRef(name string) *pb.OIDCCredentialRef {
	return &pb.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeTenant, Name: name}
}

// TestOIDCCredentialRPCs_Lifecycle proves every RPC reaches the credential
// service in the caller's tenant: a credential is created with tokens,
// read, listed, served, refreshed, re-imported, logged in by device and
// deleted.
func TestOIDCCredentialRPCs_Lifecycle(t *testing.T) {
	s, issuer := newOIDCCredentialGRPC(t)
	ctx := platformScopeCtx("acme")
	ref := sharedRef("ci")
	expires := timestamppb.New(time.Now().Add(time.Hour))

	created, err := s.OIDCCredentialCreate(ctx, &pb.OIDCCredentialCreateRequest{
		Ref: ref, Config: oidcProviderConfig(issuer),
		Tokens: &pb.OIDCCredentialTokens{AccessToken: "at-0", RefreshToken: "rt-0", ExpiresAt: expires},
	})
	require.NoError(t, err)
	assert.Equal(t, transport.OIDCCredentialStatusActive, created.GetStatus())
	assert.Equal(t, "acme", created.GetRef().GetTenantId())
	assert.Equal(t, expires.AsTime(), created.GetExpiresAt().AsTime())
	assert.NotNil(t, created.GetCreatedAt())

	got, err := s.OIDCCredentialGet(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "ci", got.GetRef().GetName())
	assert.Empty(t, got.GetConfig().GetClientSecret(), "the view never carries the client secret")

	list, err := s.OIDCCredentialList(ctx, &pb.OIDCCredentialListRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetCredentials(), 1)
	assert.Equal(t, "ci", list.GetCredentials()[0].GetRef().GetName())

	tok, err := s.OIDCCredentialGetAccessToken(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "at-0", tok.GetAccessToken(), "a token outside its margin is served as imported")

	refreshed, err := s.OIDCCredentialRefresh(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, transport.OIDCCredentialStatusActive, refreshed.GetStatus())
	assert.NotNil(t, refreshed.GetLastRefresh())
	tok, err = s.OIDCCredentialGetAccessToken(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "at-refresh_token", tok.GetAccessToken())
	assert.Equal(t, "id-1", tok.GetIdToken())

	imported, err := s.OIDCCredentialImport(ctx, &pb.OIDCCredentialImportRequest{
		Ref: ref, Tokens: &pb.OIDCCredentialTokens{AccessToken: "at-imported", RefreshToken: "rt-1", ExpiresAt: expires},
	})
	require.NoError(t, err)
	assert.Equal(t, transport.OIDCCredentialStatusActive, imported.GetStatus())
	tok, err = s.OIDCCredentialGetAccessToken(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "at-imported", tok.GetAccessToken())

	started, err := s.OIDCCredentialDeviceStart(ctx, ref)
	require.NoError(t, err)
	require.NotNil(t, started.GetDeviceLogin())
	assert.Equal(t, "USER-CODE", started.GetDeviceLogin().GetUserCode())
	polled, err := s.OIDCCredentialDevicePoll(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, transport.OIDCCredentialStatusActive, polled.GetStatus())
	assert.Nil(t, polled.GetDeviceLogin(), "a granted login ends the device flow")

	_, err = s.OIDCCredentialDelete(ctx, ref)
	require.NoError(t, err)
	_, err = s.OIDCCredentialGet(ctx, ref)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestOIDCCredentialRPCs_MapErrors proves the service's errors reach the
// wire with the codes apierrors.OIDCCredentialClassOf assigns.
func TestOIDCCredentialRPCs_MapErrors(t *testing.T) {
	s, issuer := newOIDCCredentialGRPC(t)
	ctx := platformScopeCtx("acme")
	future := timestamppb.New(time.Now().Add(time.Hour))
	_, err := s.OIDCCredentialCreate(ctx, &pb.OIDCCredentialCreateRequest{
		Ref: sharedRef("revoked"), Config: oidcProviderConfig(issuer),
		Tokens: &pb.OIDCCredentialTokens{AccessToken: "at", RefreshToken: oidcRevokedRefreshToken, ExpiresAt: future},
	})
	require.NoError(t, err)
	_, err = s.OIDCCredentialCreate(ctx, &pb.OIDCCredentialCreateRequest{Ref: sharedRef("pending"), Config: oidcProviderConfig(issuer)})
	require.NoError(t, err)

	tests := []struct {
		name string
		call func() error
		code codes.Code
	}{
		{"nil request", func() error { _, err := s.OIDCCredentialGet(ctx, nil); return err }, codes.InvalidArgument},
		{"invalid scope", func() error {
			_, err := s.OIDCCredentialGet(ctx, &pb.OIDCCredentialRef{Scope: "galaxy", Name: "ci"})
			return err
		}, codes.InvalidArgument},
		{"invalid config", func() error {
			_, err := s.OIDCCredentialCreate(ctx, &pb.OIDCCredentialCreateRequest{Ref: sharedRef("bad"), Config: &pb.OIDCCredentialConfig{ClientId: "c"}})
			return err
		}, codes.InvalidArgument},
		{"exists", func() error {
			_, err := s.OIDCCredentialCreate(ctx, &pb.OIDCCredentialCreateRequest{Ref: sharedRef("pending"), Config: oidcProviderConfig(issuer)})
			return err
		}, codes.AlreadyExists},
		{"not found", func() error { _, err := s.OIDCCredentialDelete(ctx, sharedRef("missing")); return err }, codes.NotFound},
		{"relogin required", func() error { _, err := s.OIDCCredentialRefresh(ctx, sharedRef("revoked")); return err }, codes.FailedPrecondition},
		{"no login", func() error { _, err := s.OIDCCredentialGetAccessToken(ctx, sharedRef("pending")); return err }, codes.FailedPrecondition},
		{"no device login", func() error { _, err := s.OIDCCredentialDevicePoll(ctx, sharedRef("pending")); return err }, codes.FailedPrecondition},
		{"another user's credential", func() error {
			_, err := s.OIDCCredentialGet(ctx, &pb.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeUser, Owner: "bob@acme", Name: "ci"})
			return err
		}, codes.PermissionDenied},
		{"another tenant", func() error {
			_, err := s.OIDCCredentialList(ctx, &pb.OIDCCredentialListRequest{TenantId: "globex"})
			return err
		}, codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.code, status.Code(tt.call()))
		})
	}
}

// TestOIDCCredentialRPCs_Unavailable proves the RPCs answer Unavailable on a
// server with no XKMSService, and on one with no credential service wired.
func TestOIDCCredentialRPCs_Unavailable(t *testing.T) {
	ctx := platformScopeCtx("acme")
	for name, s := range map[string]*Service{
		"no service":            NewService(nil, nil, nil),
		"no credential service": NewService(nil, nil, &xkms.XKMSService{}),
	} {
		t.Run(name, func(t *testing.T) {
			for rpc, call := range oidcCredentialRPCs(s) {
				assert.Equal(t, codes.Unavailable, status.Code(call(ctx)), rpc)
			}
		})
	}
}

// TestOIDCCredentialRPCs_PermissionDenied proves every RPC authorizes its
// permission before reaching the service.
func TestOIDCCredentialRPCs_PermissionDenied(t *testing.T) {
	s := newDeniedService()
	for rpc, call := range oidcCredentialRPCs(s) {
		t.Run(rpc, func(t *testing.T) {
			assert.Equal(t, codes.PermissionDenied, status.Code(call(deniedCtx())))
		})
	}
}

// oidcCredentialRPCs calls each OIDC credential RPC of s with a valid
// request.
func oidcCredentialRPCs(s *Service) map[string]func(context.Context) error {
	ref := sharedRef("ci")
	return map[string]func(context.Context) error{
		"OIDCCredentialCreate": func(ctx context.Context) error {
			_, err := s.OIDCCredentialCreate(ctx, &pb.OIDCCredentialCreateRequest{Ref: ref, Config: &pb.OIDCCredentialConfig{Issuer: "https://idp.example"}})
			return err
		},
		"OIDCCredentialImport": func(ctx context.Context) error {
			_, err := s.OIDCCredentialImport(ctx, &pb.OIDCCredentialImportRequest{Ref: ref, Tokens: &pb.OIDCCredentialTokens{AccessToken: "at"}})
			return err
		},
		"OIDCCredentialGet": func(ctx context.Context) error { _, err := s.OIDCCredentialGet(ctx, ref); return err },
		"OIDCCredentialList": func(ctx context.Context) error {
			_, err := s.OIDCCredentialList(ctx, &pb.OIDCCredentialListRequest{})
			return err
		},
		"OIDCCredentialDelete":  func(ctx context.Context) error { _, err := s.OIDCCredentialDelete(ctx, ref); return err },
		"OIDCCredentialRefresh": func(ctx context.Context) error { _, err := s.OIDCCredentialRefresh(ctx, ref); return err },
		"OIDCCredentialGetAccessToken": func(ctx context.Context) error {
			_, err := s.OIDCCredentialGetAccessToken(ctx, ref)
			return err
		},
		"OIDCCredentialDeviceStart": func(ctx context.Context) error {
			_, err := s.OIDCCredentialDeviceStart(ctx, ref)
			return err
		},
		"OIDCCredentialDevicePoll": func(ctx context.Context) error {
			_, err := s.OIDCCredentialDevicePoll(ctx, ref)
			return err
		},
	}
}

// TestMapOIDCCredentialError_Classifies proves the classification of the
// credential service's errors, typed ones included, and that an
// unclassified error is Internal.
func TestMapOIDCCredentialError_Classifies(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{"not found", credential.ErrNotFound, codes.NotFound},
		{"relogin required", credential.ErrReloginRequired, codes.FailedPrecondition},
		{"invalid config", credential.ErrInvalidConfig, codes.InvalidArgument},
		{"config error", &credential.ConfigError{Detail: "an issuer is required"}, codes.InvalidArgument},
		{"transient refresh failure", &credential.RefreshError{Name: "ci", Err: errOIDCUnclassified}, codes.Unavailable},
		{"unclassified", errOIDCUnclassified, codes.Internal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := status.Convert(mapOIDCCredentialError(tt.err))
			assert.Equal(t, tt.code, st.Code())
			assert.Equal(t, tt.err.Error(), st.Message())
		})
	}
}

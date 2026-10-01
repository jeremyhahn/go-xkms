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

package pbconv

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// sampleTime is a UTC time, as a proto timestamp decodes.
var sampleTime = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// sampleRef names a personal credential.
func sampleRef() transport.OIDCCredentialRef {
	return transport.OIDCCredentialRef{TenantID: "acme", Scope: transport.OIDCCredentialScopeUser, Owner: "alice", Name: "codex"}
}

// sampleConfig is a provider configuration with every field set.
func sampleConfig() transport.OIDCCredentialConfig {
	return transport.OIDCCredentialConfig{
		Template:                    "openai",
		Issuer:                      "https://auth.example",
		ClientID:                    "client-1",
		ClientSecret:                "secret",
		Scopes:                      []string{"openid", "offline_access"},
		AuthorizationEndpoint:       "https://auth.example/authorize",
		TokenEndpoint:               "https://auth.example/token",
		DeviceAuthorizationEndpoint: "https://auth.example/device",
		TokenEncoding:               "json",
		DeviceStyle:                 "openai",
		NoRefresh:                   true,
		TokenLifetimeSeconds:        3600,
		RefreshMarginSeconds:        120,
	}
}

// sampleCredential is a credential's view with every field set.
func sampleCredential() *transport.OIDCCredential {
	expires := sampleTime.Add(time.Hour)
	refreshed := sampleTime.Add(-time.Minute)
	return &transport.OIDCCredential{
		OIDCCredentialRef: sampleRef(),
		Config:            sampleConfig(),
		Status:            transport.OIDCCredentialStatusPending,
		StatusReason:      "awaiting approval",
		ExpiresAt:         &expires,
		Refreshable:       true,
		LastRefresh:       &refreshed,
		LastError:         "invalid_grant",
		DeviceLogin: &transport.OIDCDeviceLogin{
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://auth.example/activate",
			VerificationURIComplete: "https://auth.example/activate?code=ABCD-EFGH",
			IntervalSeconds:         5,
			ExpiresAt:               sampleTime.Add(15 * time.Minute),
		},
		CreatedAt: sampleTime,
		UpdatedAt: sampleTime.Add(time.Second),
		CreatedBy: "alice",
	}
}

// TestOIDCCredentialConversions_RoundTrip proves every OIDC credential
// message survives the trip to proto and back unchanged.
func TestOIDCCredentialConversions_RoundTrip(t *testing.T) {
	c := sampleCredential()
	assert.Equal(t, c, OIDCCredentialFromProto(OIDCCredentialToProto(c)))

	ref := sampleRef()
	assert.Equal(t, &ref, OIDCCredentialRefFromProto(OIDCCredentialRefToProto(&ref)))

	expires := sampleTime
	tokens := &transport.OIDCCredentialTokens{AccessToken: "at", RefreshToken: "rt", IDToken: "id", TokenType: "Bearer", Scope: "openid", ExpiresAt: &expires}
	create := &transport.OIDCCredentialCreateRequest{OIDCCredentialRef: ref, Config: sampleConfig(), Tokens: tokens}
	assert.Equal(t, create, OIDCCredentialCreateRequestFromProto(OIDCCredentialCreateRequestToProto(create)))

	imp := &transport.OIDCCredentialImportRequest{OIDCCredentialRef: ref, Tokens: *tokens}
	assert.Equal(t, imp, OIDCCredentialImportRequestFromProto(OIDCCredentialImportRequestToProto(imp)))

	list := &transport.OIDCCredentialListResponse{Credentials: []transport.OIDCCredential{*c}}
	assert.Equal(t, list, OIDCCredentialListResponseFromProto(OIDCCredentialListResponseToProto(list)))

	tok := &transport.OIDCAccessToken{AccessToken: "at", TokenType: "Bearer", ExpiresAt: &expires, IDToken: "id", Scope: "openid"}
	assert.Equal(t, tok, OIDCAccessTokenFromProto(OIDCAccessTokenToProto(tok)))
}

// TestOIDCCredentialConversions_AbsentFieldsStayAbsent proves an optional
// time, the tokens of a create request and a device login are absent on
// the wire when unset and decode back as nil, not as zero values.
func TestOIDCCredentialConversions_AbsentFieldsStayAbsent(t *testing.T) {
	c := &transport.OIDCCredential{OIDCCredentialRef: sampleRef(), Status: transport.OIDCCredentialStatusActive}
	wire := OIDCCredentialToProto(c)
	assert.Nil(t, wire.GetExpiresAt())
	assert.Nil(t, wire.GetLastRefresh())
	assert.Nil(t, wire.GetDeviceLogin())
	assert.Nil(t, wire.GetCreatedAt(), "the zero time is absent")
	assert.Equal(t, c, OIDCCredentialFromProto(wire))

	create := &transport.OIDCCredentialCreateRequest{OIDCCredentialRef: sampleRef(), Config: transport.OIDCCredentialConfig{Issuer: "https://auth.example"}}
	assert.Nil(t, OIDCCredentialCreateRequestToProto(create).GetTokens())
	assert.Equal(t, create, OIDCCredentialCreateRequestFromProto(OIDCCredentialCreateRequestToProto(create)))

	tok := OIDCAccessTokenFromProto(&pb.OIDCAccessToken{AccessToken: "at"})
	assert.Nil(t, tok.ExpiresAt)
}

// TestOIDCCredentialConversions_NilMessages proves a request decoded from
// absent messages is the empty request -- which the service refuses for its
// missing scope -- rather than a panic, and an empty list decodes as [].
func TestOIDCCredentialConversions_NilMessages(t *testing.T) {
	assert.Equal(t, &transport.OIDCCredentialRef{}, OIDCCredentialRefFromProto(nil))
	assert.Equal(t, &transport.OIDCCredentialCreateRequest{}, OIDCCredentialCreateRequestFromProto(nil))
	assert.Equal(t, &transport.OIDCCredentialImportRequest{}, OIDCCredentialImportRequestFromProto(nil))
	assert.Equal(t, &transport.OIDCCredential{}, OIDCCredentialFromProto(nil))

	list := OIDCCredentialListResponseFromProto(&pb.OIDCCredentialListResponse{})
	assert.NotNil(t, list.Credentials)
	assert.Empty(t, list.Credentials)
}

// oidcRecordingServer answers every OIDC credential RPC with a response
// derived from its request, and records the last request of each.
type oidcRecordingServer struct {
	pb.UnimplementedKeystoreServiceServer
	last map[string]any
}

func (s *oidcRecordingServer) view(name string, r *pb.OIDCCredentialRef, st string) *pb.OIDCCredential {
	s.last[name] = r
	return &pb.OIDCCredential{Ref: r, Status: st}
}

func (s *oidcRecordingServer) OIDCCredentialCreate(_ context.Context, r *pb.OIDCCredentialCreateRequest) (*pb.OIDCCredential, error) {
	s.last["create"] = r
	return &pb.OIDCCredential{Ref: r.GetRef(), Config: r.GetConfig(), Status: transport.OIDCCredentialStatusActive}, nil
}
func (s *oidcRecordingServer) OIDCCredentialImport(_ context.Context, r *pb.OIDCCredentialImportRequest) (*pb.OIDCCredential, error) {
	s.last["import"] = r
	return &pb.OIDCCredential{Ref: r.GetRef(), Status: transport.OIDCCredentialStatusActive, ExpiresAt: r.GetTokens().GetExpiresAt()}, nil
}
func (s *oidcRecordingServer) OIDCCredentialGet(_ context.Context, r *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	return s.view("get", r, transport.OIDCCredentialStatusActive), nil
}
func (s *oidcRecordingServer) OIDCCredentialList(_ context.Context, r *pb.OIDCCredentialListRequest) (*pb.OIDCCredentialListResponse, error) {
	s.last["list"] = r
	return &pb.OIDCCredentialListResponse{Credentials: []*pb.OIDCCredential{{Ref: &pb.OIDCCredentialRef{TenantId: r.GetTenantId(), Name: "ci"}}}}, nil
}
func (s *oidcRecordingServer) OIDCCredentialDelete(_ context.Context, r *pb.OIDCCredentialRef) (*pb.OIDCCredentialDeleteResponse, error) {
	s.last["delete"] = r
	return nil, status.Error(codes.NotFound, "oidc credential: not found")
}
func (s *oidcRecordingServer) OIDCCredentialRefresh(_ context.Context, r *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	return s.view("refresh", r, transport.OIDCCredentialStatusReloginRequired), nil
}
func (s *oidcRecordingServer) OIDCCredentialGetAccessToken(_ context.Context, r *pb.OIDCCredentialRef) (*pb.OIDCAccessToken, error) {
	s.last["token"] = r
	return &pb.OIDCAccessToken{AccessToken: "at-" + r.GetName(), TokenType: "Bearer", IdToken: "id"}, nil
}
func (s *oidcRecordingServer) OIDCCredentialDeviceStart(_ context.Context, r *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	c := s.view("start", r, transport.OIDCCredentialStatusPending)
	c.DeviceLogin = &pb.OIDCDeviceLogin{UserCode: "ABCD", IntervalSeconds: 5}
	return c, nil
}
func (s *oidcRecordingServer) OIDCCredentialDevicePoll(_ context.Context, r *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	return s.view("poll", r, transport.OIDCCredentialStatusPending), nil
}

// serveOIDC serves srv over an in-memory connection and returns an
// OIDCCredentialClient over it.
func serveOIDC(t *testing.T, srv pb.KeystoreServiceServer) OIDCCredentialClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(gs, srv)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
		gs.Stop()
		require.NoError(t, <-served)
	})
	return OIDCCredentialClient{Client: pb.NewKeystoreServiceClient(conn)}
}

// TestOIDCCredentialClient_CarriesEveryRequest proves each client method
// sends its request's fields and decodes the server's answer.
func TestOIDCCredentialClient_CarriesEveryRequest(t *testing.T) {
	rec := &oidcRecordingServer{last: map[string]any{}}
	c := serveOIDC(t, rec)
	ctx := context.Background()
	ref := sampleRef()
	wantRef := OIDCCredentialRefToProto(&ref)

	created, err := c.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{OIDCCredentialRef: ref, Config: sampleConfig()})
	require.NoError(t, err)
	assert.Equal(t, ref, created.OIDCCredentialRef)
	assert.Equal(t, sampleConfig(), created.Config)
	assert.Nil(t, rec.last["create"].(*pb.OIDCCredentialCreateRequest).GetTokens(), "a create without tokens sends none")

	expires := sampleTime
	imported, err := c.OIDCCredentialImport(ctx, &transport.OIDCCredentialImportRequest{OIDCCredentialRef: ref, Tokens: transport.OIDCCredentialTokens{AccessToken: "at", ExpiresAt: &expires}})
	require.NoError(t, err)
	require.NotNil(t, imported.ExpiresAt)
	assert.Equal(t, sampleTime, *imported.ExpiresAt)
	assert.Equal(t, "at", rec.last["import"].(*pb.OIDCCredentialImportRequest).GetTokens().GetAccessToken())

	got, err := c.OIDCCredentialGet(ctx, &ref)
	require.NoError(t, err)
	assert.Equal(t, transport.OIDCCredentialStatusActive, got.Status)
	assert.True(t, proto.Equal(wantRef, rec.last["get"].(*pb.OIDCCredentialRef)))

	list, err := c.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{TenantID: "acme"})
	require.NoError(t, err)
	require.Len(t, list.Credentials, 1)
	assert.Equal(t, "acme", list.Credentials[0].TenantID)

	err = c.OIDCCredentialDelete(ctx, &ref)
	assert.Equal(t, codes.NotFound, status.Code(err), "the server's status reaches the caller unchanged")
	assert.True(t, proto.Equal(wantRef, rec.last["delete"].(*pb.OIDCCredentialRef)))

	refreshed, err := c.OIDCCredentialRefresh(ctx, &ref)
	require.NoError(t, err)
	assert.Equal(t, transport.OIDCCredentialStatusReloginRequired, refreshed.Status)

	tok, err := c.OIDCCredentialGetAccessToken(ctx, &ref)
	require.NoError(t, err)
	assert.Equal(t, "at-codex", tok.AccessToken)
	assert.Equal(t, "id", tok.IDToken)
	assert.Nil(t, tok.ExpiresAt)

	started, err := c.OIDCCredentialDeviceStart(ctx, &ref)
	require.NoError(t, err)
	require.NotNil(t, started.DeviceLogin)
	assert.Equal(t, "ABCD", started.DeviceLogin.UserCode)

	polled, err := c.OIDCCredentialDevicePoll(ctx, &ref)
	require.NoError(t, err)
	assert.Equal(t, transport.OIDCCredentialStatusPending, polled.Status)
	assert.True(t, proto.Equal(wantRef, rec.last["poll"].(*pb.OIDCCredentialRef)))
}

// TestOIDCCredentialClient_RefusesNilRequests proves every method refuses a
// nil request without calling the server -- the client has none.
func TestOIDCCredentialClient_RefusesNilRequests(t *testing.T) {
	c := OIDCCredentialClient{}
	ctx := context.Background()
	calls := map[string]func() error{
		"create":  func() error { _, err := c.OIDCCredentialCreate(ctx, nil); return err },
		"import":  func() error { _, err := c.OIDCCredentialImport(ctx, nil); return err },
		"get":     func() error { _, err := c.OIDCCredentialGet(ctx, nil); return err },
		"list":    func() error { _, err := c.OIDCCredentialList(ctx, nil); return err },
		"delete":  func() error { return c.OIDCCredentialDelete(ctx, nil) },
		"refresh": func() error { _, err := c.OIDCCredentialRefresh(ctx, nil); return err },
		"token":   func() error { _, err := c.OIDCCredentialGetAccessToken(ctx, nil); return err },
		"start":   func() error { _, err := c.OIDCCredentialDeviceStart(ctx, nil); return err },
		"poll":    func() error { _, err := c.OIDCCredentialDevicePoll(ctx, nil); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNilRequest)
		})
	}
}

// TestOIDCCredentialClient_ServerErrorsPassThrough proves an RPC failure of
// every method reaches the caller as the server's status.
func TestOIDCCredentialClient_ServerErrorsPassThrough(t *testing.T) {
	c := serveOIDC(t, &pb.UnimplementedKeystoreServiceServer{})
	ctx := context.Background()
	ref := sampleRef()
	calls := map[string]func() error{
		"create": func() error {
			_, err := c.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{})
			return err
		},
		"import": func() error {
			_, err := c.OIDCCredentialImport(ctx, &transport.OIDCCredentialImportRequest{})
			return err
		},
		"get":     func() error { _, err := c.OIDCCredentialGet(ctx, &ref); return err },
		"list":    func() error { _, err := c.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{}); return err },
		"delete":  func() error { return c.OIDCCredentialDelete(ctx, &ref) },
		"refresh": func() error { _, err := c.OIDCCredentialRefresh(ctx, &ref); return err },
		"token":   func() error { _, err := c.OIDCCredentialGetAccessToken(ctx, &ref); return err },
		"start":   func() error { _, err := c.OIDCCredentialDeviceStart(ctx, &ref); return err },
		"poll":    func() error { _, err := c.OIDCCredentialDevicePoll(ctx, &ref); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.Unimplemented, status.Code(call()))
		})
	}
}

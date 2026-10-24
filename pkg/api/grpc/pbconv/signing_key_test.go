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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestSigningKeyConversions_RoundTrip proves a binding, a binding list and a
// resolution survive the wire unchanged.
func TestSigningKeyConversions_RoundTrip(t *testing.T) {
	binding := &transport.SigningKeyBinding{
		Repository: "acme/app", KeyID: "app-release", Backend: "software",
		UpdatedAt: time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC),
	}
	assert.Equal(t, binding, SigningKeyBindingFromProto(SigningKeyBindingToProto(binding)))

	list := &transport.ListSigningKeyBindingsResponse{Bindings: []*transport.SigningKeyBinding{binding}}
	assert.Equal(t, list, ListSigningKeyBindingsResponseFromProto(ListSigningKeyBindingsResponseToProto(list)))

	resolution := &transport.SigningKeyResolution{Repository: "acme/app", KeyID: "release", Default: true}
	assert.Equal(t, resolution, SigningKeyResolutionFromProto(SigningKeyResolutionToProto(resolution)))
}

// TestSigningKeyConversions_NilMessages proves an absent message converts to
// nil, and an absent list to an empty one.
func TestSigningKeyConversions_NilMessages(t *testing.T) {
	assert.Nil(t, SigningKeyBindingToProto(nil))
	assert.Nil(t, SigningKeyBindingFromProto(nil))
	assert.Nil(t, SigningKeyResolutionToProto(nil))
	assert.Nil(t, SigningKeyResolutionFromProto(nil))
	assert.Empty(t, ListSigningKeyBindingsResponseToProto(nil).GetBindings())
	got := ListSigningKeyBindingsResponseFromProto(nil)
	require.NotNil(t, got.Bindings)
	assert.Empty(t, got.Bindings)
}

// signingKeyRecordingServer answers each signing-key RPC and records the
// repository it named.
type signingKeyRecordingServer struct {
	pb.UnimplementedKeystoreServiceServer
	repositories []string
}

func (s *signingKeyRecordingServer) SetSigningKeyBinding(_ context.Context, r *pb.SetSigningKeyBindingRequest) (*pb.SigningKeyBinding, error) {
	s.repositories = append(s.repositories, r.GetRepository())
	return &pb.SigningKeyBinding{Repository: r.GetRepository(), KeyId: r.GetKeyId(), Backend: r.GetBackend()}, nil
}

func (s *signingKeyRecordingServer) GetSigningKeyBinding(_ context.Context, r *pb.GetSigningKeyBindingRequest) (*pb.SigningKeyBinding, error) {
	s.repositories = append(s.repositories, r.GetRepository())
	return nil, status.Error(codes.NotFound, "no binding")
}

func (s *signingKeyRecordingServer) ListSigningKeyBindings(context.Context, *pb.ListSigningKeyBindingsRequest) (*pb.ListSigningKeyBindingsResponse, error) {
	return &pb.ListSigningKeyBindingsResponse{Bindings: []*pb.SigningKeyBinding{{Repository: "acme/app", KeyId: "k"}}}, nil
}

func (s *signingKeyRecordingServer) DeleteSigningKeyBinding(_ context.Context, r *pb.DeleteSigningKeyBindingRequest) (*pb.DeleteSigningKeyBindingResponse, error) {
	s.repositories = append(s.repositories, r.GetRepository())
	return &pb.DeleteSigningKeyBindingResponse{}, nil
}

func (s *signingKeyRecordingServer) ResolveSigningKey(_ context.Context, r *pb.ResolveSigningKeyRequest) (*pb.SigningKeyResolution, error) {
	s.repositories = append(s.repositories, r.GetRepository())
	return &pb.SigningKeyResolution{Repository: r.GetRepository(), KeyId: "release", Default: true}, nil
}

// TestSigningKeyClient_OverTheWire proves the client sends each request's
// repository and returns the server's answer, and the server's status error
// unchanged.
func TestSigningKeyClient_OverTheWire(t *testing.T) {
	srv := &signingKeyRecordingServer{}
	c := SigningKeyClient{Client: serveOIDC(t, srv).Client}
	ctx := context.Background()

	bound, err := c.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "k", Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, "software", bound.Backend)

	_, err = c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: "acme/web"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	list, err := c.ListSigningKeyBindings(ctx)
	require.NoError(t, err)
	require.Len(t, list.Bindings, 1)

	require.NoError(t, c.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{Repository: "acme/app"}))

	resolved, err := c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: "acme/cli"})
	require.NoError(t, err)
	assert.True(t, resolved.Default)

	assert.Equal(t, []string{"acme/app", "acme/web", "acme/app", "acme/cli"}, srv.repositories)
}

// TestSigningKeyClient_NilRequests proves a nil request is refused before
// it reaches the wire.
func TestSigningKeyClient_NilRequests(t *testing.T) {
	c := SigningKeyClient{}
	ctx := context.Background()
	_, err := c.SetSigningKeyBinding(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	_, err = c.GetSigningKeyBinding(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
	assert.ErrorIs(t, c.DeleteSigningKeyBinding(ctx, nil), ErrNilRequest)
	_, err = c.ResolveSigningKey(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)
}

// TestSigningKeyClient_WireErrors proves every call returns the server's
// error when the server does not serve the API.
func TestSigningKeyClient_WireErrors(t *testing.T) {
	c := SigningKeyClient{Client: serveOIDC(t, &pb.UnimplementedKeystoreServiceServer{}).Client}
	ctx := context.Background()
	_, err := c.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = c.ListSigningKeyBindings(ctx)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	assert.Equal(t, codes.Unimplemented, status.Code(c.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{})))
	_, err = c.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// TestSigningKeyRequests_FromProto proves the server side reads every field
// of a signing-key request, and reads an absent message as an empty
// request, which the service then refuses as an invalid repository.
func TestSigningKeyRequests_FromProto(t *testing.T) {
	set := SetSigningKeyBindingRequestFromProto(&pb.SetSigningKeyBindingRequest{Repository: "acme/app", KeyId: "app-release", Backend: "pkcs8"})
	assert.Equal(t, &transport.SetSigningKeyBindingRequest{Repository: "acme/app", KeyID: "app-release", Backend: "pkcs8"}, set)
	assert.Equal(t, "acme/app", GetSigningKeyBindingRequestFromProto(&pb.GetSigningKeyBindingRequest{Repository: "acme/app"}).Repository)
	assert.Equal(t, "acme/app", DeleteSigningKeyBindingRequestFromProto(&pb.DeleteSigningKeyBindingRequest{Repository: "acme/app"}).Repository)
	assert.Equal(t, "acme/app", ResolveSigningKeyRequestFromProto(&pb.ResolveSigningKeyRequest{Repository: "acme/app"}).Repository)

	assert.Equal(t, &transport.SetSigningKeyBindingRequest{}, SetSigningKeyBindingRequestFromProto(nil))
	assert.Empty(t, GetSigningKeyBindingRequestFromProto(nil).Repository)
	assert.Empty(t, DeleteSigningKeyBindingRequestFromProto(nil).Repository)
	assert.Empty(t, ResolveSigningKeyRequestFromProto(nil).Repository)
}

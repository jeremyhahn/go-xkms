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

package unix

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpclib "google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// loginTenantRecorder records the login requests the transport sends.
type loginTenantRecorder struct {
	pb.KeystoreServiceClient
	begin  *pb.BeginAuthenticationRequest
	finish *pb.FinishAuthenticationRequest
}

func (r *loginTenantRecorder) BeginAuthentication(_ context.Context, in *pb.BeginAuthenticationRequest, _ ...grpclib.CallOption) (*pb.BeginAuthenticationResponse, error) {
	r.begin = in
	return &pb.BeginAuthenticationResponse{}, nil
}

func (r *loginTenantRecorder) FinishAuthentication(_ context.Context, in *pb.FinishAuthenticationRequest, _ ...grpclib.CallOption) (*pb.FinishAuthenticationResponse, error) {
	r.finish = in
	return &pb.FinishAuthenticationResponse{}, nil
}

// TestLogin_CopiesTenantID proves the unix-socket client carries the
// explicit login tenant on both ceremony requests (go-xkms#2319).
func TestLogin_CopiesTenantID(t *testing.T) {
	rec := &loginTenantRecorder{}
	tr := &Transport{config: transport.DefaultConfig(), client: rec, connected: true}
	ctx := context.Background()

	_, err := tr.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{Email: "member@example.com", TenantID: "tenant-b"})
	require.NoError(t, err)
	_, err = tr.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{SessionID: "s", Email: "member@example.com", TenantID: "tenant-b"})
	require.NoError(t, err)

	require.NotNil(t, rec.begin)
	require.NotNil(t, rec.finish)
	assert.Equal(t, "tenant-b", rec.begin.GetTenantId())
	assert.Equal(t, "tenant-b", rec.finish.GetTenantId())
}

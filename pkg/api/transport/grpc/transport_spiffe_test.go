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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// signCSRRecorder is a KeystoreServiceClient that records the SignCSR
// request it is sent and answers with err when set.
type signCSRRecorder struct {
	pb.KeystoreServiceClient
	got *pb.SignCSRRequest
	err error
}

func (r *signCSRRecorder) SignCSR(_ context.Context, req *pb.SignCSRRequest, _ ...grpc.CallOption) (*pb.SignCSRResponse, error) {
	r.got = req
	if r.err != nil {
		return nil, r.err
	}
	return &pb.SignCSRResponse{CertificatePem: []byte("cert")}, nil
}

// TestSignCSR_SendsTenantAndSPIFFEKind proves the client puts the request's
// tenant and SPIFFE kind on the wire (go-xkms#1659).
func TestSignCSR_SendsTenantAndSPIFFEKind(t *testing.T) {
	rec := &signCSRRecorder{}
	tr := &Transport{config: transport.DefaultConfig(), client: rec, connected: true}

	_, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM: []byte("csr"), TenantID: "tenant-a", SPIFFEKind: "svc",
	})
	require.NoError(t, err)
	require.NotNil(t, rec.got)
	assert.Equal(t, "tenant-a", rec.got.GetTenantId())
	assert.Equal(t, "svc", rec.got.GetSpiffeKind())
}

// TestSignCSR_ReturnsPermissionDenied proves a refused svc request reaches
// the caller as an error rather than a certificate.
func TestSignCSR_ReturnsPermissionDenied(t *testing.T) {
	rec := &signCSRRecorder{err: status.Error(codes.PermissionDenied, "certs:issue_service required")}
	tr := &Transport{config: transport.DefaultConfig(), client: rec, connected: true}

	resp, err := tr.SignCSR(context.Background(), &transport.SignCSRRequest{
		CSRPEM: []byte("csr"), TenantID: "tenant-a", SPIFFEKind: "svc",
	})
	require.Error(t, err)
	assert.Nil(t, resp)
}

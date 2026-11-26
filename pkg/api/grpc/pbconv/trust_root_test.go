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

	"github.com/stretchr/testify/assert"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

func (s *cannedServer) TrustRootList(_ context.Context, in *pb.TrustRootListRequest) (*pb.TrustRootListResponse, error) {
	return answer[*pb.TrustRootListResponse](s, in)
}

func (s *cannedServer) TrustRootGet(_ context.Context, in *pb.TrustRootRequest) (*pb.TrustRoot, error) {
	return answer[*pb.TrustRoot](s, in)
}

func (s *cannedServer) TrustRootImport(_ context.Context, in *pb.TrustRootImportRequest) (*pb.TrustRootImportResponse, error) {
	return answer[*pb.TrustRootImportResponse](s, in)
}

func (s *cannedServer) TrustRootQuarantine(_ context.Context, in *pb.TrustRootRequest) (*pb.TrustRoot, error) {
	return answer[*pb.TrustRoot](s, in)
}

func (s *cannedServer) TrustRootRemove(_ context.Context, in *pb.TrustRootRequest) (*pb.TrustRootRemoveResponse, error) {
	return answer[*pb.TrustRootRemoveResponse](s, in)
}

func sampleTrustRoot() *transport.TrustRoot {
	return &transport.TrustRoot{
		Fingerprint: "ab12", Purpose: "tls", Subject: "CN=Root", Issuer: "CN=Root", Algorithm: "ECDSA-P384",
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2036-01-01T00:00:00Z", AddedAt: "2026-02-01T00:00:00Z",
		Source: "aia", PEM: "-----BEGIN CERTIFICATE-----",
	}
}

func sampleTrustRootPB() *pb.TrustRoot {
	return &pb.TrustRoot{
		Fingerprint: "ab12", Purpose: "tls", Subject: "CN=Root", Issuer: "CN=Root", Algorithm: "ECDSA-P384",
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2036-01-01T00:00:00Z", AddedAt: "2026-02-01T00:00:00Z",
		Source: "aia", Pem: "-----BEGIN CERTIFICATE-----",
	}
}

func TestTrustRootConversions_RoundTrip(t *testing.T) {
	assert.Equal(t, sampleTrustRootPB(), TrustRootToProto(sampleTrustRoot()))
	assert.Equal(t, sampleTrustRoot(), TrustRootFromProto(TrustRootToProto(sampleTrustRoot())))

	list := &transport.TrustRootListResponse{Roots: []transport.TrustRoot{*sampleTrustRoot()}}
	assert.Equal(t, list, TrustRootListResponseFromProto(TrustRootListResponseToProto(list)))

	assert.Equal(t, &transport.TrustRootImportRequest{PEM: "pem", Purpose: "tls", Source: "operator"},
		TrustRootImportRequestFromProto(&pb.TrustRootImportRequest{Pem: "pem", Purpose: "tls", Source: "operator"}))
}

func TestTrustRootConversions_EmptyListIsNotNil(t *testing.T) {
	// A JSON consumer must see "roots": [] rather than null.
	assert.Equal(t, []transport.TrustRoot{}, TrustRootListResponseFromProto(&pb.TrustRootListResponse{}).Roots)
	assert.Equal(t, []transport.TrustRoot{}, TrustRootListResponseFromProto(nil).Roots)
	assert.Empty(t, TrustRootListResponseToProto(&transport.TrustRootListResponse{}).Roots)
}

func TestTrustRootClient_CarriesEveryRequest(t *testing.T) {
	byFingerprint := &transport.TrustRootRequest{Fingerprint: "ab12"}

	runClientCases(t, func(c pb.KeystoreServiceClient) TrustRootClient { return TrustRootClient{Client: c} }, []clientCase[TrustRootClient]{
		{
			name: "TrustRootList",
			call: func(ctx context.Context, c TrustRootClient) (any, error) {
				return c.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: "tls"})
			},
			wantReq: &pb.TrustRootListRequest{Purpose: "tls"},
			reply:   &pb.TrustRootListResponse{Roots: []*pb.TrustRoot{sampleTrustRootPB()}},
			want:    &transport.TrustRootListResponse{Roots: []transport.TrustRoot{*sampleTrustRoot()}},
		},
		{
			name: "TrustRootGet",
			call: func(ctx context.Context, c TrustRootClient) (any, error) {
				return c.TrustRootGet(ctx, byFingerprint)
			},
			wantReq: &pb.TrustRootRequest{Fingerprint: "ab12"},
			reply:   sampleTrustRootPB(),
			want:    sampleTrustRoot(),
		},
		{
			name: "TrustRootImport",
			call: func(ctx context.Context, c TrustRootClient) (any, error) {
				return c.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem", Purpose: "tls", Source: "operator"})
			},
			wantReq: &pb.TrustRootImportRequest{Pem: "pem", Purpose: "tls", Source: "operator"},
			reply:   &pb.TrustRootImportResponse{Added: 2, Skipped: 1},
			want:    &transport.TrustRootImportResponse{Added: 2, Skipped: 1},
		},
		{
			name: "TrustRootQuarantine",
			call: func(ctx context.Context, c TrustRootClient) (any, error) {
				return c.TrustRootQuarantine(ctx, byFingerprint)
			},
			wantReq: &pb.TrustRootRequest{Fingerprint: "ab12"},
			reply:   sampleTrustRootPB(),
			want:    sampleTrustRoot(),
		},
		{
			name: "TrustRootRemove",
			call: func(ctx context.Context, c TrustRootClient) (any, error) {
				return nil, c.TrustRootRemove(ctx, byFingerprint)
			},
			wantReq: &pb.TrustRootRequest{Fingerprint: "ab12"},
			reply:   &pb.TrustRootRemoveResponse{},
		},
	})
}

func TestTrustRootClient_RefusesNilRequests(t *testing.T) {
	c := TrustRootClient{}
	ctx := context.Background()
	calls := []error{
		func() error { _, err := c.TrustRootList(ctx, nil); return err }(),
		func() error { _, err := c.TrustRootGet(ctx, nil); return err }(),
		func() error { _, err := c.TrustRootImport(ctx, nil); return err }(),
		func() error { _, err := c.TrustRootQuarantine(ctx, nil); return err }(),
		c.TrustRootRemove(ctx, nil),
	}
	for i, err := range calls {
		assert.ErrorIs(t, err, ErrNilRequest, "call %d", i)
	}
}

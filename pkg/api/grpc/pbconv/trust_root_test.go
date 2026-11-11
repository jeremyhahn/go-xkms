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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

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

func testTrustRoot(fingerprint string) transport.TrustRoot {
	return transport.TrustRoot{
		Fingerprint: fingerprint,
		Purpose:     "tpm-manufacturer",
		Subject:     "CN=EK Root",
		Issuer:      "CN=EK Root",
		Algorithm:   "ECDSA-P256",
		NotBefore:   "2026-01-01T00:00:00Z",
		NotAfter:    "2036-01-01T00:00:00Z",
		AddedAt:     "2026-09-30T12:00:00Z",
		Source:      "aia",
		PEM:         "-----BEGIN CERTIFICATE-----",
	}
}

func TestTrustRoot_RoundTrip(t *testing.T) {
	root := testTrustRoot("ab12")
	wire := TrustRootToProto(&root)
	assert.Equal(t, root.PEM, wire.GetPem())
	assert.Equal(t, &root, TrustRootFromProto(wire))

	tests := map[string]*transport.TrustRootListResponse{
		"empty":    {Roots: []transport.TrustRoot{}},
		"one":      {Roots: []transport.TrustRoot{root}},
		"many":     {Roots: []transport.TrustRoot{root, testTrustRoot("cd34")}},
		"no-roots": {},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			wire := TrustRootListResponseToProto(in)
			require.Len(t, wire.GetRoots(), len(in.Roots))
			out := TrustRootListResponseFromProto(wire)
			assert.ElementsMatch(t, in.Roots, out.Roots)
			assert.NotNil(t, out.Roots, "an empty list is [] on the transport, never null")
		})
	}
}

// TestTrustRoot_FromProtoNil pins that a nil wire message converts to the
// zero value rather than panicking: the generated getters are nil-safe.
func TestTrustRoot_FromProtoNil(t *testing.T) {
	assert.Equal(t, &transport.TrustRoot{}, TrustRootFromProto(nil))
	assert.Equal(t, &transport.TrustRootListResponse{Roots: []transport.TrustRoot{}}, TrustRootListResponseFromProto(nil))
	assert.Equal(t, &transport.TrustRootImportRequest{}, TrustRootImportRequestFromProto(nil))
}

func TestTrustRootImportRequestFromProto(t *testing.T) {
	in := &pb.TrustRootImportRequest{Pem: "pem", Purpose: "user-ca", Source: "operator"}
	assert.Equal(t,
		&transport.TrustRootImportRequest{PEM: "pem", Purpose: "user-ca", Source: "operator"},
		TrustRootImportRequestFromProto(in))
}

// trustRootRecorder answers every trust-root call from canned responses and
// records the request it was sent.
type trustRootRecorder struct {
	pb.KeystoreServiceClient
	root *pb.TrustRoot
	sent any
}

func (r *trustRootRecorder) TrustRootList(_ context.Context, in *pb.TrustRootListRequest, _ ...grpc.CallOption) (*pb.TrustRootListResponse, error) {
	r.sent = in
	return &pb.TrustRootListResponse{Roots: []*pb.TrustRoot{r.root}}, nil
}

func (r *trustRootRecorder) TrustRootGet(_ context.Context, in *pb.TrustRootRequest, _ ...grpc.CallOption) (*pb.TrustRoot, error) {
	r.sent = in
	return r.root, nil
}

func (r *trustRootRecorder) TrustRootImport(_ context.Context, in *pb.TrustRootImportRequest, _ ...grpc.CallOption) (*pb.TrustRootImportResponse, error) {
	r.sent = in
	return &pb.TrustRootImportResponse{Added: 2, Skipped: 1}, nil
}

func (r *trustRootRecorder) TrustRootQuarantine(_ context.Context, in *pb.TrustRootRequest, _ ...grpc.CallOption) (*pb.TrustRoot, error) {
	r.sent = in
	return r.root, nil
}

func (r *trustRootRecorder) TrustRootRemove(_ context.Context, in *pb.TrustRootRequest, _ ...grpc.CallOption) (*pb.TrustRootRemoveResponse, error) {
	r.sent = in
	return &pb.TrustRootRemoveResponse{}, nil
}

func TestTrustRootClient_Calls(t *testing.T) {
	ctx := context.Background()
	root := testTrustRoot("ab12")
	rec := &trustRootRecorder{root: TrustRootToProto(&root)}
	c := TrustRootClient{Client: rec}
	byFingerprint := &transport.TrustRootRequest{Fingerprint: "ab12"}

	list, err := c.TrustRootList(ctx, &transport.TrustRootListRequest{Purpose: "general"})
	require.NoError(t, err)
	assert.Equal(t, "general", rec.sent.(*pb.TrustRootListRequest).GetPurpose())
	assert.Equal(t, []transport.TrustRoot{root}, list.Roots)

	got, err := c.TrustRootGet(ctx, byFingerprint)
	require.NoError(t, err)
	assert.Equal(t, "ab12", rec.sent.(*pb.TrustRootRequest).GetFingerprint())
	assert.Equal(t, &root, got)

	imported, err := c.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem", Purpose: "user-ca", Source: "operator"})
	require.NoError(t, err)
	sent := rec.sent.(*pb.TrustRootImportRequest)
	assert.Equal(t, []string{"pem", "user-ca", "operator"}, []string{sent.GetPem(), sent.GetPurpose(), sent.GetSource()})
	assert.Equal(t, &transport.TrustRootImportResponse{Added: 2, Skipped: 1}, imported)

	quarantined, err := c.TrustRootQuarantine(ctx, &transport.TrustRootRequest{Fingerprint: "cd34"})
	require.NoError(t, err)
	assert.Equal(t, "cd34", rec.sent.(*pb.TrustRootRequest).GetFingerprint())
	assert.Equal(t, &root, quarantined)

	require.NoError(t, c.TrustRootRemove(ctx, &transport.TrustRootRequest{Fingerprint: "ef56"}))
	assert.Equal(t, "ef56", rec.sent.(*pb.TrustRootRequest).GetFingerprint())
}

func (c failingKeystoreClient) TrustRootList(context.Context, *pb.TrustRootListRequest, ...grpc.CallOption) (*pb.TrustRootListResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) TrustRootGet(context.Context, *pb.TrustRootRequest, ...grpc.CallOption) (*pb.TrustRoot, error) {
	return nil, c.err
}

func (c failingKeystoreClient) TrustRootImport(context.Context, *pb.TrustRootImportRequest, ...grpc.CallOption) (*pb.TrustRootImportResponse, error) {
	return nil, c.err
}

func (c failingKeystoreClient) TrustRootQuarantine(context.Context, *pb.TrustRootRequest, ...grpc.CallOption) (*pb.TrustRoot, error) {
	return nil, c.err
}

func (c failingKeystoreClient) TrustRootRemove(context.Context, *pb.TrustRootRequest, ...grpc.CallOption) (*pb.TrustRootRemoveResponse, error) {
	return nil, c.err
}

func TestTrustRootClient_Errors(t *testing.T) {
	ctx := context.Background()
	rpcErr := errors.New("rpc failed")
	c := TrustRootClient{Client: failingKeystoreClient{err: rpcErr}}
	byFingerprint := &transport.TrustRootRequest{Fingerprint: "ab12"}

	calls := map[string]func(*transport.TrustRootRequest) (any, error){
		"list": func(r *transport.TrustRootRequest) (any, error) {
			if r == nil {
				return c.TrustRootList(ctx, nil)
			}
			return c.TrustRootList(ctx, &transport.TrustRootListRequest{})
		},
		"get": func(r *transport.TrustRootRequest) (any, error) { return c.TrustRootGet(ctx, r) },
		"import": func(r *transport.TrustRootRequest) (any, error) {
			if r == nil {
				return c.TrustRootImport(ctx, nil)
			}
			return c.TrustRootImport(ctx, &transport.TrustRootImportRequest{PEM: "pem"})
		},
		"quarantine": func(r *transport.TrustRootRequest) (any, error) { return c.TrustRootQuarantine(ctx, r) },
		"remove":     func(r *transport.TrustRootRequest) (any, error) { return nil, c.TrustRootRemove(ctx, r) },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			out, err := call(nil)
			require.ErrorIs(t, err, ErrNilRequest)
			assert.Nil(t, out)
			out, err = call(byFingerprint)
			require.ErrorIs(t, err, rpcErr)
			assert.Nil(t, out, "no partial result on a transport error")
		})
	}
}

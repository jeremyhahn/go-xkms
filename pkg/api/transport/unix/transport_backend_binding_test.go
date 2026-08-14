// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package unix

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// recordingKeystoreServer captures the wrap/unwrap requests it receives so a
// test can assert what actually went onto the wire, rather than only that the
// call returned.
type recordingKeystoreServer struct {
	pb.UnimplementedKeystoreServiceServer

	wrapReq   *pb.WrapKeyRequest
	unwrapReq *pb.UnwrapKeyRequest
}

func (s *recordingKeystoreServer) WrapKey(_ context.Context, req *pb.WrapKeyRequest) (*pb.WrapKeyResponse, error) {
	s.wrapReq = req
	return &pb.WrapKeyResponse{WrappedKey: []byte("wrapped"), Algorithm: req.Algorithm}, nil
}

func (s *recordingKeystoreServer) UnwrapKey(_ context.Context, req *pb.UnwrapKeyRequest) (*pb.UnwrapKeyResponse, error) {
	s.unwrapReq = req
	return &pb.UnwrapKeyResponse{KeyMaterial: []byte("material")}, nil
}

func newRecordingTransport(t *testing.T) (*Transport, *recordingKeystoreServer, func()) {
	t.Helper()

	rec := &recordingKeystoreServer{}
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, rec)

	go func() {
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test-backend-binding.sock"

	tr := &Transport{
		config:    cfg,
		conn:      conn,
		client:    pb.NewKeystoreServiceClient(conn),
		connected: true,
	}

	return tr, rec, func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	}
}

// TestWrapUnwrapForwardBackend pins that the backend the caller named reaches
// the server over the unix-socket transport.
//
// transport.WrapKeyRequest and transport.UnwrapKeyRequest have always carried a
// Backend, and xkmsctl has always set it, but this transport built its protobuf
// message without that field -- so the name was accepted from the caller and
// then dropped. The server had no way to honour it and searched every
// registered backend instead, which is what made UnwrapKey an unwrap oracle.
func TestWrapUnwrapForwardBackend(t *testing.T) {
	tr, rec, cleanup := newRecordingTransport(t)
	defer cleanup()

	_, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{
		Backend:     "prod-hsm",
		KeyMaterial: []byte("key"),
		Algorithm:   "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	require.NotNil(t, rec.wrapReq)
	assert.Equal(t, "prod-hsm", rec.wrapReq.Backend)

	_, err = tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		Backend:            "prod-hsm",
		WrappedKeyMaterial: []byte("wrapped"),
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	require.NotNil(t, rec.unwrapReq)
	assert.Equal(t, "prod-hsm", rec.unwrapReq.Backend)
}

// TestWrapUnwrapForwardEmptyBackend is the bad-input companion: a request that
// names no backend must travel as an empty field, not as some substituted
// default the client invented.
func TestWrapUnwrapForwardEmptyBackend(t *testing.T) {
	tr, rec, cleanup := newRecordingTransport(t)
	defer cleanup()

	_, err := tr.WrapKey(context.Background(), &transport.WrapKeyRequest{
		KeyMaterial: []byte("key"),
		Algorithm:   "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	require.NotNil(t, rec.wrapReq)
	assert.Empty(t, rec.wrapReq.Backend)

	_, err = tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{
		WrappedKeyMaterial: []byte("wrapped"),
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	require.NotNil(t, rec.unwrapReq)
	assert.Empty(t, rec.unwrapReq.Backend)
}

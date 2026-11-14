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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

const otaBadBoard = "Bad--Board"

// otaImageServer answers the OTA image-key RPCs the way the xkmsd unix-socket
// gRPC server does: a malformed board id is InvalidArgument, any other board
// gets a response naming its key.
type otaImageServer struct {
	pb.UnimplementedKeystoreServiceServer
}

func (otaImageServer) CreateOTAImageKey(_ context.Context, req *pb.OTAImageKeyRequest) (*pb.GenerateKeyResponse, error) {
	if req.BoardId == otaBadBoard {
		return nil, status.Error(codes.InvalidArgument, "invalid board id")
	}
	return &pb.GenerateKeyResponse{KeyId: "ota-image-" + req.BoardId}, nil
}

func (otaImageServer) RotateOTAImageKey(_ context.Context, req *pb.OTAImageKeyRequest) (*pb.RotateKeyResponse, error) {
	if req.BoardId == otaBadBoard {
		return nil, status.Error(codes.InvalidArgument, "invalid board id")
	}
	return &pb.RotateKeyResponse{KeyId: "ota-image-" + req.BoardId, KeyVersion: 2}, nil
}

func (otaImageServer) SignOTAImage(_ context.Context, req *pb.SignOTAImageRequest) (*pb.SignResponse, error) {
	if req.BoardId == otaBadBoard {
		return nil, status.Error(codes.InvalidArgument, "invalid board id")
	}
	if string(req.Data) != "image" {
		return nil, status.Error(codes.InvalidArgument, "unexpected data")
	}
	return &pb.SignResponse{Signature: []byte("sig"), KeyVersion: 2}, nil
}

func (otaImageServer) ExportOTAImageKey(_ context.Context, req *pb.OTAImageKeyRequest) (*pb.ExportOTAImageKeyResponse, error) {
	if req.BoardId == otaBadBoard {
		return nil, status.Error(codes.InvalidArgument, "invalid board id")
	}
	return &pb.ExportOTAImageKeyResponse{
		BoardId:    req.BoardId,
		KeyId:      "ota-image-" + req.BoardId,
		KeyVersion: 2,
		Algorithm:  "ES256",
		PublicKey:  []byte("x||y"),
		CoseKey:    []byte("cose"),
	}, nil
}

func newOTAImageTransport(t *testing.T) *Transport {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, otaImageServer{})
	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, conn.Close())
		srv.Stop()
		assert.NoError(t, <-served)
	})

	return &Transport{
		config:    transport.DefaultConfig(),
		conn:      conn,
		client:    pb.NewKeystoreServiceClient(conn),
		connected: true,
	}
}

func TestOTAImageKey_Unix(t *testing.T) {
	tr := newOTAImageTransport(t)
	ctx := context.Background()

	created, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, "ota-image-cm4", created.KeyID)

	rotated, err := tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)

	signed, err := tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: "cm4", Data: []byte("image")})
	require.NoError(t, err)
	assert.Equal(t, []byte("sig"), signed.Signature)
	assert.Equal(t, uint32(2), signed.KeyVersion)

	exported, err := tr.ExportOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: "cm4"})
	require.NoError(t, err)
	assert.Equal(t, &transport.ExportOTAImageKeyResponse{
		BoardID:    "cm4",
		KeyID:      "ota-image-cm4",
		KeyVersion: 2,
		Algorithm:  "ES256",
		PublicKey:  []byte("x||y"),
		COSEKey:    []byte("cose"),
	}, exported, "every field crosses the wire")
}

func TestOTAImageKey_Unix_InvalidBoard(t *testing.T) {
	tr := newOTAImageTransport(t)
	ctx := context.Background()

	calls := map[string]func() error{
		"create": func() error {
			_, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: otaBadBoard})
			return err
		},
		"rotate": func() error {
			_, err := tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: otaBadBoard})
			return err
		},
		"sign": func() error {
			_, err := tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{Backend: "software", BoardID: otaBadBoard, Data: []byte("image")})
			return err
		},
		"export": func() error {
			_, err := tr.ExportOTAImageKey(ctx, &transport.OTAImageKeyRequest{Backend: "software", BoardID: otaBadBoard})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.InvalidArgument, status.Code(call()))
		})
	}
}

func TestOTAImageKey_Unix_NotConnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	ctx := context.Background()

	_, err := tr.CreateOTAImageKey(ctx, &transport.OTAImageKeyRequest{BoardID: "cm4"})
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = tr.RotateOTAImageKey(ctx, &transport.OTAImageKeyRequest{BoardID: "cm4"})
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = tr.SignOTAImage(ctx, &transport.OTAImageSignRequest{BoardID: "cm4"})
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = tr.ExportOTAImageKey(ctx, &transport.OTAImageKeyRequest{BoardID: "cm4"})
	assert.ErrorIs(t, err, ErrNotConnected)
}

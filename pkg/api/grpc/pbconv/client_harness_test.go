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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// dialKeystore serves srv over an in-memory listener and returns a client
// connected to it.
func dialKeystore(t *testing.T, srv pb.KeystoreServiceServer) pb.KeystoreServiceClient {
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
	return pb.NewKeystoreServiceClient(conn)
}

// cannedServer records the last request it received and answers with
// reply, so a client test pins both the request the client puts on the wire
// and how it decodes the answer.
type cannedServer struct {
	pb.UnimplementedKeystoreServiceServer
	got   proto.Message
	reply proto.Message
}

// answer records in and returns the canned reply as the method's response
// type.
func answer[T proto.Message](s *cannedServer, in proto.Message) (T, error) {
	s.got = in
	return s.reply.(T), nil
}

// clientCase is one client method call: the request it must send, the
// reply the server gives, and the transport value the client must return.
type clientCase[C any] struct {
	name    string
	call    func(context.Context, C) (any, error)
	wantReq proto.Message
	reply   proto.Message
	want    any
}

// runClientCases runs every case against a canned server, then against a
// server that implements nothing, whose status error the client must return
// unchanged.
func runClientCases[C any](t *testing.T, newClient func(pb.KeystoreServiceClient) C, cases []clientCase[C]) {
	t.Helper()
	srv := &cannedServer{}
	client := newClient(dialKeystore(t, srv))
	unimplemented := newClient(dialKeystore(t, &pb.UnimplementedKeystoreServiceServer{}))
	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv.reply = tc.reply
			got, err := tc.call(ctx, client)
			require.NoError(t, err)
			assert.True(t, proto.Equal(tc.wantReq, srv.got), "request on the wire: %v", srv.got)
			assert.Equal(t, tc.want, got)

			_, err = tc.call(ctx, unimplemented)
			assert.Equal(t, codes.Unimplemented, status.Code(err))
		})
	}
}

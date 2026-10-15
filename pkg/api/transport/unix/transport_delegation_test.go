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
	"path"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/keyversiontest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// recordedRPC is one call an rpcRecorder served: the RPC's method name and
// its request in wire form.
type recordedRPC struct {
	method string
	req    []byte
}

// rpcRecorder is an in-process gRPC server for every RPC: it records each
// call and answers it with reply, or with err when err is set.
type rpcRecorder struct {
	reply proto.Message
	err   error
	last  atomic.Pointer[recordedRPC]
}

// handle serves any RPC. The request decodes into an Empty that keeps its
// fields as unknown fields, so it re-marshals to the bytes the client sent.
func (r *rpcRecorder) handle(_ any, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	var req emptypb.Empty
	if err := stream.RecvMsg(&req); err != nil {
		return err
	}
	raw, err := proto.Marshal(&req)
	if err != nil {
		return err
	}
	r.last.Store(&recordedRPC{method: path.Base(method), req: raw})
	if r.err != nil {
		return r.err
	}
	return stream.SendMsg(r.reply)
}

// connect returns a transport connected to the recorder over bufconn.
func (r *rpcRecorder) connect(t *testing.T) *Transport {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(r.handle))
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
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return &Transport{
		config:    transport.DefaultConfig(),
		conn:      conn,
		client:    pb.NewKeystoreServiceClient(conn),
		connected: true,
	}
}

// request returns the method of the last call the recorder served and
// decodes its request into into, failing the test when no call reached it.
func (r *rpcRecorder) request(t *testing.T, into proto.Message) string {
	t.Helper()
	rpc := r.last.Swap(nil)
	require.NotNil(t, rpc, "no call reached the server")
	if into != nil {
		require.NoError(t, proto.Unmarshal(rpc.req, into))
	}
	return rpc.method
}

// delegatedCalls returns every method the transport serves by delegating to
// a pbconv client: key versions, TPM policies and OIDC credentials.
func delegatedCalls(ctx context.Context, tr *Transport) map[string]func() error {
	calls := keyversiontest.Calls(ctx, tr)
	for name, call := range tpmpolicytest.Calls(ctx, tr) {
		calls[name] = call
	}
	for name, call := range oidccredentialtest.Calls(ctx, tr) {
		calls[name] = call
	}
	return calls
}

// TestDelegatedCalls_InvokeTheirRPC proves every delegated method of a
// connected transport invokes the RPC of the same name and accepts its
// reply. The request and reply conversions are tested in pbconv.
func TestDelegatedCalls_InvokeTheirRPC(t *testing.T) {
	rec := &rpcRecorder{reply: &emptypb.Empty{}}
	tr := rec.connect(t)

	for name, call := range delegatedCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, call())
			assert.Equal(t, name, rec.request(t, nil))
		})
	}
}

// TestDelegatedCalls_SurfaceServerErrors proves every delegated method
// returns the server's status unchanged.
func TestDelegatedCalls_SurfaceServerErrors(t *testing.T) {
	rec := &rpcRecorder{err: status.Error(codes.FailedPrecondition, "version is current")}
	tr := rec.connect(t)

	for name, call := range delegatedCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			err := call()
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		})
	}
}

// TestDelegatedCalls_NotConnected proves the OIDC credential methods refuse
// to run without a client. The key version and TPM policy methods are
// covered by their own NotConnected tests.
func TestDelegatedCalls_NotConnected(t *testing.T) {
	for name, call := range oidccredentialtest.Calls(context.Background(), &Transport{}) {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}

// TestInvites_SendTheInvitee proves the invite redemption methods send the
// tenant, token and credential the invitee presents, and convert the reply.
func TestInvites_SendTheInvitee(t *testing.T) {
	ctx := context.Background()

	t.Run("GetInvite", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.GetInviteResponse{Email: "ann@example.com", Methods: []string{"webauthn"}}}
		resp, err := rec.connect(t).GetInvite(ctx, &transport.GetInviteRequest{TenantID: "acme", Token: "tok"})
		require.NoError(t, err)
		var req pb.GetInviteRequest
		assert.Equal(t, "GetInvite", rec.request(t, &req))
		assert.Equal(t, "acme", req.GetTenantId())
		assert.Equal(t, "tok", req.GetToken())
		assert.Equal(t, "ann@example.com", resp.Email)
		assert.Equal(t, []string{"webauthn"}, resp.Methods)
	})

	t.Run("BeginInviteRegistration", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.BeginInviteRegistrationResponse{SessionId: "s1", OptionsJson: "{}"}}
		resp, err := rec.connect(t).BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: "acme", Token: "tok"})
		require.NoError(t, err)
		var req pb.BeginInviteRegistrationRequest
		assert.Equal(t, "BeginInviteRegistration", rec.request(t, &req))
		assert.Equal(t, "tok", req.GetToken())
		assert.Equal(t, "s1", resp.SessionID)
		assert.Equal(t, "{}", resp.OptionsJSON)
	})

	t.Run("FinishInviteRegistration", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.FinishInviteRegistrationResponse{UserId: 42}}
		resp, err := rec.connect(t).FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{
			TenantID: "acme", Token: "tok", SessionID: "s1", AttestationJSON: `{"id":"cred"}`,
		})
		require.NoError(t, err)
		var req pb.FinishInviteRegistrationRequest
		assert.Equal(t, "FinishInviteRegistration", rec.request(t, &req))
		assert.Equal(t, "s1", req.GetSessionId())
		assert.Equal(t, `{"id":"cred"}`, req.GetAttestationJson())
		assert.Equal(t, uint64(42), resp.UserID)
	})

	t.Run("ActivateInvitePIV", func(t *testing.T) {
		rec := &rpcRecorder{reply: &pb.ActivateInvitePIVResponse{UserId: 7}}
		resp, err := rec.connect(t).ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{TenantID: "acme", Token: "tok", CertPEM: "PEM"})
		require.NoError(t, err)
		var req pb.ActivateInvitePIVRequest
		assert.Equal(t, "ActivateInvitePIV", rec.request(t, &req))
		assert.Equal(t, "PEM", req.GetCertPem())
		assert.Equal(t, uint64(7), resp.UserID)
	})
}

// inviteCalls returns every invite redemption method of tr.
func inviteCalls(ctx context.Context, tr *Transport) map[string]func() error {
	return map[string]func() error{
		"GetInvite": func() error {
			_, err := tr.GetInvite(ctx, &transport.GetInviteRequest{TenantID: "acme", Token: "tok"})
			return err
		},
		"BeginInviteRegistration": func() error {
			_, err := tr.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: "acme", Token: "tok"})
			return err
		},
		"FinishInviteRegistration": func() error {
			_, err := tr.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{TenantID: "acme", Token: "tok"})
			return err
		},
		"ActivateInvitePIV": func() error {
			_, err := tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{TenantID: "acme", Token: "tok"})
			return err
		},
	}
}

// TestInvites_Errors proves the invite methods refuse to run unconnected
// and return the server's status when it refuses the invite.
func TestInvites_Errors(t *testing.T) {
	ctx := context.Background()

	for name, call := range inviteCalls(ctx, &Transport{}) {
		t.Run(name+"/not connected", func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}

	rec := &rpcRecorder{err: status.Error(codes.NotFound, "invite expired")}
	for name, call := range inviteCalls(ctx, rec.connect(t)) {
		t.Run(name+"/server error", func(t *testing.T) {
			assert.Equal(t, codes.NotFound, status.Code(call()))
		})
	}
}

// TestBootstrapListenerKeys proves the listener keys are read over the
// socket and a refusal is wrapped with what failed.
func TestBootstrapListenerKeys(t *testing.T) {
	ctx := context.Background()

	rec := &rpcRecorder{reply: &pb.BootstrapListenerKeysResponse{NoisePublicKey: "noise", P256PublicKey: "p256"}}
	resp, err := rec.connect(t).BootstrapListenerKeys(ctx)
	require.NoError(t, err)
	assert.Equal(t, "BootstrapListenerKeys", rec.request(t, nil))
	assert.Equal(t, "noise", resp.NoisePublicKey)
	assert.Equal(t, "p256", resp.P256PublicKey)

	refused := &rpcRecorder{err: status.Error(codes.Unavailable, "no listener")}
	_, err = refused.connect(t).BootstrapListenerKeys(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap listener keys failed")
	assert.Equal(t, codes.Unavailable, status.Code(err))

	_, err = (&Transport{}).BootstrapListenerKeys(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)
}

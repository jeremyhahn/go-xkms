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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/peercred"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/tenancy"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// identityRecorder is an embedder interceptor that records the identity each
// admitted request carries at the end of the listener's chain.
type identityRecorder struct {
	mu   sync.Mutex
	seen []*auth.Identity
}

func (r *identityRecorder) unary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	r.mu.Lock()
	r.seen = append(r.seen, auth.GetIdentity(ctx))
	r.mu.Unlock()
	return handler(ctx, req)
}

func (r *identityRecorder) identities() []*auth.Identity {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*auth.Identity(nil), r.seen...)
}

// startRecordingServer starts a listener under cfg with an identityRecorder
// as its embedder interceptor and returns the recorder and the socket path.
func startRecordingServer(t *testing.T, cfg *GRPCConfig) (*identityRecorder, string) {
	t.Helper()
	recorder := &identityRecorder{}
	cfg.SocketPath = filepath.Join(privateSocketDir(t), "identity.sock")
	cfg.UnaryInterceptors = []grpc.UnaryServerInterceptor{recorder.unary}
	server, err := NewGRPCServer(cfg)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start() }()
	waitForGRPCServerReady(t, server, cfg.SocketPath)
	t.Cleanup(func() { _ = server.Stop(context.Background()) })
	return recorder, cfg.SocketPath
}

// TestGRPCServer_AttachesPeerIdentity proves every admitted peer reaches the
// handlers with an explicit identity built from its kernel credentials:
// subject uid:<uid> in the system tenant, auth_method unix-peer (#1406).
func TestGRPCServer_AttachesPeerIdentity(t *testing.T) {
	recorder, socketPath := startRecordingServer(t, &GRPCConfig{})

	resp, err := healthCall(t, socketPath)
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.Status)

	seen := recorder.identities()
	require.Len(t, seen, 1)
	identity := seen[0]
	require.NotNil(t, identity, "an admitted peer must carry an identity")
	uid := strconv.Itoa(os.Geteuid())
	assert.Equal(t, "uid:"+uid, identity.Subject)
	assert.Equal(t, qrdbsdk.SystemTenantID, identity.TenantID)
	assert.Equal(t, PeerAuthMethod, identity.Metadata["auth_method"])
	assert.Equal(t, uid, identity.Metadata["uid"])
	assert.Equal(t, strconv.Itoa(os.Getegid()), identity.Metadata["gid"])
	assert.Equal(t, strconv.Itoa(os.Getpid()), identity.Metadata["pid"])
}

// TestGRPCServer_RefusedPeerGetsNoIdentity proves a peer the policy refuses
// never reaches the chain, so no identity is ever attached to it.
func TestGRPCServer_RefusedPeerGetsNoIdentity(t *testing.T) {
	recorder, socketPath := startRecordingServer(t, &GRPCConfig{
		ExclusivePeers: true,
		AllowedUIDs:    []uint32{uint32(os.Geteuid()) + 1},
	})

	_, err := healthCall(t, socketPath)
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.Empty(t, recorder.identities(), "a refused peer must never reach an interceptor")
}

// TestGRPCServer_SSHServedToThePeer proves the SSH RPCs work over the socket:
// the peer's unix-peer identity owns its user-scope keys in the system
// partition, and another subject's keys stay out of its reach. Before #1406
// a socket peer carried no identity and every SSH RPC was refused.
func TestGRPCServer_SSHServedToThePeer(t *testing.T) {
	sshClient, err := tenancy.New(tenancy.Options{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sshClient.Close()) })
	_, socketPath := startRecordingServer(t, &GRPCConfig{SSHClient: sshClient})

	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	client := pb.NewKeystoreServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	subject := "uid:" + strconv.Itoa(os.Geteuid())
	_, err = client.SSHGenerateKey(ctx, &pb.SSHGenerateKeyRequest{
		Scope: "user", Owner: subject, Name: "peer-key", Algorithm: "ed25519",
	})
	require.NoError(t, err)

	listed, err := client.SSHListKeys(ctx, &pb.SSHListKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listed.GetKeys(), 1)
	assert.Equal(t, subject, listed.GetKeys()[0].GetOwner())

	_, err = client.SSHGenerateKey(ctx, &pb.SSHGenerateKeyRequest{
		Scope: "user", Owner: "someone-else", Name: "foreign-key", Algorithm: "ed25519",
	})
	require.Error(t, err, "the peer must not write under another subject")
}

// otherAuthInfo is a credentials.AuthInfo of another transport.
type otherAuthInfo struct{}

func (otherAuthInfo) AuthType() string { return "other" }

func TestWithPeerIdentity_OnlyAdmittedPeers(t *testing.T) {
	admitted := peerCredentialAuthInfo{credentials: &peercred.Credentials{PID: 7, UID: 1000, GID: 1001}}
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{"admitted peer", peer.NewContext(context.Background(), &peer.Peer{AuthInfo: admitted}), "uid:1000"},
		{"no peer", context.Background(), ""},
		{"another transport's peer", peer.NewContext(context.Background(), &peer.Peer{AuthInfo: otherAuthInfo{}}), ""},
		{"peer without auth info", peer.NewContext(context.Background(), &peer.Peer{}), ""},
		{"peer without credentials", peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peerCredentialAuthInfo{}}), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			identity := auth.GetIdentity(withPeerIdentity(tc.ctx))
			if tc.expected == "" {
				assert.Nil(t, identity)
				return
			}
			require.NotNil(t, identity)
			assert.Equal(t, tc.expected, identity.Subject)
			assert.Equal(t, map[string]string{
				"auth_method": PeerAuthMethod, "uid": "1000", "gid": "1001", "pid": "7",
			}, identity.Metadata)
		})
	}
}

// fakeServerStream is a grpc.ServerStream carrying only a context.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *fakeServerStream) Context() context.Context { return s.ctx }

func TestPeerIdentityStreamInterceptor(t *testing.T) {
	admitted := peerCredentialAuthInfo{credentials: &peercred.Credentials{UID: 0}}
	streams := map[string]struct {
		ctx      context.Context
		expected string
	}{
		"admitted peer": {peer.NewContext(context.Background(), &peer.Peer{AuthInfo: admitted}), "uid:0"},
		"no peer":       {context.Background(), ""},
	}
	for name, tc := range streams {
		t.Run(name, func(t *testing.T) {
			var got *auth.Identity
			err := peerIdentityStreamInterceptor(nil, &fakeServerStream{ctx: tc.ctx}, &grpc.StreamServerInfo{},
				func(_ any, ss grpc.ServerStream) error {
					got = auth.GetIdentity(ss.Context())
					return nil
				})
			require.NoError(t, err)
			if tc.expected == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.expected, got.Subject)
			assert.Equal(t, qrdbsdk.SystemTenantID, got.TenantID)
		})
	}
}

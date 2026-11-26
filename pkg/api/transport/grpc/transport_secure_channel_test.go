// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"net"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// guardOn turns the mandatory-TLS guard back on for one test (TestMain opts
// the package out of it): with the variable empty, the config field decides.
func guardOn(t *testing.T) {
	t.Helper()
	t.Setenv(transport.EnvAllowInsecureTransport, "")
}

func TestNew_RefusesPlaintextTCP(t *testing.T) {
	guardOn(t)

	_, err := New(transport.WithAddress("10.0.0.1:9090"))
	assert.ErrorIs(t, err, transport.ErrInsecureTransport)

	_, err = NewWithConfig(&transport.Config{Address: "127.0.0.1:9090"})
	assert.ErrorIs(t, err, transport.ErrInsecureTransport, "loopback needs the opt-out too")

	_, err = NewWithConfig(nil)
	assert.ErrorIs(t, err, transport.ErrInsecureTransport, "the default config has TLS disabled")
}

func TestNew_AdmitsSecureOrOptedOutEndpoints(t *testing.T) {
	guardOn(t)

	for name, cfg := range map[string]*transport.Config{
		"tls":              {Address: "10.0.0.1:9090", TLSEnabled: true},
		"unix socket":      {Address: "unix:///run/xkms/xkms.sock"},
		"unix path":        {Address: "unix:xkms.sock"},
		"loopback opt-out": {Address: "127.0.0.1:9090", AllowInsecureTransport: true},
		"tls with opt-out": {Address: "10.0.0.1:9090", TLSEnabled: true, AllowInsecureTransport: true},
	} {
		t.Run(name, func(t *testing.T) {
			tr, err := NewWithConfig(cfg)
			require.NoError(t, err)
			assert.Same(t, cfg, tr.Config())
		})
	}

	tr, err := New(transport.WithAddress("127.0.0.1:9090"), transport.WithAllowInsecureTransport(true))
	require.NoError(t, err)
	assert.True(t, tr.Config().AllowInsecureTransport, "the option sets the opt-out")
}

func TestSignImage_RefusesRegistryCredentialsOverPlaintext(t *testing.T) {
	guardOn(t)
	cfg := &transport.Config{Address: "127.0.0.1:9090", AllowInsecureTransport: true}
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)

	// The caller withdraws the opt-out after construction; the credential
	// must still never be sent.
	cfg.AllowInsecureTransport = false
	req := &transport.SignImageRequest{
		Reference: "registry.example/app:1",
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: types.SecretBytes("hunter2")},
	}
	_, err = tr.SignImage(context.Background(), req)
	require.ErrorIs(t, err, transport.ErrInsecureTransport, "refused before the not-connected check, so before any request")
	assert.NotContains(t, err.Error(), "hunter2")
}

func TestSignImage_GuardAdmitsCredentialFreeOrSecureRequests(t *testing.T) {
	guardOn(t)

	plaintext, err := NewWithConfig(&transport.Config{Address: "127.0.0.1:9090", AllowInsecureTransport: true})
	require.NoError(t, err)
	plaintext.Config().AllowInsecureTransport = false
	_, err = plaintext.SignImage(context.Background(), &transport.SignImageRequest{Reference: "registry.example/app:1"})
	assert.ErrorIs(t, err, ErrNotConnected, "a request without registry credentials passes the guard")

	secure, err := NewWithConfig(&transport.Config{Address: "10.0.0.1:9090", TLSEnabled: true})
	require.NoError(t, err)
	_, err = secure.SignImage(context.Background(), &transport.SignImageRequest{
		Reference: "registry.example/app:1",
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: types.SecretBytes("hunter2")},
	})
	assert.ErrorIs(t, err, ErrNotConnected, "credentials over TLS pass the guard")
}

func TestNotLeaderInterceptor_GuardsTheLeaderTarget(t *testing.T) {
	guardOn(t)

	const unixAddress = "unix:///run/xkms/xkms.sock"
	tests := []struct {
		name    string
		cfg     *transport.Config
		leader  string
		wantErr bool
	}{
		{name: "tcp leader over insecure credentials", cfg: &transport.Config{Address: unixAddress}, leader: "10.0.0.2:9443", wantErr: true},
		{name: "unix leader over insecure credentials", cfg: &transport.Config{Address: unixAddress}, leader: "unix:///run/xkms/leader.sock"},
		{name: "tcp leader with the opt-out", cfg: &transport.Config{Address: unixAddress, AllowInsecureTransport: true}, leader: "10.0.0.2:9443"},
		{name: "tcp leader over tls", cfg: &transport.Config{Address: "10.0.0.1:9443", TLSEnabled: true}, leader: "10.0.0.2:9443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Transport{config: tt.cfg, credsOpt: grpc.WithTransportCredentials(insecure.NewCredentials())}
			calls := 0
			invoker := func(_ context.Context, _ string, _, _ interface{}, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
				calls++
				if calls == 1 {
					return notLeaderStatus(t, notLeaderReason, tt.leader)
				}
				return nil
			}

			err := tr.notLeaderInterceptor(context.Background(), "/xkmsv1.KeystoreService/SignImage", nil, nil, nil, invoker)
			if tt.wantErr {
				require.ErrorIs(t, err, transport.ErrInsecureTransport)
				assert.Equal(t, 1, calls, "the request is never replayed to the leader")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 2, calls, "the request is retried once on the leader")
		})
	}
}

// signImageRecorder counts the SignImage requests that reach the server.
type signImageRecorder struct {
	mockKeystoreServer
	calls atomic.Int32
}

func (s *signImageRecorder) SignImage(_ context.Context, _ *pb.SignImageRequest) (*pb.SignedImage, error) {
	s.calls.Add(1)
	return &pb.SignedImage{}, nil
}

// connectPlaintextThenFlip connects over plaintext TCP with the opt-out set,
// then flips the caller's Config to claim TLS and withdraws the opt-out. The
// channel Connect established is still plaintext.
func connectPlaintextThenFlip(t *testing.T) (*Transport, *signImageRecorder) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	rec := &signImageRecorder{}
	srv := grpc.NewServer()
	pb.RegisterKeystoreServiceServer(srv, rec)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	cfg := &transport.Config{Address: lis.Addr().String(), AllowInsecureTransport: true}
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	t.Cleanup(func() { _ = tr.Close() })

	cfg.TLSEnabled = true
	cfg.AllowInsecureTransport = false
	return tr, rec
}

func TestSignImage_GuardChecksTheEstablishedChannelNotTheConfig(t *testing.T) {
	guardOn(t)
	tr, rec := connectPlaintextThenFlip(t)

	_, err := tr.SignImage(context.Background(), &transport.SignImageRequest{
		Reference: "registry.example/app:1",
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: types.SecretBytes("hunter2")},
	})
	require.ErrorIs(t, err, transport.ErrInsecureTransport, "the channel is plaintext whatever the Config now claims")
	assert.Zero(t, rec.calls.Load(), "the registry credential is never sent")
}

func TestRequireSecureTarget_LeaderChecksTheEstablishedChannelNotTheConfig(t *testing.T) {
	guardOn(t)
	tr, _ := connectPlaintextThenFlip(t)

	require.ErrorIs(t, tr.requireSecureTarget("10.0.0.2:9443"), transport.ErrInsecureTransport,
		"the leader is redialed with the cached plaintext credentials")
}

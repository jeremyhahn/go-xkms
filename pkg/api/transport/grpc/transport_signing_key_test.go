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

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/signingkeytest"
)

// SetSigningKeyBinding echoes the requested binding, so a client test can
// see the request arrive.
func (s *mockKeystoreServer) SetSigningKeyBinding(_ context.Context, req *pb.SetSigningKeyBindingRequest) (*pb.SigningKeyBinding, error) {
	return &pb.SigningKeyBinding{Repository: req.GetRepository(), KeyId: req.GetKeyId(), Backend: req.GetBackend()}, nil
}

// GetSigningKeyBinding answers with a binding of the requested repository.
func (s *mockKeystoreServer) GetSigningKeyBinding(_ context.Context, req *pb.GetSigningKeyBindingRequest) (*pb.SigningKeyBinding, error) {
	return &pb.SigningKeyBinding{Repository: req.GetRepository(), KeyId: "app-release"}, nil
}

// ListSigningKeyBindings answers with one binding.
func (s *mockKeystoreServer) ListSigningKeyBindings(context.Context, *pb.ListSigningKeyBindingsRequest) (*pb.ListSigningKeyBindingsResponse, error) {
	return &pb.ListSigningKeyBindingsResponse{Bindings: []*pb.SigningKeyBinding{{Repository: signingkeytest.Repository, KeyId: "app-release"}}}, nil
}

// DeleteSigningKeyBinding accepts every removal.
func (s *mockKeystoreServer) DeleteSigningKeyBinding(context.Context, *pb.DeleteSigningKeyBindingRequest) (*pb.DeleteSigningKeyBindingResponse, error) {
	return &pb.DeleteSigningKeyBindingResponse{}, nil
}

// ResolveSigningKey answers that the release key signs the repository.
func (s *mockKeystoreServer) ResolveSigningKey(_ context.Context, req *pb.ResolveSigningKeyRequest) (*pb.SigningKeyResolution, error) {
	return &pb.SigningKeyResolution{Repository: req.GetRepository(), KeyId: "release-signing", Default: true}, nil
}

func (s *mockKeystoreServer) SignCoRIM(_ context.Context, req *pb.SignCoRIMRequest) (*pb.SignedCoRIM, error) {
	key := &pb.SigningKeyResolution{Repository: req.GetRepository(), KeyId: "release-signing", Default: true}
	return &pb.SignedCoRIM{Key: key, Corim: append([]byte{0xd2}, req.GetCorim()...)}, nil
}

// TestSigningKey_ReachesTheServer proves a connected transport serves the
// signing-key API over its connection: each request reaches the server and
// its answer is decoded. The conversions themselves are tested once, in
// pkg/api/grpc/pbconv.
func TestSigningKey_ReachesTheServer(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ctx := context.Background()

	binding, err := tr.SetSigningKeyBinding(ctx, &transport.SetSigningKeyBindingRequest{Repository: signingkeytest.Repository, KeyID: "app-release", Backend: "pkcs8"})
	require.NoError(t, err)
	assert.Equal(t, "pkcs8", binding.Backend)

	binding, err = tr.GetSigningKeyBinding(ctx, &transport.GetSigningKeyBindingRequest{Repository: signingkeytest.Repository})
	require.NoError(t, err)
	assert.Equal(t, signingkeytest.Repository, binding.Repository)

	list, err := tr.ListSigningKeyBindings(ctx)
	require.NoError(t, err)
	require.Len(t, list.Bindings, 1)
	assert.Equal(t, "app-release", list.Bindings[0].KeyID)

	require.NoError(t, tr.DeleteSigningKeyBinding(ctx, &transport.DeleteSigningKeyBindingRequest{Repository: signingkeytest.Repository}))

	resolution, err := tr.ResolveSigningKey(ctx, &transport.ResolveSigningKeyRequest{Repository: signingkeytest.Repository})
	require.NoError(t, err)
	assert.True(t, resolution.Default)
	assert.Equal(t, "release-signing", resolution.KeyID)

	signed, err := tr.SignCoRIM(ctx, &transport.SignCoRIMRequest{Repository: signingkeytest.Repository, CoRIM: []byte{0xa0}, SignerName: "Acme"})
	require.NoError(t, err)
	assert.Equal(t, "release-signing", signed.Key.KeyID)
	assert.Equal(t, []byte{0xd2, 0xa0}, signed.CoRIM)

	_, err = tr.SignCoRIM(ctx, nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest, "a nil request never reaches the server")
}

// TestSigningKey_NotConnected proves every signing-key method refuses
// before the transport is connected.
func TestSigningKey_NotConnected(t *testing.T) {
	for name, call := range signingkeytest.Calls(context.Background(), newDisconnected(t)) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}

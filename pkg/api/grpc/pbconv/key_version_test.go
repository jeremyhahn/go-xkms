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
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestVersionNumbers proves the int32 wire form clamps rather than wraps,
// and a negative wire number becomes the invalid version 0.
func TestVersionNumbers(t *testing.T) {
	assert.Equal(t, int32(7), KeyVersionToProto(7))
	assert.Equal(t, int32(math.MaxInt32), KeyVersionToProto(math.MaxUint32))
	assert.Equal(t, uint32(7), KeyVersionFromProto(7))
	assert.Equal(t, uint32(0), KeyVersionFromProto(-3))
}

// TestListKeyVersionsResponse_RoundTrip proves every field of a version
// listing survives the wire.
func TestListKeyVersionsResponse_RoundTrip(t *testing.T) {
	in := &transport.ListKeyVersionsResponse{
		KeyID: "k", Backend: "software", CurrentVersion: 2,
		Versions: []transport.KeyVersionInfo{
			{Version: 1, State: transport.KeyVersionRetired, CreatedBy: "alice"},
			{Version: 2, State: transport.KeyVersionEnabled, Current: true, CreatedAt: "2026-09-30T12:00:00Z", PublicKeyPEM: "pem"},
		},
	}
	wire := ListKeyVersionsResponseToProto(in)
	assert.Equal(t, int32(2), wire.GetTotal())
	assert.Equal(t, in, ListKeyVersionsResponseFromProto(wire))
}

// TestVersionStateResponses proves the enable, disable and retire responses
// share one decoding.
func TestVersionStateResponses(t *testing.T) {
	in := &transport.KeyVersionStateResponse{KeyID: "k", Version: 3, State: transport.KeyVersionDisabled, Changed: true}
	assert.Equal(t, in, KeyVersionStateResponseFromProto(EnableKeyVersionResponseToProto(in)))
	assert.Equal(t, in, KeyVersionStateResponseFromProto(DisableKeyVersionResponseToProto(in)))
	assert.Equal(t, in, KeyVersionStateResponseFromProto(RetireKeyVersionResponseToProto(in)))
}

// TestAllKeyVersionsResponses proves both bulk responses round-trip and the
// count follows the versions.
func TestAllKeyVersionsResponses(t *testing.T) {
	in := &transport.AllKeyVersionsResponse{KeyID: "k", State: transport.KeyVersionEnabled, Versions: []uint32{1, 3}, Count: 2}
	assert.Equal(t, in, AllKeyVersionsResponseFromProto(EnableAllKeyVersionsResponseToProto(in)))
	assert.Equal(t, in, AllKeyVersionsResponseFromProto(DisableAllKeyVersionsResponseToProto(in)))
	empty := AllKeyVersionsResponseFromProto(&pb.DisableAllKeyVersionsResponse{KeyId: "k"})
	assert.Empty(t, empty.Versions)
	assert.Zero(t, empty.Count)
}

// TestRotateScopeKeysResponse_RoundTrip proves a scope rotation report,
// failures included, survives the wire.
func TestRotateScopeKeysResponse_RoundTrip(t *testing.T) {
	in := &transport.RotateScopeKeysResponse{
		TenantID: "acme", Rotated: 1, Skipped: 1, Failed: 1,
		Results: []transport.KeyRotationResult{
			{Backend: "software", KeyID: "a", State: transport.KeyRotationRotated, KeyVersion: 2},
			{Backend: "software", KeyID: "b", State: transport.KeyRotationFailed, Error: "cannot be rotated"},
			{Backend: "software", KeyID: "c", State: transport.KeyRotationSkipped, Reason: "has a certificate; re-issue after rotating it explicitly"},
		},
	}
	assert.Equal(t, in, RotateScopeKeysResponseFromProto(RotateScopeKeysResponseToProto(in)))
}

// failingKeystoreClient answers every key-version RPC with err.
type failingKeystoreClient struct {
	pb.KeystoreServiceClient
	err error
}

func (f failingKeystoreClient) ListKeyVersions(context.Context, *pb.ListKeyVersionsRequest, ...grpc.CallOption) (*pb.ListKeyVersionsResponse, error) {
	return nil, f.err
}
func (f failingKeystoreClient) EnableKeyVersion(context.Context, *pb.EnableKeyVersionRequest, ...grpc.CallOption) (*pb.EnableKeyVersionResponse, error) {
	return nil, f.err
}
func (f failingKeystoreClient) DisableKeyVersion(context.Context, *pb.DisableKeyVersionRequest, ...grpc.CallOption) (*pb.DisableKeyVersionResponse, error) {
	return nil, f.err
}
func (f failingKeystoreClient) RetireKeyVersion(context.Context, *pb.RetireKeyVersionRequest, ...grpc.CallOption) (*pb.RetireKeyVersionResponse, error) {
	return nil, f.err
}
func (f failingKeystoreClient) EnableAllKeyVersions(context.Context, *pb.EnableAllKeyVersionsRequest, ...grpc.CallOption) (*pb.EnableAllKeyVersionsResponse, error) {
	return nil, f.err
}
func (f failingKeystoreClient) DisableAllKeyVersions(context.Context, *pb.DisableAllKeyVersionsRequest, ...grpc.CallOption) (*pb.DisableAllKeyVersionsResponse, error) {
	return nil, f.err
}
func (f failingKeystoreClient) RotateScopeKeys(context.Context, *pb.RotateScopeKeysRequest, ...grpc.CallOption) (*pb.RotateScopeKeysResponse, error) {
	return nil, f.err
}

// TestKeyVersionClient_Errors proves the client refuses a nil request
// before any RPC and returns the server's error unchanged.
func TestKeyVersionClient_Errors(t *testing.T) {
	ctx := context.Background()
	rpcErr := errors.New("rpc failed")
	c := KeyVersionClient{Client: failingKeystoreClient{err: rpcErr}}
	version := &transport.KeyVersionRequest{KeyID: "k", Version: 1}
	all := &transport.AllKeyVersionsRequest{KeyID: "k"}

	calls := map[string]struct{ nilReq, withReq func() error }{
		"list": {
			func() error { _, err := c.ListKeyVersions(ctx, nil); return err },
			func() error {
				_, err := c.ListKeyVersions(ctx, &transport.ListKeyVersionsRequest{KeyID: "k"})
				return err
			},
		},
		"enable": {
			func() error { _, err := c.EnableKeyVersion(ctx, nil); return err },
			func() error { _, err := c.EnableKeyVersion(ctx, version); return err },
		},
		"disable": {
			func() error { _, err := c.DisableKeyVersion(ctx, nil); return err },
			func() error { _, err := c.DisableKeyVersion(ctx, version); return err },
		},
		"retire": {
			func() error { _, err := c.RetireKeyVersion(ctx, nil); return err },
			func() error { _, err := c.RetireKeyVersion(ctx, version); return err },
		},
		"enable-all": {
			func() error { _, err := c.EnableAllKeyVersions(ctx, nil); return err },
			func() error { _, err := c.EnableAllKeyVersions(ctx, all); return err },
		},
		"disable-all": {
			func() error { _, err := c.DisableAllKeyVersions(ctx, nil); return err },
			func() error { _, err := c.DisableAllKeyVersions(ctx, all); return err },
		},
		"rotate-all": {
			func() error { _, err := c.RotateScopeKeys(ctx, nil); return err },
			func() error { _, err := c.RotateScopeKeys(ctx, &transport.RotateScopeKeysRequest{}); return err },
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call.nilReq(), ErrNilRequest)
			require.ErrorIs(t, call.withReq(), rpcErr)
		})
	}
}

// TestSealKeyVersion_RoundTrip proves the sealing key version travels with a
// seal's response and back on the matching unseal.
func TestSealKeyVersion_RoundTrip(t *testing.T) {
	sealed, err := SealResponseFromProto(SealResponseToProto(&transport.SealResponse{Backend: "software", Ciphertext: []byte("c"), KeyVersion: 4}))
	require.NoError(t, err)
	assert.Equal(t, uint32(4), sealed.KeyVersion)

	unseal, err := UnsealRequestFromProto(UnsealRequestToProto(&transport.UnsealRequest{Backend: "software", Ciphertext: []byte("c"), KeyVersion: 4}), "acme")
	require.NoError(t, err)
	assert.Equal(t, uint32(4), unseal.KeyVersion)
	assert.Equal(t, "acme", unseal.TenantID)
}

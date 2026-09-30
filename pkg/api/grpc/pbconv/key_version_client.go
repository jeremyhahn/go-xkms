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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Compile-time check that the client serves the whole key-version API.
var _ transport.KeyVersionService = KeyVersionClient{}

// KeyVersionClient serves transport.KeyVersionService over a generated
// xkms.v1 client. The gRPC and Unix-socket transports, which both speak the
// generated protocol, delegate to it once they hold a connection. Errors are
// the server's gRPC status errors, unchanged. The tenant of every call is the
// caller's, which the server takes from the authenticated identity; only
// RotateScopeKeys carries a tenant on the wire.
type KeyVersionClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

// ListKeyVersions lists a key's versions.
func (c KeyVersionClient) ListKeyVersions(ctx context.Context, req *transport.ListKeyVersionsRequest) (*transport.ListKeyVersionsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.ListKeyVersions(ctx, &pb.ListKeyVersionsRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return ListKeyVersionsResponseFromProto(resp), nil
}

// EnableKeyVersion enables a version of a key.
func (c KeyVersionClient) EnableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.EnableKeyVersion(ctx, &pb.EnableKeyVersionRequest{KeyId: req.KeyID, Backend: req.Backend, Version: versionToProto(req.Version)})
	if err != nil {
		return nil, err
	}
	return KeyVersionStateResponseFromProto(resp), nil
}

// DisableKeyVersion disables a version of a key.
func (c KeyVersionClient) DisableKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.DisableKeyVersion(ctx, &pb.DisableKeyVersionRequest{KeyId: req.KeyID, Backend: req.Backend, Version: versionToProto(req.Version)})
	if err != nil {
		return nil, err
	}
	return KeyVersionStateResponseFromProto(resp), nil
}

// RetireKeyVersion retires a version of a key.
func (c KeyVersionClient) RetireKeyVersion(ctx context.Context, req *transport.KeyVersionRequest) (*transport.KeyVersionStateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.RetireKeyVersion(ctx, &pb.RetireKeyVersionRequest{KeyId: req.KeyID, Backend: req.Backend, Version: versionToProto(req.Version)})
	if err != nil {
		return nil, err
	}
	return KeyVersionStateResponseFromProto(resp), nil
}

// EnableAllKeyVersions enables every disabled version of a key.
func (c KeyVersionClient) EnableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.EnableAllKeyVersions(ctx, &pb.EnableAllKeyVersionsRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return AllKeyVersionsResponseFromProto(resp), nil
}

// DisableAllKeyVersions disables every non-current version of a key.
func (c KeyVersionClient) DisableAllKeyVersions(ctx context.Context, req *transport.AllKeyVersionsRequest) (*transport.AllKeyVersionsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.DisableAllKeyVersions(ctx, &pb.DisableAllKeyVersionsRequest{KeyId: req.KeyID, Backend: req.Backend})
	if err != nil {
		return nil, err
	}
	return AllKeyVersionsResponseFromProto(resp), nil
}

// RotateScopeKeys rotates every key of a tenant.
func (c KeyVersionClient) RotateScopeKeys(ctx context.Context, req *transport.RotateScopeKeysRequest) (*transport.RotateScopeKeysResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.RotateScopeKeys(ctx, &pb.RotateScopeKeysRequest{TenantId: req.TenantID})
	if err != nil {
		return nil, err
	}
	return RotateScopeKeysResponseFromProto(resp), nil
}

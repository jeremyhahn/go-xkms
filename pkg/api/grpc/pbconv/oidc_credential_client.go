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

	"google.golang.org/grpc"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Compile-time check that the client serves the whole OIDC credential API.
var _ transport.OIDCCredentialService = OIDCCredentialClient{}

// OIDCCredentialClient serves transport.OIDCCredentialService over a
// generated xkms.v1 client. The gRPC and Unix-socket transports, which both
// speak the generated protocol, delegate to it once they hold a connection.
// Errors are the server's gRPC status errors, unchanged.
type OIDCCredentialClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

// OIDCCredentialCreate creates a credential.
func (c OIDCCredentialClient) OIDCCredentialCreate(ctx context.Context, req *transport.OIDCCredentialCreateRequest) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.OIDCCredentialCreate(ctx, OIDCCredentialCreateRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return OIDCCredentialFromProto(resp), nil
}

// OIDCCredentialImport imports tokens into a credential.
func (c OIDCCredentialClient) OIDCCredentialImport(ctx context.Context, req *transport.OIDCCredentialImportRequest) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.OIDCCredentialImport(ctx, OIDCCredentialImportRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return OIDCCredentialFromProto(resp), nil
}

// OIDCCredentialGet returns a credential's public view.
func (c OIDCCredentialClient) OIDCCredentialGet(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credentialCall(ctx, req, c.Client.OIDCCredentialGet)
}

// OIDCCredentialList lists the credentials the caller can see.
func (c OIDCCredentialClient) OIDCCredentialList(ctx context.Context, req *transport.OIDCCredentialListRequest) (*transport.OIDCCredentialListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.OIDCCredentialList(ctx, &pb.OIDCCredentialListRequest{TenantId: req.TenantID})
	if err != nil {
		return nil, err
	}
	return OIDCCredentialListResponseFromProto(resp), nil
}

// OIDCCredentialDelete deletes a credential.
func (c OIDCCredentialClient) OIDCCredentialDelete(ctx context.Context, req *transport.OIDCCredentialRef) error {
	if req == nil {
		return ErrNilRequest
	}
	_, err := c.Client.OIDCCredentialDelete(ctx, OIDCCredentialRefToProto(req))
	return err
}

// OIDCCredentialRefresh refreshes a credential now.
func (c OIDCCredentialClient) OIDCCredentialRefresh(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credentialCall(ctx, req, c.Client.OIDCCredentialRefresh)
}

// OIDCCredentialGetAccessToken returns a current access token.
func (c OIDCCredentialClient) OIDCCredentialGetAccessToken(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCAccessToken, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.OIDCCredentialGetAccessToken(ctx, OIDCCredentialRefToProto(req))
	if err != nil {
		return nil, err
	}
	return OIDCAccessTokenFromProto(resp), nil
}

// OIDCCredentialDeviceStart starts a device login.
func (c OIDCCredentialClient) OIDCCredentialDeviceStart(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credentialCall(ctx, req, c.Client.OIDCCredentialDeviceStart)
}

// OIDCCredentialDevicePoll polls a device login once.
func (c OIDCCredentialClient) OIDCCredentialDevicePoll(ctx context.Context, req *transport.OIDCCredentialRef) (*transport.OIDCCredential, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	return c.credentialCall(ctx, req, c.Client.OIDCCredentialDevicePoll)
}

// credentialCall runs rpc, an RPC that takes a credential reference and
// returns the credential's view. The caller has refused a nil request,
// before naming rpc on a client that may be unset.
func (c OIDCCredentialClient) credentialCall(ctx context.Context, req *transport.OIDCCredentialRef,
	rpc func(context.Context, *pb.OIDCCredentialRef, ...grpc.CallOption) (*pb.OIDCCredential, error)) (*transport.OIDCCredential, error) {

	resp, err := rpc(ctx, OIDCCredentialRefToProto(req))
	if err != nil {
		return nil, err
	}
	return OIDCCredentialFromProto(resp), nil
}

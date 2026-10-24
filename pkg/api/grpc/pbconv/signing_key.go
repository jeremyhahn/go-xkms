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

// SigningKeyBindingToProto converts a binding to its wire form.
func SigningKeyBindingToProto(b *transport.SigningKeyBinding) *pb.SigningKeyBinding {
	if b == nil {
		return nil
	}
	return &pb.SigningKeyBinding{
		Repository: b.Repository,
		KeyId:      b.KeyID,
		Backend:    b.Backend,
		UpdatedAt:  timeToProto(b.UpdatedAt),
	}
}

// SigningKeyBindingFromProto converts a wire binding.
func SigningKeyBindingFromProto(b *pb.SigningKeyBinding) *transport.SigningKeyBinding {
	if b == nil {
		return nil
	}
	return &transport.SigningKeyBinding{
		Repository: b.GetRepository(),
		KeyID:      b.GetKeyId(),
		Backend:    b.GetBackend(),
		UpdatedAt:  timeFromProto(b.GetUpdatedAt()),
	}
}

// ListSigningKeyBindingsResponseToProto converts a binding list.
func ListSigningKeyBindingsResponseToProto(r *transport.ListSigningKeyBindingsResponse) *pb.ListSigningKeyBindingsResponse {
	out := &pb.ListSigningKeyBindingsResponse{}
	if r == nil {
		return out
	}
	for _, b := range r.Bindings {
		out.Bindings = append(out.Bindings, SigningKeyBindingToProto(b))
	}
	return out
}

// ListSigningKeyBindingsResponseFromProto converts a wire binding list.
func ListSigningKeyBindingsResponseFromProto(r *pb.ListSigningKeyBindingsResponse) *transport.ListSigningKeyBindingsResponse {
	out := &transport.ListSigningKeyBindingsResponse{Bindings: []*transport.SigningKeyBinding{}}
	for _, b := range r.GetBindings() {
		out.Bindings = append(out.Bindings, SigningKeyBindingFromProto(b))
	}
	return out
}

// SetSigningKeyBindingRequestFromProto converts a wire binding request.
func SetSigningKeyBindingRequestFromProto(r *pb.SetSigningKeyBindingRequest) *transport.SetSigningKeyBindingRequest {
	return &transport.SetSigningKeyBindingRequest{
		Repository: r.GetRepository(),
		KeyID:      r.GetKeyId(),
		Backend:    r.GetBackend(),
	}
}

// GetSigningKeyBindingRequestFromProto converts a wire binding lookup.
func GetSigningKeyBindingRequestFromProto(r *pb.GetSigningKeyBindingRequest) *transport.GetSigningKeyBindingRequest {
	return &transport.GetSigningKeyBindingRequest{Repository: r.GetRepository()}
}

// DeleteSigningKeyBindingRequestFromProto converts a wire binding removal.
func DeleteSigningKeyBindingRequestFromProto(r *pb.DeleteSigningKeyBindingRequest) *transport.DeleteSigningKeyBindingRequest {
	return &transport.DeleteSigningKeyBindingRequest{Repository: r.GetRepository()}
}

// ResolveSigningKeyRequestFromProto converts a wire resolution request.
func ResolveSigningKeyRequestFromProto(r *pb.ResolveSigningKeyRequest) *transport.ResolveSigningKeyRequest {
	return &transport.ResolveSigningKeyRequest{Repository: r.GetRepository()}
}

// SigningKeyResolutionToProto converts a resolution to its wire form.
func SigningKeyResolutionToProto(r *transport.SigningKeyResolution) *pb.SigningKeyResolution {
	if r == nil {
		return nil
	}
	return &pb.SigningKeyResolution{
		Repository: r.Repository,
		KeyId:      r.KeyID,
		Backend:    r.Backend,
		Default:    r.Default,
	}
}

// SigningKeyResolutionFromProto converts a wire resolution.
func SigningKeyResolutionFromProto(r *pb.SigningKeyResolution) *transport.SigningKeyResolution {
	if r == nil {
		return nil
	}
	return &transport.SigningKeyResolution{
		Repository: r.GetRepository(),
		KeyID:      r.GetKeyId(),
		Backend:    r.GetBackend(),
		Default:    r.GetDefault(),
	}
}

// SignCoRIMRequestToProto converts a transport SignCoRIMRequest.
func SignCoRIMRequestToProto(r *transport.SignCoRIMRequest) *pb.SignCoRIMRequest {
	return &pb.SignCoRIMRequest{
		Repository: r.Repository,
		Corim:      r.CoRIM,
		SignerName: r.SignerName,
		SignerUri:  r.SignerURI,
		NotBefore:  timeToProto(r.NotBefore),
		NotAfter:   timeToProto(r.NotAfter),
	}
}

// SignCoRIMRequestFromProto converts a protobuf SignCoRIMRequest.
func SignCoRIMRequestFromProto(r *pb.SignCoRIMRequest) *transport.SignCoRIMRequest {
	return &transport.SignCoRIMRequest{
		Repository: r.GetRepository(),
		CoRIM:      r.GetCorim(),
		SignerName: r.GetSignerName(),
		SignerURI:  r.GetSignerUri(),
		NotBefore:  timeFromProto(r.GetNotBefore()),
		NotAfter:   timeFromProto(r.GetNotAfter()),
	}
}

// SignedCoRIMToProto converts a transport SignedCoRIM.
func SignedCoRIMToProto(s *transport.SignedCoRIM) *pb.SignedCoRIM {
	if s == nil {
		return nil
	}
	return &pb.SignedCoRIM{Key: SigningKeyResolutionToProto(&s.Key), Corim: s.CoRIM}
}

// SignedCoRIMFromProto converts a protobuf SignedCoRIM.
func SignedCoRIMFromProto(s *pb.SignedCoRIM) *transport.SignedCoRIM {
	if s == nil {
		return nil
	}
	out := &transport.SignedCoRIM{CoRIM: s.GetCorim()}
	if key := SigningKeyResolutionFromProto(s.GetKey()); key != nil {
		out.Key = *key
	}
	return out
}

// Compile-time check that the client serves the whole signing-key API.
var _ transport.SigningKeyService = SigningKeyClient{}

// SigningKeyClient serves transport.SigningKeyService over a generated
// xkms.v1 client. The gRPC and Unix-socket transports, which both speak the
// generated protocol, delegate to it once they hold a connection. Errors are
// the server's gRPC status errors, unchanged.
type SigningKeyClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

// SetSigningKeyBinding names the key that signs a repository.
func (c SigningKeyClient) SetSigningKeyBinding(ctx context.Context, req *transport.SetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.SetSigningKeyBinding(ctx, &pb.SetSigningKeyBindingRequest{
		Repository: req.Repository, KeyId: req.KeyID, Backend: req.Backend,
	})
	if err != nil {
		return nil, err
	}
	return SigningKeyBindingFromProto(resp), nil
}

// GetSigningKeyBinding returns a repository's binding.
func (c SigningKeyClient) GetSigningKeyBinding(ctx context.Context, req *transport.GetSigningKeyBindingRequest) (*transport.SigningKeyBinding, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.GetSigningKeyBinding(ctx, &pb.GetSigningKeyBindingRequest{Repository: req.Repository})
	if err != nil {
		return nil, err
	}
	return SigningKeyBindingFromProto(resp), nil
}

// ListSigningKeyBindings returns the caller's tenant's bindings.
func (c SigningKeyClient) ListSigningKeyBindings(ctx context.Context) (*transport.ListSigningKeyBindingsResponse, error) {
	resp, err := c.Client.ListSigningKeyBindings(ctx, &pb.ListSigningKeyBindingsRequest{})
	if err != nil {
		return nil, err
	}
	return ListSigningKeyBindingsResponseFromProto(resp), nil
}

// DeleteSigningKeyBinding removes a repository's binding.
func (c SigningKeyClient) DeleteSigningKeyBinding(ctx context.Context, req *transport.DeleteSigningKeyBindingRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	_, err := c.Client.DeleteSigningKeyBinding(ctx, &pb.DeleteSigningKeyBindingRequest{Repository: req.Repository})
	return err
}

// ResolveSigningKey returns the key that signs a repository.
func (c SigningKeyClient) ResolveSigningKey(ctx context.Context, req *transport.ResolveSigningKeyRequest) (*transport.SigningKeyResolution, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.ResolveSigningKey(ctx, &pb.ResolveSigningKeyRequest{Repository: req.Repository})
	if err != nil {
		return nil, err
	}
	return SigningKeyResolutionFromProto(resp), nil
}

// SignCoRIM implements transport.SigningKeyService.
func (c SigningKeyClient) SignCoRIM(ctx context.Context, req *transport.SignCoRIMRequest) (*transport.SignedCoRIM, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.SignCoRIM(ctx, SignCoRIMRequestToProto(req))
	if err != nil {
		return nil, err
	}
	return SignedCoRIMFromProto(resp), nil
}

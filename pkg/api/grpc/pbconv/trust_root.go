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

// TrustRootToProto converts a trust root to its proto form.
func TrustRootToProto(r *transport.TrustRoot) *pb.TrustRoot {
	return &pb.TrustRoot{
		Fingerprint: r.Fingerprint,
		Purpose:     r.Purpose,
		Subject:     r.Subject,
		Issuer:      r.Issuer,
		Algorithm:   r.Algorithm,
		NotBefore:   r.NotBefore,
		NotAfter:    r.NotAfter,
		AddedAt:     r.AddedAt,
		Source:      r.Source,
		Pem:         r.PEM,
	}
}

// TrustRootFromProto converts a proto trust root to its transport form.
func TrustRootFromProto(r *pb.TrustRoot) *transport.TrustRoot {
	return &transport.TrustRoot{
		Fingerprint: r.GetFingerprint(),
		Purpose:     r.GetPurpose(),
		Subject:     r.GetSubject(),
		Issuer:      r.GetIssuer(),
		Algorithm:   r.GetAlgorithm(),
		NotBefore:   r.GetNotBefore(),
		NotAfter:    r.GetNotAfter(),
		AddedAt:     r.GetAddedAt(),
		Source:      r.GetSource(),
		PEM:         r.GetPem(),
	}
}

// TrustRootListResponseToProto converts a trust-root list to its proto form.
func TrustRootListResponseToProto(r *transport.TrustRootListResponse) *pb.TrustRootListResponse {
	out := &pb.TrustRootListResponse{Roots: make([]*pb.TrustRoot, 0, len(r.Roots))}
	for i := range r.Roots {
		out.Roots = append(out.Roots, TrustRootToProto(&r.Roots[i]))
	}
	return out
}

// TrustRootListResponseFromProto converts a proto trust-root list to its
// transport form.
func TrustRootListResponseFromProto(r *pb.TrustRootListResponse) *transport.TrustRootListResponse {
	out := &transport.TrustRootListResponse{Roots: make([]transport.TrustRoot, 0, len(r.GetRoots()))}
	for _, root := range r.GetRoots() {
		out.Roots = append(out.Roots, *TrustRootFromProto(root))
	}
	return out
}

// TrustRootImportRequestFromProto converts a proto import request to its
// transport form.
func TrustRootImportRequestFromProto(r *pb.TrustRootImportRequest) *transport.TrustRootImportRequest {
	return &transport.TrustRootImportRequest{PEM: r.GetPem(), Purpose: r.GetPurpose(), Source: r.GetSource()}
}

// Compile-time check that the client serves the whole trust-root API.
var _ transport.TrustRootService = TrustRootClient{}

// TrustRootClient serves transport.TrustRootService over a generated
// xkms.v1 client, for the gRPC and Unix-socket transports. Errors are the
// server's gRPC status errors, unchanged.
type TrustRootClient struct {
	// Client is the connected generated client.
	Client pb.KeystoreServiceClient
}

// TrustRootList lists the trust roots, optionally of one purpose.
func (c TrustRootClient) TrustRootList(ctx context.Context, req *transport.TrustRootListRequest) (*transport.TrustRootListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TrustRootList(ctx, &pb.TrustRootListRequest{Purpose: req.Purpose})
	if err != nil {
		return nil, err
	}
	return TrustRootListResponseFromProto(resp), nil
}

// TrustRootGet returns one trust root, its PEM included.
func (c TrustRootClient) TrustRootGet(ctx context.Context, req *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TrustRootGet(ctx, &pb.TrustRootRequest{Fingerprint: req.Fingerprint})
	if err != nil {
		return nil, err
	}
	return TrustRootFromProto(resp), nil
}

// TrustRootImport adds the certificates of a PEM bundle.
func (c TrustRootClient) TrustRootImport(ctx context.Context, req *transport.TrustRootImportRequest) (*transport.TrustRootImportResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TrustRootImport(ctx, &pb.TrustRootImportRequest{Pem: req.PEM, Purpose: req.Purpose, Source: req.Source})
	if err != nil {
		return nil, err
	}
	return &transport.TrustRootImportResponse{Added: int(resp.GetAdded()), Skipped: int(resp.GetSkipped())}, nil
}

// TrustRootQuarantine reclassifies a trust root as synced.
func (c TrustRootClient) TrustRootQuarantine(ctx context.Context, req *transport.TrustRootRequest) (*transport.TrustRoot, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	resp, err := c.Client.TrustRootQuarantine(ctx, &pb.TrustRootRequest{Fingerprint: req.Fingerprint})
	if err != nil {
		return nil, err
	}
	return TrustRootFromProto(resp), nil
}

// TrustRootRemove deletes a trust root.
func (c TrustRootClient) TrustRootRemove(ctx context.Context, req *transport.TrustRootRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	_, err := c.Client.TrustRootRemove(ctx, &pb.TrustRootRequest{Fingerprint: req.Fingerprint})
	return err
}

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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// GetTransparencyLogHead returns the CA transparency log's signed tree head.
func (t *Transport) GetTransparencyLogHead(ctx context.Context, _ *transport.GetTransparencyLogHeadRequest) (*transport.GetTransparencyLogHeadResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	resp, err := t.client.GetTransparencyLogHead(ctx, &pb.GetTransparencyLogHeadRequest{})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "get transparency log head failed", Err: err}
	}
	return &transport.GetTransparencyLogHeadResponse{
		Checkpoint: resp.GetCheckpoint(),
		Origin:     resp.GetOrigin(),
		Size:       resp.GetSize(),
		RootHash:   resp.GetRootHash(),
	}, nil
}

// GetTransparencyLogEntry returns one encoded CA transparency log entry.
func (t *Transport) GetTransparencyLogEntry(ctx context.Context, req *transport.GetTransparencyLogEntryRequest) (*transport.GetTransparencyLogEntryResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	resp, err := t.client.GetTransparencyLogEntry(ctx, &pb.GetTransparencyLogEntryRequest{Index: req.Index})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "get transparency log entry failed", Err: err}
	}
	return &transport.GetTransparencyLogEntryResponse{Index: resp.GetIndex(), Entry: resp.GetEntry()}, nil
}

// GetTransparencyLogInclusionProof returns an entry's inclusion proof.
func (t *Transport) GetTransparencyLogInclusionProof(ctx context.Context, req *transport.GetTransparencyLogInclusionProofRequest) (*transport.GetTransparencyLogInclusionProofResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	resp, err := t.client.GetTransparencyLogInclusionProof(ctx, &pb.GetTransparencyLogInclusionProofRequest{Index: req.Index, TreeSize: req.TreeSize})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "get transparency log inclusion proof failed", Err: err}
	}
	return &transport.GetTransparencyLogInclusionProofResponse{
		Index:    resp.GetIndex(),
		TreeSize: resp.GetTreeSize(),
		Hashes:   resp.GetHashes(),
	}, nil
}

// GetTransparencyLogConsistencyProof returns the consistency proof between
// two tree sizes.
func (t *Transport) GetTransparencyLogConsistencyProof(ctx context.Context, req *transport.GetTransparencyLogConsistencyProofRequest) (*transport.GetTransparencyLogConsistencyProofResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	resp, err := t.client.GetTransparencyLogConsistencyProof(ctx, &pb.GetTransparencyLogConsistencyProofRequest{FirstSize: req.FirstSize, SecondSize: req.SecondSize})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "get transparency log consistency proof failed", Err: err}
	}
	return &transport.GetTransparencyLogConsistencyProofResponse{
		FirstSize:  resp.GetFirstSize(),
		SecondSize: resp.GetSecondSize(),
		Hashes:     resp.GetHashes(),
	}, nil
}

// AppendTransparencyLogExternal appends an external entry under the caller's
// SPIFFE ID, which the server reads from this client's certificate.
func (t *Transport) AppendTransparencyLogExternal(ctx context.Context, req *transport.AppendTransparencyLogExternalRequest) (*transport.AppendTransparencyLogExternalResponse, error) {
	if t.client == nil {
		return nil, ErrNotConnected
	}
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	resp, err := t.client.AppendTransparencyLogExternal(ctx, &pb.AppendTransparencyLogExternalRequest{Payload: req.Payload})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "append transparency log external entry failed", Err: err}
	}
	return &transport.AppendTransparencyLogExternalResponse{Index: resp.GetIndex()}, nil
}

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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// GetTransparencyLogHead returns the CA transparency log's signed tree head.
func (t *Transport) GetTransparencyLogHead(ctx context.Context, req *transport.GetTransparencyLogHeadRequest) (*transport.GetTransparencyLogHeadResponse, error) {
	var result transport.GetTransparencyLogHeadResponse
	if err := t.rpcCall(ctx, "xkms.ca.transparency-log.head", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTransparencyLogEntry returns one encoded CA transparency log entry.
func (t *Transport) GetTransparencyLogEntry(ctx context.Context, req *transport.GetTransparencyLogEntryRequest) (*transport.GetTransparencyLogEntryResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	var result transport.GetTransparencyLogEntryResponse
	if err := t.rpcCall(ctx, "xkms.ca.transparency-log.entry", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTransparencyLogInclusionProof returns an entry's inclusion proof.
func (t *Transport) GetTransparencyLogInclusionProof(ctx context.Context, req *transport.GetTransparencyLogInclusionProofRequest) (*transport.GetTransparencyLogInclusionProofResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	var result transport.GetTransparencyLogInclusionProofResponse
	if err := t.rpcCall(ctx, "xkms.ca.transparency-log.inclusion-proof", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetTransparencyLogConsistencyProof returns the consistency proof between
// two tree sizes.
func (t *Transport) GetTransparencyLogConsistencyProof(ctx context.Context, req *transport.GetTransparencyLogConsistencyProofRequest) (*transport.GetTransparencyLogConsistencyProofResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	var result transport.GetTransparencyLogConsistencyProofResponse
	if err := t.rpcCall(ctx, "xkms.ca.transparency-log.consistency-proof", req, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

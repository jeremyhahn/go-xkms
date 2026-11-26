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

package quic

import (
	"context"
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// GetTransparencyLogHead returns the CA transparency log's signed tree head.
func (t *Transport) GetTransparencyLogHead(ctx context.Context, _ *transport.GetTransparencyLogHeadRequest) (*transport.GetTransparencyLogHeadResponse, error) {
	var resp transport.GetTransparencyLogHeadResponse
	if err := t.DoRequest(ctx, http.MethodGet, transport.TransparencyLogHeadPath, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetTransparencyLogEntry returns one encoded CA transparency log entry.
func (t *Transport) GetTransparencyLogEntry(ctx context.Context, req *transport.GetTransparencyLogEntryRequest) (*transport.GetTransparencyLogEntryResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	var resp transport.GetTransparencyLogEntryResponse
	if err := t.DoRequest(ctx, http.MethodGet, transport.TransparencyLogEntryPath(req.Index), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetTransparencyLogInclusionProof returns an entry's inclusion proof.
func (t *Transport) GetTransparencyLogInclusionProof(ctx context.Context, req *transport.GetTransparencyLogInclusionProofRequest) (*transport.GetTransparencyLogInclusionProofResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	var resp transport.GetTransparencyLogInclusionProofResponse
	if err := t.DoRequest(ctx, http.MethodGet, transport.TransparencyLogInclusionProofPath(req), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetTransparencyLogConsistencyProof returns the consistency proof between
// two tree sizes.
func (t *Transport) GetTransparencyLogConsistencyProof(ctx context.Context, req *transport.GetTransparencyLogConsistencyProofRequest) (*transport.GetTransparencyLogConsistencyProofResponse, error) {
	if req == nil {
		return nil, transport.ErrInvalidRequest
	}
	var resp transport.GetTransparencyLogConsistencyProofResponse
	if err := t.DoRequest(ctx, http.MethodGet, transport.TransparencyLogConsistencyProofPath(req), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

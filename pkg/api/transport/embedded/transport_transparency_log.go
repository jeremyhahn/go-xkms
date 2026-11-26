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

package embedded

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// GetTransparencyLogHead returns the CA transparency log's signed tree head.
func (t *Transport) GetTransparencyLogHead(ctx context.Context, req *transport.GetTransparencyLogHeadRequest) (*transport.GetTransparencyLogHeadResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetTransparencyLogHead(ctx, req)
}

// GetTransparencyLogEntry returns one encoded CA transparency log entry.
func (t *Transport) GetTransparencyLogEntry(ctx context.Context, req *transport.GetTransparencyLogEntryRequest) (*transport.GetTransparencyLogEntryResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetTransparencyLogEntry(ctx, req)
}

// GetTransparencyLogInclusionProof returns an entry's inclusion proof.
func (t *Transport) GetTransparencyLogInclusionProof(ctx context.Context, req *transport.GetTransparencyLogInclusionProofRequest) (*transport.GetTransparencyLogInclusionProofResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetTransparencyLogInclusionProof(ctx, req)
}

// GetTransparencyLogConsistencyProof returns the consistency proof between
// two tree sizes.
func (t *Transport) GetTransparencyLogConsistencyProof(ctx context.Context, req *transport.GetTransparencyLogConsistencyProofRequest) (*transport.GetTransparencyLogConsistencyProofResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetTransparencyLogConsistencyProof(ctx, req)
}

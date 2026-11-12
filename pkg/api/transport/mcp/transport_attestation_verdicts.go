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

// The continuous attestation verdict verbs reach the server's
// attestation.verdict.* methods.

var _ transport.AttestationVerdictService = (*Transport)(nil)

// ListAttestationVerdicts returns a device's verdicts, oldest first.
func (t *Transport) ListAttestationVerdicts(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.ListAttestationVerdictsResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.ListAttestationVerdictsResponse
	if err := t.rpcCall(ctx, "attestation.verdict.list", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetLatestAttestationVerdict returns a device's newest verdict.
func (t *Transport) GetLatestAttestationVerdict(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.AttestationVerdict
	if err := t.rpcCall(ctx, "attestation.verdict.latest", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReattestDevice re-attests a device now and returns the verdict.
func (t *Transport) ReattestDevice(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.AttestationVerdict
	if err := t.rpcCall(ctx, "attestation.verdict.reattest", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

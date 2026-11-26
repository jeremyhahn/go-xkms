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

// The attestation Verifier (go-xkms#1608) over the MCP JSON-RPC methods
// attestation.endorsement.*, attestation.reference_values.* and
// attestation.quote.appraise.

// PutAttestationEndorsement stores a trust anchor.
func (t *Transport) PutAttestationEndorsement(ctx context.Context, req *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.AttestationEndorsement
	if err := t.rpcCall(ctx, "attestation.endorsement.put", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListAttestationEndorsements lists trust anchors, optionally by kind.
func (t *Transport) ListAttestationEndorsements(ctx context.Context, req *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.ListAttestationEndorsementsResponse
	if err := t.rpcCall(ctx, "attestation.endorsement.list", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteAttestationEndorsement removes a trust anchor.
func (t *Transport) DeleteAttestationEndorsement(ctx context.Context, req *transport.DeleteAttestationEndorsementRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "attestation.endorsement.delete", req, nil)
}

// PutAttestationReferenceValues verifies and stores a signed CoRIM.
func (t *Transport) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.AttestationReferenceValues
	if err := t.rpcCall(ctx, "attestation.reference_values.put", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetAttestationReferenceValues returns stored reference values.
func (t *Transport) GetAttestationReferenceValues(ctx context.Context, req *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.AttestationReferenceValues
	if err := t.rpcCall(ctx, "attestation.reference_values.get", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListAttestationReferenceValues lists stored reference values.
func (t *Transport) ListAttestationReferenceValues(ctx context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.ListAttestationReferenceValuesResponse
	if err := t.rpcCall(ctx, "attestation.reference_values.list", struct{}{}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteAttestationReferenceValues removes stored reference values.
func (t *Transport) DeleteAttestationReferenceValues(ctx context.Context, req *transport.DeleteAttestationReferenceValuesRequest) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, "attestation.reference_values.delete", req, nil)
}

// AppraiseAttestationQuote appraises TPM quote evidence.
func (t *Transport) AppraiseAttestationQuote(ctx context.Context, req *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp transport.AttestationResult
	if err := t.rpcCall(ctx, "attestation.quote.appraise", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

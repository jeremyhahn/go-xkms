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

// The attestation Verifier's appraisal API (row 1660) over the MCP JSON-RPC
// methods attestation.endorsement.*, attestation.reference_values.* and
// attestation.appraise.

var _ transport.AttestationAppraisalService = (*Transport)(nil)

// appraisalCall sends one appraisal request and decodes the result into a R.
func appraisalCall[R any](t *Transport, ctx context.Context, method string, params any) (*R, error) {
	if !t.IsConnected() {
		return nil, ErrNotConnected
	}
	var resp R
	if err := t.rpcCall(ctx, method, params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// appraisalDelete sends one appraisal delete request.
func (t *Transport) appraisalDelete(ctx context.Context, method string, params any) error {
	if !t.IsConnected() {
		return ErrNotConnected
	}
	return t.rpcCall(ctx, method, params, nil)
}

// PutAttestationEndorsement stores a trust anchor.
func (t *Transport) PutAttestationEndorsement(ctx context.Context, req *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	return appraisalCall[transport.AttestationEndorsement](t, ctx, "attestation.endorsement.put", req)
}

// ListAttestationEndorsements lists the trust anchors, optionally by kind.
func (t *Transport) ListAttestationEndorsements(ctx context.Context, req *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	return appraisalCall[transport.ListAttestationEndorsementsResponse](t, ctx, "attestation.endorsement.list", req)
}

// DeleteAttestationEndorsement removes a trust anchor.
func (t *Transport) DeleteAttestationEndorsement(ctx context.Context, req *transport.DeleteAttestationEndorsementRequest) error {
	return t.appraisalDelete(ctx, "attestation.endorsement.delete", req)
}

// PutAttestationReferenceValues verifies a signed CoRIM and stores its
// reference values.
func (t *Transport) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	return appraisalCall[transport.AttestationReferenceValues](t, ctx, "attestation.reference_values.put", req)
}

// GetAttestationReferenceValues returns stored reference values.
func (t *Transport) GetAttestationReferenceValues(ctx context.Context, req *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	return appraisalCall[transport.AttestationReferenceValues](t, ctx, "attestation.reference_values.get", req)
}

// ListAttestationReferenceValues lists the stored reference values.
func (t *Transport) ListAttestationReferenceValues(ctx context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	return appraisalCall[transport.ListAttestationReferenceValuesResponse](t, ctx, "attestation.reference_values.list", struct{}{})
}

// DeleteAttestationReferenceValues removes stored reference values.
func (t *Transport) DeleteAttestationReferenceValues(ctx context.Context, req *transport.DeleteAttestationReferenceValuesRequest) error {
	return t.appraisalDelete(ctx, "attestation.reference_values.delete", req)
}

// AppraiseAttestationQuote appraises a TPM quote and returns the attestation
// result.
func (t *Transport) AppraiseAttestationQuote(ctx context.Context, req *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	return appraisalCall[transport.AttestationResult](t, ctx, "attestation.appraise", req)
}

// AppraiseAndroidKeyAttestation is a placeholder the MCP commit of row
// 1660 slice A replaces.
func (t *Transport) AppraiseAndroidKeyAttestation(_ context.Context, _ *transport.AppraiseAndroidKeyAttestationRequest) (*transport.AttestationResult, error) {
	return nil, ErrNotSupported
}

// AppraiseEKCertificate is a placeholder the MCP commit of row 1660 slice
// A replaces.
func (t *Transport) AppraiseEKCertificate(_ context.Context, _ *transport.AppraiseEKCertificateRequest) (*transport.AttestationResult, error) {
	return nil, ErrNotSupported
}

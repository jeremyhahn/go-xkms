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

package wire

import (
	"context"
	"net/http"
	"net/url"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The attestation Verifier routes (go-xkms#1608). Endorsements and
// reference values are collections of the caller's tenant's named records;
// AttestationAppraisePath appraises quote evidence.
const (
	AttestationEndorsementsPath    = "/api/v1/attestation/endorsements"
	AttestationReferenceValuesPath = "/api/v1/attestation/reference-values"
	AttestationAppraisePath        = "/api/v1/attestation/appraise"
)

// AttestationEndorsementKindParam filters the endorsement list by kind.
const AttestationEndorsementKindParam = "kind"

// Compile-time check that the client serves the whole Verifier API.
var _ transport.AttestationAppraisalService = AttestationAppraisalClient{}

// AttestationAppraisalClient serves transport.AttestationAppraisalService
// over the REST routes. The REST and QUIC transports (QUIC serves the same
// router over HTTP/3) delegate to it with their own Requester.
type AttestationAppraisalClient struct {
	// Do performs the requests.
	Do Requester
}

// PutAttestationEndorsement stores a trust anchor.
func (c AttestationAppraisalClient) PutAttestationEndorsement(ctx context.Context, req *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.AttestationEndorsement
	if err := callJSON(ctx, c.Do, http.MethodPut, AttestationEndorsementsPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListAttestationEndorsements lists trust anchors, optionally by kind.
func (c AttestationAppraisalClient) ListAttestationEndorsements(ctx context.Context, req *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	path := withQuery(AttestationEndorsementsPath, map[string]string{AttestationEndorsementKindParam: string(req.Kind)})
	var resp transport.ListAttestationEndorsementsResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteAttestationEndorsement removes a trust anchor.
func (c AttestationAppraisalClient) DeleteAttestationEndorsement(ctx context.Context, req *transport.DeleteAttestationEndorsementRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return callJSON(ctx, c.Do, http.MethodDelete, AttestationEndorsementsPath+"/"+url.PathEscape(req.Name), nil, nil)
}

// PutAttestationReferenceValues verifies and stores a signed CoRIM.
func (c AttestationAppraisalClient) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.AttestationReferenceValues
	if err := callJSON(ctx, c.Do, http.MethodPut, AttestationReferenceValuesPath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetAttestationReferenceValues returns stored reference values.
func (c AttestationAppraisalClient) GetAttestationReferenceValues(ctx context.Context, req *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.AttestationReferenceValues
	if err := callJSON(ctx, c.Do, http.MethodGet, AttestationReferenceValuesPath+"/"+url.PathEscape(req.Name), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListAttestationReferenceValues lists stored reference values.
func (c AttestationAppraisalClient) ListAttestationReferenceValues(ctx context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	var resp transport.ListAttestationReferenceValuesResponse
	if err := callJSON(ctx, c.Do, http.MethodGet, AttestationReferenceValuesPath, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteAttestationReferenceValues removes stored reference values.
func (c AttestationAppraisalClient) DeleteAttestationReferenceValues(ctx context.Context, req *transport.DeleteAttestationReferenceValuesRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return callJSON(ctx, c.Do, http.MethodDelete, AttestationReferenceValuesPath+"/"+url.PathEscape(req.Name), nil, nil)
}

// AppraiseAttestationQuote appraises TPM quote evidence.
func (c AttestationAppraisalClient) AppraiseAttestationQuote(ctx context.Context, req *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	var resp transport.AttestationResult
	if err := callJSON(ctx, c.Do, http.MethodPost, AttestationAppraisePath, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

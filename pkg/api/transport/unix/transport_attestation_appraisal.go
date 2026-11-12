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

package unix

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The attestation Verifier's appraisal API is served by
// pbconv.AttestationAppraisalClient, shared by the gRPC and Unix-socket
// transports, once this transport holds a connection.

var _ transport.AttestationAppraisalService = (*Transport)(nil)

// attestationAppraisal returns the shared appraisal client over this
// transport's connection, or ErrNotConnected before it holds one.
func (t *Transport) attestationAppraisal() (pbconv.AttestationAppraisalClient, error) {
	if t.client == nil {
		return pbconv.AttestationAppraisalClient{}, ErrNotConnected
	}
	return pbconv.AttestationAppraisalClient{Client: t.client}, nil
}

// PutAttestationEndorsement stores a trust anchor.
func (t *Transport) PutAttestationEndorsement(ctx context.Context, req *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	c, err := t.attestationAppraisal()
	if err != nil {
		return nil, err
	}
	return c.PutAttestationEndorsement(ctx, req)
}

// ListAttestationEndorsements lists the trust anchors, optionally by kind.
func (t *Transport) ListAttestationEndorsements(ctx context.Context, req *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	c, err := t.attestationAppraisal()
	if err != nil {
		return nil, err
	}
	return c.ListAttestationEndorsements(ctx, req)
}

// DeleteAttestationEndorsement removes a trust anchor.
func (t *Transport) DeleteAttestationEndorsement(ctx context.Context, req *transport.DeleteAttestationEndorsementRequest) error {
	c, err := t.attestationAppraisal()
	if err != nil {
		return err
	}
	return c.DeleteAttestationEndorsement(ctx, req)
}

// PutAttestationReferenceValues verifies a signed CoRIM and stores its
// reference values.
func (t *Transport) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	c, err := t.attestationAppraisal()
	if err != nil {
		return nil, err
	}
	return c.PutAttestationReferenceValues(ctx, req)
}

// GetAttestationReferenceValues returns stored reference values.
func (t *Transport) GetAttestationReferenceValues(ctx context.Context, req *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	c, err := t.attestationAppraisal()
	if err != nil {
		return nil, err
	}
	return c.GetAttestationReferenceValues(ctx, req)
}

// ListAttestationReferenceValues lists the stored reference values.
func (t *Transport) ListAttestationReferenceValues(ctx context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	c, err := t.attestationAppraisal()
	if err != nil {
		return nil, err
	}
	return c.ListAttestationReferenceValues(ctx)
}

// DeleteAttestationReferenceValues removes stored reference values.
func (t *Transport) DeleteAttestationReferenceValues(ctx context.Context, req *transport.DeleteAttestationReferenceValuesRequest) error {
	c, err := t.attestationAppraisal()
	if err != nil {
		return err
	}
	return c.DeleteAttestationReferenceValues(ctx, req)
}

// AppraiseAttestationQuote appraises a TPM quote and returns the
// attestation result.
func (t *Transport) AppraiseAttestationQuote(ctx context.Context, req *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	c, err := t.attestationAppraisal()
	if err != nil {
		return nil, err
	}
	return c.AppraiseAttestationQuote(ctx, req)
}

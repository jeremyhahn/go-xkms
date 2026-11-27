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

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The attestation Verifier (go-xkms#1608) is served by
// pbconv.AttestationAppraisalClient, shared by the gRPC and Unix-socket
// transports, once this transport holds a connection.

// appraisal returns the shared Verifier client over this transport's
// connection, or ErrNotConnected before it holds one.
func (t *Transport) appraisal() (pbconv.AttestationAppraisalClient, error) {
	if t.client == nil {
		return pbconv.AttestationAppraisalClient{}, ErrNotConnected
	}
	return pbconv.AttestationAppraisalClient{Client: t.client}, nil
}

// PutAttestationEndorsement stores a trust anchor.
func (t *Transport) PutAttestationEndorsement(ctx context.Context, req *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	c, err := t.appraisal()
	if err != nil {
		return nil, err
	}
	return c.PutAttestationEndorsement(ctx, req)
}

// ListAttestationEndorsements lists trust anchors, optionally by kind.
func (t *Transport) ListAttestationEndorsements(ctx context.Context, req *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	c, err := t.appraisal()
	if err != nil {
		return nil, err
	}
	return c.ListAttestationEndorsements(ctx, req)
}

// DeleteAttestationEndorsement removes a trust anchor.
func (t *Transport) DeleteAttestationEndorsement(ctx context.Context, req *transport.DeleteAttestationEndorsementRequest) error {
	c, err := t.appraisal()
	if err != nil {
		return err
	}
	return c.DeleteAttestationEndorsement(ctx, req)
}

// PutAttestationReferenceValues verifies and stores a signed CoRIM.
func (t *Transport) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	c, err := t.appraisal()
	if err != nil {
		return nil, err
	}
	return c.PutAttestationReferenceValues(ctx, req)
}

// GetAttestationReferenceValues returns stored reference values.
func (t *Transport) GetAttestationReferenceValues(ctx context.Context, req *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	c, err := t.appraisal()
	if err != nil {
		return nil, err
	}
	return c.GetAttestationReferenceValues(ctx, req)
}

// ListAttestationReferenceValues lists stored reference values.
func (t *Transport) ListAttestationReferenceValues(ctx context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	c, err := t.appraisal()
	if err != nil {
		return nil, err
	}
	return c.ListAttestationReferenceValues(ctx)
}

// DeleteAttestationReferenceValues removes stored reference values.
func (t *Transport) DeleteAttestationReferenceValues(ctx context.Context, req *transport.DeleteAttestationReferenceValuesRequest) error {
	c, err := t.appraisal()
	if err != nil {
		return err
	}
	return c.DeleteAttestationReferenceValues(ctx, req)
}

// AppraiseAttestationQuote appraises TPM quote evidence.
func (t *Transport) AppraiseAttestationQuote(ctx context.Context, req *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	c, err := t.appraisal()
	if err != nil {
		return nil, err
	}
	return c.AppraiseAttestationQuote(ctx, req)
}

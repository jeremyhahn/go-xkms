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
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The attestation Verifier (go-xkms#1660) calls the in-process service,
// which binds each call to the caller's tenant.

var _ transport.AttestationAppraisalService = (*Transport)(nil)

// ErrAppraisalUnsupported is returned when the wrapped service does not
// serve the attestation Verifier.
var ErrAppraisalUnsupported = fmt.Errorf("embedded: the service has no attestation Verifier: %w", errors.ErrUnsupported)

// appraisalService returns the wrapped service's Verifier.
func (t *Transport) appraisalService() (transport.AttestationAppraisalServicer, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	s, ok := t.service.(transport.AttestationAppraisalServicer)
	if !ok {
		return nil, ErrAppraisalUnsupported
	}
	return s, nil
}

// PutAttestationEndorsement stores a trust anchor.
func (t *Transport) PutAttestationEndorsement(ctx context.Context, req *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	s, err := t.appraisalService()
	if err != nil {
		return nil, err
	}
	return s.PutAttestationEndorsement(ctx, req)
}

// ListAttestationEndorsements lists the trust anchors, optionally by kind.
func (t *Transport) ListAttestationEndorsements(ctx context.Context, req *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	s, err := t.appraisalService()
	if err != nil {
		return nil, err
	}
	return s.ListAttestationEndorsements(ctx, req)
}

// DeleteAttestationEndorsement removes a trust anchor.
func (t *Transport) DeleteAttestationEndorsement(ctx context.Context, req *transport.DeleteAttestationEndorsementRequest) error {
	s, err := t.appraisalService()
	if err != nil {
		return err
	}
	return s.DeleteAttestationEndorsement(ctx, req)
}

// PutAttestationReferenceValues verifies a signed CoRIM and stores its
// reference values.
func (t *Transport) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	s, err := t.appraisalService()
	if err != nil {
		return nil, err
	}
	return s.PutAttestationReferenceValues(ctx, req)
}

// GetAttestationReferenceValues returns stored reference values.
func (t *Transport) GetAttestationReferenceValues(ctx context.Context, req *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	s, err := t.appraisalService()
	if err != nil {
		return nil, err
	}
	return s.GetAttestationReferenceValues(ctx, req)
}

// ListAttestationReferenceValues lists the stored reference values.
func (t *Transport) ListAttestationReferenceValues(ctx context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	s, err := t.appraisalService()
	if err != nil {
		return nil, err
	}
	return s.ListAttestationReferenceValues(ctx)
}

// DeleteAttestationReferenceValues removes stored reference values.
func (t *Transport) DeleteAttestationReferenceValues(ctx context.Context, req *transport.DeleteAttestationReferenceValuesRequest) error {
	s, err := t.appraisalService()
	if err != nil {
		return err
	}
	return s.DeleteAttestationReferenceValues(ctx, req)
}

// AppraiseAttestationQuote appraises a TPM quote.
func (t *Transport) AppraiseAttestationQuote(ctx context.Context, req *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	s, err := t.appraisalService()
	if err != nil {
		return nil, err
	}
	return s.AppraiseAttestationQuote(ctx, req)
}

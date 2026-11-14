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

// The attestation Verifier (go-xkms#1608) calls the in-process service,
// which binds each call to the caller's tenant and appraises with the
// in-process Appraiser.

// PutAttestationEndorsement stores a trust anchor.
func (t *Transport) PutAttestationEndorsement(ctx context.Context, req *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PutAttestationEndorsement(ctx, req)
}

// ListAttestationEndorsements lists trust anchors, optionally by kind.
func (t *Transport) ListAttestationEndorsements(ctx context.Context, req *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListAttestationEndorsements(ctx, req)
}

// DeleteAttestationEndorsement removes a trust anchor.
func (t *Transport) DeleteAttestationEndorsement(ctx context.Context, req *transport.DeleteAttestationEndorsementRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.DeleteAttestationEndorsement(ctx, req)
}

// PutAttestationReferenceValues verifies and stores a signed CoRIM.
func (t *Transport) PutAttestationReferenceValues(ctx context.Context, req *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.PutAttestationReferenceValues(ctx, req)
}

// GetAttestationReferenceValues returns stored reference values.
func (t *Transport) GetAttestationReferenceValues(ctx context.Context, req *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.GetAttestationReferenceValues(ctx, req)
}

// ListAttestationReferenceValues lists stored reference values.
func (t *Transport) ListAttestationReferenceValues(ctx context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.ListAttestationReferenceValues(ctx)
}

// DeleteAttestationReferenceValues removes stored reference values.
func (t *Transport) DeleteAttestationReferenceValues(ctx context.Context, req *transport.DeleteAttestationReferenceValuesRequest) error {
	if !t.connected {
		return ErrNotConnected
	}
	return t.service.DeleteAttestationReferenceValues(ctx, req)
}

// AppraiseAttestationQuote appraises TPM quote evidence.
func (t *Transport) AppraiseAttestationQuote(ctx context.Context, req *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	if !t.connected {
		return nil, ErrNotConnected
	}
	return t.service.AppraiseAttestationQuote(ctx, req)
}

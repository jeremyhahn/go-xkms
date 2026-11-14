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

package appraisaltest

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// ErrUnserved is the error every Unserved Verifier method returns.
var ErrUnserved = errors.New("appraisaltest: attestation verifier not served by this test double")

// Unserved answers every attestation Verifier call with ErrUnserved. Test
// doubles of transport.Client or of an XKMSServicer that do not exercise the
// Verifier embed it to satisfy transport.AttestationAppraisalService.
type Unserved struct{}

var _ transport.AttestationAppraisalService = Unserved{}

// PutAttestationEndorsement returns ErrUnserved.
func (Unserved) PutAttestationEndorsement(context.Context, *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	return nil, ErrUnserved
}

// ListAttestationEndorsements returns ErrUnserved.
func (Unserved) ListAttestationEndorsements(context.Context, *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	return nil, ErrUnserved
}

// DeleteAttestationEndorsement returns ErrUnserved.
func (Unserved) DeleteAttestationEndorsement(context.Context, *transport.DeleteAttestationEndorsementRequest) error {
	return ErrUnserved
}

// PutAttestationReferenceValues returns ErrUnserved.
func (Unserved) PutAttestationReferenceValues(context.Context, *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	return nil, ErrUnserved
}

// GetAttestationReferenceValues returns ErrUnserved.
func (Unserved) GetAttestationReferenceValues(context.Context, *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	return nil, ErrUnserved
}

// ListAttestationReferenceValues returns ErrUnserved.
func (Unserved) ListAttestationReferenceValues(context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	return nil, ErrUnserved
}

// DeleteAttestationReferenceValues returns ErrUnserved.
func (Unserved) DeleteAttestationReferenceValues(context.Context, *transport.DeleteAttestationReferenceValuesRequest) error {
	return ErrUnserved
}

// AppraiseAttestationQuote returns ErrUnserved.
func (Unserved) AppraiseAttestationQuote(context.Context, *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	return nil, ErrUnserved
}

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

package usb

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The attestation Verifier (go-xkms#1608) holds a tenant's endorsements and
// reference values on a server and appraises evidence there; a USB device
// holds none, so it is not available over USB.

// PutAttestationEndorsement is not available over USB.
func (t *Transport) PutAttestationEndorsement(_ context.Context, _ *transport.PutAttestationEndorsementRequest) (*transport.AttestationEndorsement, error) {
	return nil, ErrNotSupported
}

// ListAttestationEndorsements is not available over USB.
func (t *Transport) ListAttestationEndorsements(_ context.Context, _ *transport.ListAttestationEndorsementsRequest) (*transport.ListAttestationEndorsementsResponse, error) {
	return nil, ErrNotSupported
}

// DeleteAttestationEndorsement is not available over USB.
func (t *Transport) DeleteAttestationEndorsement(_ context.Context, _ *transport.DeleteAttestationEndorsementRequest) error {
	return ErrNotSupported
}

// PutAttestationReferenceValues is not available over USB.
func (t *Transport) PutAttestationReferenceValues(_ context.Context, _ *transport.PutAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	return nil, ErrNotSupported
}

// GetAttestationReferenceValues is not available over USB.
func (t *Transport) GetAttestationReferenceValues(_ context.Context, _ *transport.GetAttestationReferenceValuesRequest) (*transport.AttestationReferenceValues, error) {
	return nil, ErrNotSupported
}

// ListAttestationReferenceValues is not available over USB.
func (t *Transport) ListAttestationReferenceValues(_ context.Context) (*transport.ListAttestationReferenceValuesResponse, error) {
	return nil, ErrNotSupported
}

// DeleteAttestationReferenceValues is not available over USB.
func (t *Transport) DeleteAttestationReferenceValues(_ context.Context, _ *transport.DeleteAttestationReferenceValuesRequest) error {
	return ErrNotSupported
}

// AppraiseAttestationQuote is not available over USB.
func (t *Transport) AppraiseAttestationQuote(_ context.Context, _ *transport.AppraiseAttestationQuoteRequest) (*transport.AttestationResult, error) {
	return nil, ErrNotSupported
}

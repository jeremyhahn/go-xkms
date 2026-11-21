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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestAttestationAppraisal_NotSupported proves no attestation appraisal
// method is served over USB (go-xkms#1660).
func TestAttestationAppraisal_NotSupported(t *testing.T) {
	ctx := context.Background()
	var svc transport.AttestationAppraisalService = &Transport{}
	calls := map[string]func() error{
		"PutAttestationEndorsement": func() error {
			_, err := svc.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{})
			return err
		},
		"ListAttestationEndorsements": func() error {
			_, err := svc.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
			return err
		},
		"DeleteAttestationEndorsement": func() error {
			return svc.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{})
		},
		"PutAttestationReferenceValues": func() error {
			_, err := svc.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{})
			return err
		},
		"GetAttestationReferenceValues": func() error {
			_, err := svc.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{})
			return err
		},
		"ListAttestationReferenceValues": func() error {
			_, err := svc.ListAttestationReferenceValues(ctx)
			return err
		},
		"DeleteAttestationReferenceValues": func() error {
			return svc.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{})
		},
		"AppraiseAttestationQuote": func() error {
			_, err := svc.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{})
			return err
		},
	}
	assert.Len(t, calls, 8, "every method of transport.AttestationAppraisalService")
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			assert.True(t, errors.Is(err, ErrNotSupported), "%v", err)
		})
	}
}

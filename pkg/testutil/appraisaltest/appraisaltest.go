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

// Package appraisaltest holds the fixtures of tests that exercise the
// attestation Verifier API (transport.AttestationAppraisalService). It
// imports only pkg/api/transport, so every transport's tests can use it.
package appraisaltest

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Name is the record name every call of Calls names.
const Name = "fleet-baseline"

// Calls returns one call of every Verifier method of svc, by method name,
// each returning only its error.
func Calls(ctx context.Context, svc transport.AttestationAppraisalService) map[string]func() error {
	return map[string]func() error{
		"PutAttestationEndorsement": func() error {
			_, err := svc.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{Name: Name})
			return err
		},
		"ListAttestationEndorsements": func() error {
			_, err := svc.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
			return err
		},
		"DeleteAttestationEndorsement": func() error {
			return svc.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: Name})
		},
		"PutAttestationReferenceValues": func() error {
			_, err := svc.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: Name})
			return err
		},
		"GetAttestationReferenceValues": func() error {
			_, err := svc.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: Name})
			return err
		},
		"ListAttestationReferenceValues": func() error {
			_, err := svc.ListAttestationReferenceValues(ctx)
			return err
		},
		"DeleteAttestationReferenceValues": func() error {
			return svc.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: Name})
		},
		"AppraiseAttestationQuote": func() error {
			_, err := svc.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: Name})
			return err
		},
	}
}

// NilRequestCalls returns a call of every Verifier method of svc that takes
// a request, each passing a nil request and returning only its error.
func NilRequestCalls(ctx context.Context, svc transport.AttestationAppraisalService) map[string]func() error {
	return map[string]func() error{
		"PutAttestationEndorsement": func() error {
			_, err := svc.PutAttestationEndorsement(ctx, nil)
			return err
		},
		"ListAttestationEndorsements": func() error {
			_, err := svc.ListAttestationEndorsements(ctx, nil)
			return err
		},
		"DeleteAttestationEndorsement": func() error {
			return svc.DeleteAttestationEndorsement(ctx, nil)
		},
		"PutAttestationReferenceValues": func() error {
			_, err := svc.PutAttestationReferenceValues(ctx, nil)
			return err
		},
		"GetAttestationReferenceValues": func() error {
			_, err := svc.GetAttestationReferenceValues(ctx, nil)
			return err
		},
		"DeleteAttestationReferenceValues": func() error {
			return svc.DeleteAttestationReferenceValues(ctx, nil)
		},
		"AppraiseAttestationQuote": func() error {
			_, err := svc.AppraiseAttestationQuote(ctx, nil)
			return err
		},
	}
}

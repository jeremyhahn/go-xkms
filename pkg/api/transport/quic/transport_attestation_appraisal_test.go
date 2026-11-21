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

package quic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestAttestationAppraisal_RefusesANilRequest refuses a nil request before
// any round trip.
func TestAttestationAppraisal_RefusesANilRequest(t *testing.T) {
	tr, cleanup := newMockTransport(t)
	defer cleanup()
	ctx := context.Background()
	_, err := tr.PutAttestationEndorsement(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	assert.ErrorIs(t, tr.DeleteAttestationEndorsement(ctx, nil), wire.ErrNilRequest)
	_, err = tr.PutAttestationReferenceValues(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = tr.GetAttestationReferenceValues(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	assert.ErrorIs(t, tr.DeleteAttestationReferenceValues(ctx, nil), wire.ErrNilRequest)
	_, err = tr.AppraiseAttestationQuote(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
}

// TestAttestationAppraisal_NotConnected refuses every method before dialing.
func TestAttestationAppraisal_NotConnected(t *testing.T) {
	tr := newDisconnected(t)
	ctx := context.Background()
	calls := map[string]func() error{
		"put endorsement": func() error {
			_, err := tr.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{Name: "root"})
			return err
		},
		"list endorsements": func() error {
			_, err := tr.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
			return err
		},
		"delete endorsement": func() error {
			return tr.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "root"})
		},
		"put reference values": func() error {
			_, err := tr.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "golden"})
			return err
		},
		"get reference values": func() error {
			_, err := tr.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "golden"})
			return err
		},
		"list reference values": func() error {
			_, err := tr.ListAttestationReferenceValues(ctx)
			return err
		},
		"delete reference values": func() error {
			return tr.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "golden"})
		},
		"appraise": func() error {
			_, err := tr.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: "golden"})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNotConnected) })
	}
}

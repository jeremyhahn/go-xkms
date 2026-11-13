// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package wire

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
)

// TestAttestationAppraisalClient_Routes pins every Verifier call to the
// method, path and JSON body the REST server routes.
func TestAttestationAppraisalClient_Routes(t *testing.T) {
	rec := &recordingRequester{response: `{}`}
	c := AttestationAppraisalClient{Do: rec.do}
	ctx := context.Background()

	tests := []struct {
		name   string
		call   func() error
		method string
		path   string
		body   map[string]any
	}{
		{"put endorsement", func() error {
			_, err := c.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{
				Name: "root", Kind: appraisal.EndorsementAKRoot, CertificatePEM: []byte("pem"),
			})
			return err
		}, http.MethodPut, "/api/v1/attestation/endorsements",
			map[string]any{"name": "root", "kind": "ak-root", "certificate_pem": "cGVt"}},
		{"list endorsements by kind", func() error {
			_, err := c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{Kind: appraisal.EndorsementReferenceSigner})
			return err
		}, http.MethodGet, "/api/v1/attestation/endorsements?kind=reference-signer", nil},
		{"list all endorsements", func() error {
			_, err := c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
			return err
		}, http.MethodGet, "/api/v1/attestation/endorsements", nil},
		{"delete endorsement", func() error {
			return c.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "a/b"})
		}, http.MethodDelete, "/api/v1/attestation/endorsements/a%2Fb", nil},
		{"put reference values", func() error {
			_, err := c.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{
				Name: "fw", SignedCoRIM: []byte("corim"), Repository: "acme/fw",
			})
			return err
		}, http.MethodPut, "/api/v1/attestation/reference-values",
			map[string]any{"name": "fw", "signed_corim": "Y29yaW0=", "repository": "acme/fw"}},
		{"get reference values", func() error {
			_, err := c.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "fw 1"})
			return err
		}, http.MethodGet, "/api/v1/attestation/reference-values/fw%201", nil},
		{"list reference values", func() error {
			_, err := c.ListAttestationReferenceValues(ctx)
			return err
		}, http.MethodGet, "/api/v1/attestation/reference-values", nil},
		{"delete reference values", func() error {
			return c.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "fw"})
		}, http.MethodDelete, "/api/v1/attestation/reference-values/fw", nil},
		{"appraise quote", func() error {
			_, err := c.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{
				AKCertificatePEM: []byte("ak"), Quote: []byte("q"), Signature: []byte("s"), Nonce: []byte("n"),
				PCRs: map[uint32][]byte{7: []byte("p")}, ReferenceValues: "fw",
			})
			return err
		}, http.MethodPost, "/api/v1/attestation/appraise", map[string]any{
			"ak_certificate_pem": "YWs=", "quote": "cQ==", "signature": "cw==", "nonce": "bg==",
			"pcrs": map[string]any{"7": "cA=="}, "reference_values": "fw",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.call())
			got := rec.last()
			assert.Equal(t, tt.method, got.method)
			assert.Equal(t, tt.path, got.path)
			assert.Equal(t, tt.body, got.body)
		})
	}
}

// TestAttestationAppraisalClient_DecodesResponses checks each call returns
// the server's JSON decoded into the transport type.
func TestAttestationAppraisalClient_DecodesResponses(t *testing.T) {
	ctx := context.Background()
	client := func(response string) AttestationAppraisalClient {
		return AttestationAppraisalClient{Do: (&recordingRequester{response: response}).do}
	}

	endorsement, err := client(`{"name":"root","kind":"ak-root","certificate_pem":"cGVt"}`).
		PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{Name: "root"})
	require.NoError(t, err)
	assert.Equal(t, appraisal.EndorsementAKRoot, endorsement.Kind)
	assert.Equal(t, []byte("pem"), endorsement.CertificatePEM)

	endorsements, err := client(`{"endorsements":[{"name":"a"},{"name":"b"}]}`).
		ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
	require.NoError(t, err)
	require.Len(t, endorsements.Endorsements, 2)
	assert.Equal(t, "b", endorsements.Endorsements[1].Name)

	stored, err := client(`{"name":"fw","manifest_id":"m1","pcr_indices":[0,7]}`).
		PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "fw"})
	require.NoError(t, err)
	assert.Equal(t, "m1", stored.ManifestID)
	assert.Equal(t, []uint32{0, 7}, stored.PCRIndices)

	fetched, err := client(`{"name":"fw","signed_corim":"Y29yaW0="}`).
		GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "fw"})
	require.NoError(t, err)
	assert.Equal(t, []byte("corim"), fetched.SignedCoRIM)

	listed, err := client(`{"reference_values":[{"name":"fw"}]}`).ListAttestationReferenceValues(ctx)
	require.NoError(t, err)
	require.Len(t, listed.ReferenceValues, 1)
	assert.Equal(t, "fw", listed.ReferenceValues[0].Name)

	result, err := client(`{"verified":true}`).
		AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: "fw"})
	require.NoError(t, err)
	assert.True(t, result.Verified)
}

// TestAttestationAppraisalClient_Errors checks a nil request fails before
// any request is sent, and a transport or decode failure surfaces typed.
func TestAttestationAppraisalClient_Errors(t *testing.T) {
	ctx := context.Background()
	failing := AttestationAppraisalClient{Do: (&recordingRequester{err: errRequestFailed}).do}
	garbled := AttestationAppraisalClient{Do: (&recordingRequester{response: `{not json`}).do}

	type calls struct {
		nilReq, withReq func(AttestationAppraisalClient) error
	}
	for name, call := range map[string]calls{
		"put endorsement": {
			func(c AttestationAppraisalClient) error { _, err := c.PutAttestationEndorsement(ctx, nil); return err },
			func(c AttestationAppraisalClient) error {
				_, err := c.PutAttestationEndorsement(ctx, &transport.PutAttestationEndorsementRequest{Name: "root"})
				return err
			},
		},
		"list endorsements": {
			func(c AttestationAppraisalClient) error {
				_, err := c.ListAttestationEndorsements(ctx, nil)
				return err
			},
			func(c AttestationAppraisalClient) error {
				_, err := c.ListAttestationEndorsements(ctx, &transport.ListAttestationEndorsementsRequest{})
				return err
			},
		},
		"put reference values": {
			func(c AttestationAppraisalClient) error {
				_, err := c.PutAttestationReferenceValues(ctx, nil)
				return err
			},
			func(c AttestationAppraisalClient) error {
				_, err := c.PutAttestationReferenceValues(ctx, &transport.PutAttestationReferenceValuesRequest{Name: "fw"})
				return err
			},
		},
		"get reference values": {
			func(c AttestationAppraisalClient) error {
				_, err := c.GetAttestationReferenceValues(ctx, nil)
				return err
			},
			func(c AttestationAppraisalClient) error {
				_, err := c.GetAttestationReferenceValues(ctx, &transport.GetAttestationReferenceValuesRequest{Name: "fw"})
				return err
			},
		},
		"appraise quote": {
			func(c AttestationAppraisalClient) error { _, err := c.AppraiseAttestationQuote(ctx, nil); return err },
			func(c AttestationAppraisalClient) error {
				_, err := c.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: "fw"})
				return err
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call.nilReq(failing), ErrNilRequest)
			assert.ErrorIs(t, call.withReq(failing), errRequestFailed)
			var decodeErr *DecodeError
			assert.ErrorAs(t, call.withReq(garbled), &decodeErr)
		})
	}

	_, err := failing.ListAttestationReferenceValues(ctx)
	assert.ErrorIs(t, err, errRequestFailed)
	var decodeErr *DecodeError
	_, err = garbled.ListAttestationReferenceValues(ctx)
	assert.ErrorAs(t, err, &decodeErr)

	assert.ErrorIs(t, failing.DeleteAttestationEndorsement(ctx, nil), ErrNilRequest)
	assert.ErrorIs(t, failing.DeleteAttestationEndorsement(ctx, &transport.DeleteAttestationEndorsementRequest{Name: "root"}), errRequestFailed)
	assert.ErrorIs(t, failing.DeleteAttestationReferenceValues(ctx, nil), ErrNilRequest)
	assert.ErrorIs(t, failing.DeleteAttestationReferenceValues(ctx, &transport.DeleteAttestationReferenceValuesRequest{Name: "fw"}), errRequestFailed)
}

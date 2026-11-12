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

package wire

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestAttestationVerdictClient_List proves the list verb sends the device
// as a query parameter with no body and decodes the verdicts.
func TestAttestationVerdictClient_List(t *testing.T) {
	rec := &recordingRequester{response: `{"verdicts":[{"device_id":"dev-1"}]}`}
	c := AttestationVerdictClient{Do: rec.do}
	resp, err := c.ListAttestationVerdicts(context.Background(), &transport.AttestationVerdictRequest{DeviceID: "dev-1"})
	require.NoError(t, err)
	require.Len(t, resp.Verdicts, 1)
	assert.Equal(t, "dev-1", resp.Verdicts[0].DeviceID)
	got := rec.last()
	assert.Equal(t, http.MethodGet, got.method)
	assert.Equal(t, "/api/v1/attestation/verdicts?device=dev-1", got.path)
	assert.Nil(t, got.body)
}

// TestAttestationVerdictClient_Latest proves the latest verb's route.
func TestAttestationVerdictClient_Latest(t *testing.T) {
	rec := &recordingRequester{response: `{"device_id":"dev-1"}`}
	c := AttestationVerdictClient{Do: rec.do}
	v, err := c.GetLatestAttestationVerdict(context.Background(), &transport.AttestationVerdictRequest{DeviceID: "dev-1"})
	require.NoError(t, err)
	assert.Equal(t, "dev-1", v.DeviceID)
	got := rec.last()
	assert.Equal(t, http.MethodGet, got.method)
	assert.Equal(t, "/api/v1/attestation/verdicts/latest?device=dev-1", got.path)
	assert.Nil(t, got.body)
}

// TestAttestationVerdictClient_Reattest proves the reattest verb posts the
// device in the body and carries no query.
func TestAttestationVerdictClient_Reattest(t *testing.T) {
	rec := &recordingRequester{response: `{"device_id":"dev-1"}`}
	c := AttestationVerdictClient{Do: rec.do}
	v, err := c.ReattestDevice(context.Background(), &transport.AttestationVerdictRequest{DeviceID: "dev-1"})
	require.NoError(t, err)
	assert.Equal(t, "dev-1", v.DeviceID)
	got := rec.last()
	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/api/v1/attestation/verdicts", got.path)
	assert.Equal(t, "dev-1", got.body["device_id"])
}

// verdictCalls returns the three verbs on c with req.
func verdictCalls(c AttestationVerdictClient, req *transport.AttestationVerdictRequest) map[string]func() error {
	ctx := context.Background()
	return map[string]func() error{
		"list": func() error {
			_, err := c.ListAttestationVerdicts(ctx, req)
			return err
		},
		"latest": func() error {
			_, err := c.GetLatestAttestationVerdict(ctx, req)
			return err
		},
		"reattest": func() error {
			_, err := c.ReattestDevice(ctx, req)
			return err
		},
	}
}

// TestAttestationVerdictClient_NilRequest proves each verb refuses a nil
// request before sending anything.
func TestAttestationVerdictClient_NilRequest(t *testing.T) {
	called := false
	c := AttestationVerdictClient{Do: func(context.Context, string, string, any) ([]byte, error) {
		called = true
		return nil, nil
	}}
	for name, call := range verdictCalls(c, nil) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), ErrNilRequest) })
	}
	assert.False(t, called)
}

// TestAttestationVerdictClient_RequestError proves each verb surfaces the
// requester's error.
func TestAttestationVerdictClient_RequestError(t *testing.T) {
	rec := &recordingRequester{err: errRequestFailed}
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	for name, call := range verdictCalls(AttestationVerdictClient{Do: rec.do}, req) {
		t.Run(name, func(t *testing.T) { assert.ErrorIs(t, call(), errRequestFailed) })
	}
}

// TestAttestationVerdictClient_DecodeError proves each verb returns a
// *DecodeError on an undecodable response.
func TestAttestationVerdictClient_DecodeError(t *testing.T) {
	rec := &recordingRequester{response: `{not json`}
	req := &transport.AttestationVerdictRequest{DeviceID: "dev-1"}
	for name, call := range verdictCalls(AttestationVerdictClient{Do: rec.do}, req) {
		t.Run(name, func(t *testing.T) {
			var de *DecodeError
			assert.ErrorAs(t, call(), &de)
		})
	}
}

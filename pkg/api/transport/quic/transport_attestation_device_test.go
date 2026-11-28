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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest/wire"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// newDeviceAppraisalTransport connects a QUIC transport to a server whose
// appraiser answers the device appraisal routes with result, or with a 422
// on every appraisal route when fail is set.
func newDeviceAppraisalTransport(t *testing.T, result transport.AttestationResult, fail bool) *Transport {
	t.Helper()
	mux := http.NewServeMux()
	serve := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if fail {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "evidence refused"})
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	}
	mux.HandleFunc(wire.AttestationAppraisePath, serve)
	mux.HandleFunc(wire.AttestationAppraiseAndroidKeyPath, serve)
	mux.HandleFunc(wire.AttestationAppraiseEKCertificatePath, serve)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return &Transport{
		config:     transport.DefaultConfig(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		connected:  true,
	}
}

// TestAttestationAppraisal_DeviceCallsReachTheServer drives both device
// appraisal calls through a connected QUIC client: each returns the
// server's result, and a server refusal maps as for the quote appraisal.
func TestAttestationAppraisal_DeviceCallsReachTheServer(t *testing.T) {
	ctx := context.Background()
	want := transport.AttestationResult{Verified: true, TrustAnchor: "google-root", BootState: "verified"}
	tr := newDeviceAppraisalTransport(t, want, false)

	got, err := tr.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{})
	require.NoError(t, err)
	assert.True(t, got.Verified)
	assert.Equal(t, want.TrustAnchor, got.TrustAnchor)
	assert.Equal(t, want.BootState, got.BootState)

	got, err = tr.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{})
	require.NoError(t, err)
	assert.True(t, got.Verified)
	assert.Equal(t, want.TrustAnchor, got.TrustAnchor)

	_, err = tr.AppraiseAndroidKeyAttestation(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)
	_, err = tr.AppraiseEKCertificate(ctx, nil)
	assert.ErrorIs(t, err, wire.ErrNilRequest)

	failing := newDeviceAppraisalTransport(t, want, true)
	_, quoteErr := failing.AppraiseAttestationQuote(ctx, &transport.AppraiseAttestationQuoteRequest{ReferenceValues: "golden"})
	require.Error(t, quoteErr)
	_, err = failing.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotSupported)
	assert.Equal(t, quoteErr.Error(), err.Error())
	_, err = failing.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotSupported)
	assert.Equal(t, quoteErr.Error(), err.Error())
}

// TestAttestationAppraisal_DeviceCallsNotConnected refuses both device
// appraisal calls before dialing.
func TestAttestationAppraisal_DeviceCallsNotConnected(t *testing.T) {
	tr := newDisconnected(t)
	ctx := context.Background()
	_, err := tr.AppraiseAndroidKeyAttestation(ctx, &transport.AppraiseAndroidKeyAttestationRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
	_, err = tr.AppraiseEKCertificate(ctx, &transport.AppraiseEKCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

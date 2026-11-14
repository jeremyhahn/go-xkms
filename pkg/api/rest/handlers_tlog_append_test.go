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

//go:build qrdb_vlog

package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tlogtest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

const appendCaller = "spiffe://acme/svc/billing"

// newAppendLog returns a real, empty transparency log.
func newAppendLog(t *testing.T) *tlogtest.Fixture {
	t.Helper()
	ca, err := testutil.GenerateTestCA()
	require.NoError(t, err)
	return tlogtest.New(t, ca.Key, ca.Cert)
}

// newAppendHandlers returns transparency-log handlers whose xkms service
// appends to f's log.
func newAppendHandlers(f *tlogtest.Fixture) *TransparencyLogHandlers {
	svc := &xkms.XKMSService{}
	svc.SetTransparencyLog(f.Log)
	return NewTransparencyLogHandlers(svc)
}

// verifiedClientTLS returns the TLS state of a mutual TLS connection whose
// verified client certificate carries uris as its URI SANs.
func verifiedClientTLS(t *testing.T, uris ...string) *tls.ConnectionState {
	t.Helper()
	state, err := testutil.VerifiedClientState(uris...)
	require.NoError(t, err)
	return state
}

// postAppend sends POST /ca/transparency-log/entries with body over a
// connection with state to h, under ctx.
func postAppend(t *testing.T, ctx context.Context, h *TransparencyLogHandlers, state *tls.ConnectionState, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/ca/transparency-log/entries", bytes.NewReader(body))
	req.TLS = state
	rec := httptest.NewRecorder()
	h.AppendExternalHandler(rec, req)
	return rec
}

func appendBody(t *testing.T, payload []byte) []byte {
	t.Helper()
	body, err := json.Marshal(transport.AppendTransparencyLogExternalRequest{Payload: payload})
	require.NoError(t, err)
	return body
}

func TestAppendExternalHandler_RecordsTheClientCertificatesSPIFFEID(t *testing.T) {
	f := newAppendLog(t)
	h := newAppendHandlers(f)
	state := verifiedClientTLS(t, "https://acme.example/profile", appendCaller)

	rec := postAppend(t, f.Ctx, h, state, appendBody(t, []byte("invoice 7")))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var resp transport.AppendTransparencyLogExternalResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Equal(t, uint64(0), resp.Index, "the first entry of an empty log")

	tlogtest.RequireOneEntry(f.Ctx, t, f.Log, resp.Index, tlog.External{SPIFFEID: appendCaller, Payload: []byte("invoice 7")})
}

func TestAppendExternalHandler_NoLogIsServiceUnavailable(t *testing.T) {
	f := newAppendLog(t)
	h := NewTransparencyLogHandlers(&xkms.XKMSService{})

	rec := postAppend(t, f.Ctx, h, verifiedClientTLS(t, appendCaller), appendBody(t, []byte("invoice 7")))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
}

func TestAppendExternalHandler_NoSPIFFEIDIsUnauthorized(t *testing.T) {
	f := newAppendLog(t)
	h := newAppendHandlers(f)

	tests := map[string]*tls.ConnectionState{
		"no TLS":            nil,
		"no SPIFFE ID":      verifiedClientTLS(t, "https://acme.example/profile"),
		"two SPIFFE IDs":    verifiedClientTLS(t, appendCaller, "spiffe://acme/svc/payroll"),
		"no URI SAN at all": verifiedClientTLS(t),
	}
	for name, state := range tests {
		t.Run(name, func(t *testing.T) {
			rec := postAppend(t, f.Ctx, h, state, appendBody(t, []byte("invoice 7")))
			require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		})
	}
	require.Equal(t, uint64(0), tlogtest.Size(f.Ctx, t, f.Log), "a refused append records nothing")
}

func TestAppendExternalHandler_InvalidPayloadIsBadRequest(t *testing.T) {
	f := newAppendLog(t)
	h := newAppendHandlers(f)
	state := verifiedClientTLS(t, appendCaller)

	tests := map[string][]byte{
		"empty":          appendBody(t, nil),
		"oversized":      appendBody(t, make([]byte, 1<<16)),
		"malformed JSON": []byte(`{"payload":`),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			rec := postAppend(t, f.Ctx, h, state, body)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		})
	}
}

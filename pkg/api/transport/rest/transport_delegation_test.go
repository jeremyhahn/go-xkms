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

package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/keyversiontest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/oidccredentialtest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
)

// recordedRequest is one request a routeRecorder served.
type recordedRequest struct {
	route string
	body  []byte
}

// routeRecorder is an in-process REST server that answers the health check
// the transport makes on Connect, then records every other request and
// answers it with a fixed status and body.
type routeRecorder struct {
	srv  *httptest.Server
	last atomic.Pointer[recordedRequest]
}

func newRouteRecorder(t *testing.T, status int, body string) *routeRecorder {
	t.Helper()
	rec := &routeRecorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, `{"status":"ok"}`)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec.last.Store(&recordedRequest{route: r.Method + " " + r.URL.RequestURI(), body: data})
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

// connect returns a transport connected to the recorder.
func (r *routeRecorder) connect(t *testing.T) *Transport {
	t.Helper()
	return connectFullMock(t, r.srv)
}

// request returns the last request the recorder served, failing the test
// when none reached it.
func (r *routeRecorder) request(t *testing.T) *recordedRequest {
	t.Helper()
	req := r.last.Swap(nil)
	require.NotNil(t, req, "no request reached the server")
	return req
}

// delegatedCalls returns every method the transport serves by delegating to
// a wire client: key versions, TPM policies and OIDC credentials.
func delegatedCalls(ctx context.Context, tr *Transport) map[string]func() error {
	calls := keyversiontest.Calls(ctx, tr)
	for name, call := range tpmpolicytest.Calls(ctx, tr) {
		calls[name] = call
	}
	for name, call := range oidccredentialtest.Calls(ctx, tr) {
		calls[name] = call
	}
	return calls
}

// TestDelegatedCalls_ReachTheServer proves every delegated method of a
// connected transport sends its request to the server and accepts its
// reply. The routes and bodies themselves are tested in pkg/api/rest/wire.
func TestDelegatedCalls_ReachTheServer(t *testing.T) {
	rec := newRouteRecorder(t, http.StatusOK, `{}`)
	tr := rec.connect(t)

	for name, call := range delegatedCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, call())
			assert.NotEmpty(t, rec.request(t).route)
		})
	}
}

// TestDelegatedCalls_SurfaceServerErrors proves every delegated method
// returns the server's error message instead of an empty result.
func TestDelegatedCalls_SurfaceServerErrors(t *testing.T) {
	rec := newRouteRecorder(t, http.StatusConflict, `{"error":"version is current"}`)
	tr := rec.connect(t)

	for name, call := range delegatedCalls(context.Background(), tr) {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "server error: version is current")
		})
	}
}

// TestInvites_Routes proves the invite redemption methods address the
// invite by tenant and token in the path, send the credential the invitee
// presents, and decode the server's reply.
func TestInvites_Routes(t *testing.T) {
	ctx := context.Background()

	t.Run("GetInvite", func(t *testing.T) {
		rec := newRouteRecorder(t, http.StatusOK, `{"email":"ann@example.com","methods":["webauthn","piv"]}`)
		resp, err := rec.connect(t).GetInvite(ctx, &transport.GetInviteRequest{TenantID: "acme", Token: "tok/1"})
		require.NoError(t, err)
		assert.Equal(t, "GET /api/v1/invites/acme/tok%2F1", rec.request(t).route)
		assert.Equal(t, "ann@example.com", resp.Email)
		assert.Equal(t, []string{"webauthn", "piv"}, resp.Methods)
	})

	t.Run("BeginInviteRegistration", func(t *testing.T) {
		rec := newRouteRecorder(t, http.StatusOK, `{"session_id":"s1","options_json":"{}"}`)
		resp, err := rec.connect(t).BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: "acme", Token: "tok"})
		require.NoError(t, err)
		assert.Equal(t, "POST /api/v1/invites/acme/tok/fido2/begin", rec.request(t).route)
		assert.Equal(t, "s1", resp.SessionID)
		assert.Equal(t, "{}", resp.OptionsJSON)
	})

	t.Run("FinishInviteRegistration", func(t *testing.T) {
		rec := newRouteRecorder(t, http.StatusOK, `{"user_id":"42"}`)
		resp, err := rec.connect(t).FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{
			TenantID: "acme", Token: "tok", SessionID: "s1", AttestationJSON: `{"id":"cred"}`,
		})
		require.NoError(t, err)
		req := rec.request(t)
		assert.Equal(t, "POST /api/v1/invites/acme/tok/fido2/finish", req.route)
		assert.JSONEq(t, `{"session_id":"s1","attestation_json":"{\"id\":\"cred\"}"}`, string(req.body))
		assert.Equal(t, uint64(42), resp.UserID)
	})

	t.Run("ActivateInvitePIV", func(t *testing.T) {
		rec := newRouteRecorder(t, http.StatusOK, `{"user_id":"7"}`)
		resp, err := rec.connect(t).ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{TenantID: "acme", Token: "tok", CertPEM: "PEM"})
		require.NoError(t, err)
		req := rec.request(t)
		assert.Equal(t, "POST /api/v1/invites/acme/tok/piv/activate", req.route)
		assert.JSONEq(t, `{"cert_pem":"PEM"}`, string(req.body))
		assert.Equal(t, uint64(7), resp.UserID)
	})
}

// inviteCalls returns every invite redemption method of tr.
func inviteCalls(ctx context.Context, tr *Transport) map[string]func() error {
	return map[string]func() error{
		"GetInvite": func() error {
			_, err := tr.GetInvite(ctx, &transport.GetInviteRequest{TenantID: "acme", Token: "tok"})
			return err
		},
		"BeginInviteRegistration": func() error {
			_, err := tr.BeginInviteRegistration(ctx, &transport.BeginInviteRegistrationRequest{TenantID: "acme", Token: "tok"})
			return err
		},
		"FinishInviteRegistration": func() error {
			_, err := tr.FinishInviteRegistration(ctx, &transport.FinishInviteRegistrationRequest{TenantID: "acme", Token: "tok"})
			return err
		},
		"ActivateInvitePIV": func() error {
			_, err := tr.ActivateInvitePIV(ctx, &transport.ActivateInvitePIVRequest{TenantID: "acme", Token: "tok"})
			return err
		},
	}
}

// TestInvites_Errors proves the invite methods refuse to run unconnected
// and surface a server error or an unreadable reply.
func TestInvites_Errors(t *testing.T) {
	ctx := context.Background()

	for name, call := range inviteCalls(ctx, &Transport{}) {
		t.Run(name+"/not connected", func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}

	expired := newRouteRecorder(t, http.StatusGone, `{"error":"invite expired"}`).connect(t)
	for name, call := range inviteCalls(ctx, expired) {
		t.Run(name+"/server error", func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "server error: invite expired")
		})
	}

	garbled := newRouteRecorder(t, http.StatusOK, `not json`).connect(t)
	for name, call := range inviteCalls(ctx, garbled) {
		t.Run(name+"/unreadable reply", func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to parse response")
		})
	}
}

// TestIssueLAKCertificate proves the LAK request carries the IAK evidence
// and the tenant, and decodes the issued certificate.
func TestIssueLAKCertificate(t *testing.T) {
	rec := newRouteRecorder(t, http.StatusOK, `{"certificate_der":"AQI=","serial_number":"0a"}`)
	resp, err := rec.connect(t).IssueLAKCertificate(context.Background(), &transport.IssueLAKCertificateRequest{
		TenantID: "acme", TPMManufacturer: "IFX", Nonce: []byte{9},
	})
	require.NoError(t, err)

	req := rec.request(t)
	assert.Equal(t, "POST /api/v1/ca/tcg/lak", req.route)
	var body map[string]any
	require.NoError(t, json.Unmarshal(req.body, &body))
	assert.Equal(t, "acme", body["tenant_id"])
	assert.Equal(t, "IFX", body["tpm_manufacturer"])
	assert.Equal(t, []byte{1, 2}, resp.CertificateDER)
	assert.Equal(t, "0a", resp.SerialNumber)
}

// TestIssueLAKCertificate_Errors proves the LAK request leaves the tenant
// out when none is named, and fails unconnected, on a server error and on
// an unreadable reply.
func TestIssueLAKCertificate_Errors(t *testing.T) {
	ctx := context.Background()
	req := &transport.IssueLAKCertificateRequest{TPMManufacturer: "IFX"}

	_, err := (&Transport{}).IssueLAKCertificate(ctx, req)
	assert.ErrorIs(t, err, ErrNotConnected)

	denied := newRouteRecorder(t, http.StatusForbidden, `{"error":"iak not trusted"}`)
	_, err = denied.connect(t).IssueLAKCertificate(ctx, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server error: iak not trusted")
	var body map[string]any
	require.NoError(t, json.Unmarshal(denied.request(t).body, &body))
	assert.NotContains(t, body, "tenant_id")

	garbled := newRouteRecorder(t, http.StatusOK, `not json`)
	_, err = garbled.connect(t).IssueLAKCertificate(ctx, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

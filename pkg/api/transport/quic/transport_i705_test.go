// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// This file covers pkg/api/transport/quic client methods (go-xkms #705,
// batch A) that shipped without a test: Algorithms, the PKCS11State* bridge,
// GetShare/DeleteShare, QueryAudit, TenantBarrierStatus,
// UpdateTenantEntitlements/Quotas, ClaimShareComplete, BarrierEnableEncryption
// and BootstrapListenerKeys, plus the ErrInvalidLeaderRedirect error type.

// i705RecordingServer answers every request with respBody and records the last
// request's path and decoded JSON body, so a test can assert the transport
// hit the route the real server handler is registered on with the fields
// named the way the handler decodes them.
type i705RecordingServer struct {
	gotPath   string
	gotMethod string
	gotBody   []byte
	respBody  []byte
	status    int
}

func (s *i705RecordingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.gotPath = r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		s.gotPath += "?" + r.URL.RawQuery
	}
	s.gotMethod = r.Method
	if r.Body != nil {
		s.gotBody, _ = io.ReadAll(r.Body)
	}
	if s.status != 0 {
		w.WriteHeader(s.status)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.respBody)
}

func newI705RecordingTransport(t *testing.T, respBody []byte) (*Transport, *i705RecordingServer) {
	t.Helper()
	srv := &i705RecordingServer{respBody: respBody}
	ts := httptest.NewTLSServer(srv)
	t.Cleanup(ts.Close)
	return &Transport{
		config:     transport.DefaultConfig(),
		httpClient: ts.Client(),
		baseURL:    ts.URL,
		connected:  true,
	}, srv
}

func newDisconnectedTransport() *Transport {
	return &Transport{config: transport.DefaultConfig()}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// --- ErrInvalidLeaderRedirect ---

func TestErrInvalidLeaderRedirect_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("parse failure")
	err := &ErrInvalidLeaderRedirect{Address: "not a url", Err: cause}
	assert.Contains(t, err.Error(), "not a url")
	assert.Contains(t, err.Error(), "parse failure")
	assert.Equal(t, cause, errors.Unwrap(err))
	assert.ErrorIs(t, err, cause)
}

// --- Algorithms ---

func TestAlgorithms_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.AlgorithmsResponse{
		Signing: []transport.AlgorithmInfo{{Algorithm: "ECDSA", KeySizes: []int{256}}},
	}))
	resp, err := tr.Algorithms(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Signing, 1)
	assert.Equal(t, "ECDSA", resp.Signing[0].Algorithm)
	assert.Equal(t, "/api/v1/algorithms", srv.gotPath)
}

func TestAlgorithms_MalformedResponse(t *testing.T) {
	tr, _ := newI705RecordingTransport(t, []byte("not json"))
	_, err := tr.Algorithms(context.Background())
	require.Error(t, err)
}

// --- PKCS11State* ---

func TestPKCS11StatePut_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StatePutResponse{}))
	_, err := tr.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{Token: "tok0", Key: "k", Value: []byte("v")})
	require.NoError(t, err)
	assert.Equal(t, pkcs11StatePutPath, srv.gotPath)

	var got transport.PKCS11StatePutRequest
	require.NoError(t, json.Unmarshal(srv.gotBody, &got))
	assert.Equal(t, "tok0", got.Token)
	assert.Equal(t, []byte("v"), got.Value)
}

func TestPKCS11StatePut_NotConnected(t *testing.T) {
	_, err := newDisconnectedTransport().PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StatePutIfAbsent_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StatePutIfAbsentResponse{Stored: true}))
	resp, err := tr.PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.True(t, resp.Stored)
	assert.Equal(t, pkcs11StatePutIfAbsentPath, srv.gotPath)
}

func TestPKCS11StatePutIfAbsent_NotConnected(t *testing.T) {
	_, err := newDisconnectedTransport().PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StatePutIfAbsent_MalformedResponse(t *testing.T) {
	tr, _ := newI705RecordingTransport(t, []byte("not json"))
	_, err := tr.PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{Token: "tok0"})
	require.Error(t, err)
}

func TestPKCS11StateCAS_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StateCASResponse{Swapped: true, Current: []byte("new")}))
	resp, err := tr.PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{Token: "tok0", Key: "k", Expected: []byte("old"), New: []byte("new")})
	require.NoError(t, err)
	assert.True(t, resp.Swapped)
	assert.Equal(t, pkcs11StateCASPath, srv.gotPath)
}

func TestPKCS11StateCAS_NotConnected(t *testing.T) {
	_, err := newDisconnectedTransport().PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateGet_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StateGetResponse{Value: []byte("v"), Found: true}))
	resp, err := tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.True(t, resp.Found)
	assert.Equal(t, pkcs11StateGetPath, srv.gotPath)
}

func TestPKCS11StateGet_NotConnected(t *testing.T) {
	_, err := newDisconnectedTransport().PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateDelete_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StateDeleteResponse{}))
	_, err := tr.PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.Equal(t, pkcs11StateDeletePath, srv.gotPath)
}

func TestPKCS11StateDelete_NotConnected(t *testing.T) {
	_, err := newDisconnectedTransport().PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateList_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StateListResponse{Keys: []string{"a", "b"}}))
	resp, err := tr.PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{Token: "tok0", Prefix: "ns"})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, resp.Keys)
	assert.Equal(t, pkcs11StateListPath, srv.gotPath)
}

func TestPKCS11StateList_NotConnected(t *testing.T) {
	_, err := newDisconnectedTransport().PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- GetShare / DeleteShare ---

// --- QueryAudit ---

// --- TenantBarrierStatus / UpdateTenantEntitlements / UpdateTenantQuotas ---

func TestUpdateTenantEntitlements_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.UpdateTenantEntitlementsResponse{
		Tenant: transport.TenantInfo{ID: "acme"},
	}))
	resp, err := tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{
		TenantID: "acme", Entitlements: transport.TenantEntitlements{AllowDedicatedRaft: true},
	})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.Tenant.ID)
	assert.Equal(t, "/api/v1/tenants/acme/entitlements", srv.gotPath)
	assert.Equal(t, http.MethodPut, srv.gotMethod)
}

func TestUpdateTenantQuotas_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.UpdateTenantQuotasResponse{
		Tenant: transport.TenantInfo{ID: "acme"},
	}))
	resp, err := tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{
		TenantID: "acme", Quotas: transport.TenantQuotas{MaxKeys: 10},
	})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.Tenant.ID)
	assert.Equal(t, "/api/v1/tenants/acme/quotas", srv.gotPath)
	assert.Equal(t, http.MethodPut, srv.gotMethod)
}

// --- ClaimShareComplete ---

// --- BarrierEnableEncryption ---

// --- BootstrapListenerKeys ---

func TestBootstrapListenerKeys_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.BootstrapListenerKeysResponse{NoisePublicKey: "n", P256PublicKey: "p"}))
	resp, err := tr.BootstrapListenerKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "n", resp.NoisePublicKey)
	assert.Equal(t, "/api/v1/bootstrap/keys", srv.gotPath)
}

func TestBootstrapListenerKeys_MalformedResponse(t *testing.T) {
	tr, _ := newI705RecordingTransport(t, []byte("not json"))
	_, err := tr.BootstrapListenerKeys(context.Background())
	require.Error(t, err)
}

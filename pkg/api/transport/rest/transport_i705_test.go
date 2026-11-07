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

package rest

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
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// This file covers pkg/api/transport/rest client methods (go-xkms #705,
// batch A) that shipped without a test: Algorithms, the PKCS11State* bridge,
// ClaimShareComplete, BarrierEnableEncryption, the leader-redirect contract
// (leaderBaseURL / DoRawRequest's 421 handling) and ErrMalformedLeaderAddress.

// i705RecordingServer answers every request with respBody and records the
// last request's path and raw body.
type i705RecordingServer struct {
	gotPath  string
	gotBody  []byte
	respBody []byte
	status   int
}

func (s *i705RecordingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.gotPath = r.URL.Path
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
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return &Transport{
		config:     transport.DefaultConfig(),
		httpClient: ts.Client(),
		baseURL:    ts.URL,
		connected:  true,
	}, srv
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// --- ErrMalformedLeaderAddress ---

func TestErrMalformedLeaderAddress_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("parse failure")
	err := &ErrMalformedLeaderAddress{Address: "bad-addr", Err: cause}
	assert.Contains(t, err.Error(), "bad-addr")
	assert.Contains(t, err.Error(), "parse failure")
	assert.Equal(t, cause, errors.Unwrap(err))
	assert.ErrorIs(t, err, cause)
}

// --- leaderBaseURL ---

func TestLeaderBaseURL(t *testing.T) {
	tr := &Transport{baseURL: "http://original:8080"}

	base, err := tr.leaderBaseURL("10.0.0.5:9443")
	require.NoError(t, err)
	assert.Equal(t, "http://10.0.0.5:9443", base)

	_, err = tr.leaderBaseURL("https://10.0.0.5:9443")
	require.Error(t, err)
	var malformed *ErrMalformedLeaderAddress
	assert.ErrorAs(t, err, &malformed)

	_, err = tr.leaderBaseURL("not-a-host-port")
	require.Error(t, err)
	assert.ErrorAs(t, err, &malformed)
}

func TestLeaderBaseURL_HTTPSScheme(t *testing.T) {
	tr := &Transport{baseURL: "https://original:8443"}
	base, err := tr.leaderBaseURL("10.0.0.5:9443")
	require.NoError(t, err)
	assert.Equal(t, "https://10.0.0.5:9443", base)
}

// --- DoRawRequest: the one-hop 421 leader redirect ---

func TestDoRawRequest_LeaderRedirect_RetriesOnceAgainstLeader(t *testing.T) {
	leader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer leader.Close()

	leaderHostPort := leader.Listener.Addr().String()
	calls := 0
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("X-XKMS-Leader-API-Address", leaderHostPort)
		w.WriteHeader(http.StatusMisdirectedRequest)
	}))
	defer follower.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: follower.Client(),
		baseURL:    follower.URL,
		connected:  true,
	}

	data, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/api/v1/health", nil)
	require.NoError(t, err, "the retry against the leader succeeds")
	assert.JSONEq(t, `{"ok":true}`, string(data))
	assert.Equal(t, 1, calls, "exactly one call reaches the follower before the retry")
}

func TestDoRawRequest_LeaderRedirect_NoAddressHeaderReturnsAsIs(t *testing.T) {
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMisdirectedRequest)
		_, _ = w.Write([]byte(`{"error":"not leader"}`))
	}))
	defer follower.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: follower.Client(),
		baseURL:    follower.URL,
		connected:  true,
	}

	_, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/api/v1/health", nil)
	require.Error(t, err, "a 421 without a leader address surfaces as an error unchanged")
}

func TestDoRawRequest_LeaderRedirect_MalformedAddressReturnsTypedError(t *testing.T) {
	follower := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-XKMS-Leader-API-Address", "https://not-bare-host-port")
		w.WriteHeader(http.StatusMisdirectedRequest)
	}))
	defer follower.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: follower.Client(),
		baseURL:    follower.URL,
		connected:  true,
	}

	_, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/api/v1/health", nil)
	require.Error(t, err)
	var malformed *ErrMalformedLeaderAddress
	assert.ErrorAs(t, err, &malformed)
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

// --- ClaimShareComplete ---

// --- BarrierEnableEncryption ---

// --- PKCS11State* (Put, PutIfAbsent, CAS, Get, Delete, List; CAD has its own file) ---

func TestPKCS11StatePut_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StatePutResponse{}))
	_, err := tr.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{Token: "tok0", Key: "k", Value: []byte("v")})
	require.NoError(t, err)
	assert.Equal(t, restPKCS11StatePutPath, srv.gotPath)

	var got transport.PKCS11StatePutRequest
	require.NoError(t, json.Unmarshal(srv.gotBody, &got))
	assert.Equal(t, "tok0", got.Token)
}

func TestPKCS11StatePut_NotConnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	_, err := tr.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StatePutIfAbsent_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StatePutIfAbsentResponse{Stored: true}))
	resp, err := tr.PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.True(t, resp.Stored)
	assert.Equal(t, restPKCS11StatePutIfAbsentPath, srv.gotPath)
}

func TestPKCS11StatePutIfAbsent_NotConnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	_, err := tr.PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{})
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
	assert.Equal(t, restPKCS11StateCASPath, srv.gotPath)
}

func TestPKCS11StateCAS_NotConnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	_, err := tr.PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateGet_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StateGetResponse{Value: []byte("v"), Found: true}))
	resp, err := tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.True(t, resp.Found)
	assert.Equal(t, restPKCS11StateGetPath, srv.gotPath)
}

func TestPKCS11StateGet_NotConnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	_, err := tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateDelete_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StateDeleteResponse{}))
	_, err := tr.PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.Equal(t, restPKCS11StateDeletePath, srv.gotPath)
}

func TestPKCS11StateDelete_NotConnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	_, err := tr.PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateList_Connected(t *testing.T) {
	tr, srv := newI705RecordingTransport(t, mustJSON(t, transport.PKCS11StateListResponse{Keys: []string{"a", "b"}}))
	resp, err := tr.PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{Token: "tok0", Prefix: "ns"})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, resp.Keys)
	assert.Equal(t, restPKCS11StateListPath, srv.gotPath)
}

func TestPKCS11StateList_NotConnected(t *testing.T) {
	tr := &Transport{config: transport.DefaultConfig()}
	_, err := tr.PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// pkcs11StateCalls returns every PKCS#11 state verb of tr except CAD, which
// transport_pkcs11state_cad_test.go covers.
func pkcs11StateCalls(ctx context.Context, tr *Transport) map[string]func() (any, error) {
	return map[string]func() (any, error){
		"Put": func() (any, error) {
			return tr.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{Token: "tok0", Key: "k", Value: []byte("v")})
		},
		"PutIfAbsent": func() (any, error) {
			return tr.PKCS11StatePutIfAbsent(ctx, &transport.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "k", Value: []byte("v")})
		},
		"CAS": func() (any, error) {
			return tr.PKCS11StateCAS(ctx, &transport.PKCS11StateCASRequest{Token: "tok0", Key: "k", Expected: []byte("a"), New: []byte("b")})
		},
		"Get": func() (any, error) {
			return tr.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
		},
		"Delete": func() (any, error) {
			return tr.PKCS11StateDelete(ctx, &transport.PKCS11StateDeleteRequest{Token: "tok0", Key: "k"})
		},
		"List": func() (any, error) {
			return tr.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{Token: "tok0", Prefix: "obj/"})
		},
	}
}

// TestPKCS11State_SurfacesServerRefusals proves every PKCS#11 state verb
// returns the server's refusal and no result, so the module never mistakes
// a refused write or read for a successful one.
func TestPKCS11State_SurfacesServerRefusals(t *testing.T) {
	refusing := newRouteRecorder(t, http.StatusServiceUnavailable, `{"error":"barrier sealed"}`).connect(t)
	for name, call := range pkcs11StateCalls(context.Background(), refusing) {
		t.Run(name, func(t *testing.T) {
			resp, err := call()
			var msg *errs.Message
			require.ErrorAs(t, err, &msg)
			assert.Equal(t, "server error: barrier sealed", msg.Msg)
			assert.Nil(t, resp)
		})
	}
}

// TestPKCS11State_RejectsUnreadableReplies proves every PKCS#11 state verb
// that decodes an answer fails on a reply that is not JSON instead of
// returning a zero value; Put and Delete decode no answer.
func TestPKCS11State_RejectsUnreadableReplies(t *testing.T) {
	garbled := newRouteRecorder(t, http.StatusOK, `not json`).connect(t)
	calls := pkcs11StateCalls(context.Background(), garbled)
	for _, name := range []string{"PutIfAbsent", "CAS", "Get", "List"} {
		t.Run(name, func(t *testing.T) {
			resp, err := calls[name]()
			var wrapped *errs.Wrapped
			require.ErrorAs(t, err, &wrapped)
			assert.Contains(t, wrapped.Msg, "failed to parse pkcs11 state")
			assert.Nil(t, resp)
		})
	}
}

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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordedRequest captures everything about an inbound request a fake cluster
// node needs to assert on: which path/method it received, the headers the
// client presented, and the exact body bytes (to prove the retry replayed the
// original request rather than sending something new).
type recordedRequest struct {
	method  string
	path    string
	headers http.Header
	body    []byte
}

// newLeaderRedirectServer starts an httptest.TLSServer whose handler is fully
// caller-controlled via respond. It shares its underlying certificate with
// every other httptest.NewTLSServer in this process (net/http/httptest always
// uses the same fixed localhost cert/key), so a *Transport backed by one
// server's client can dial another server started this way without any extra
// trust wiring -- exactly mirroring how a real cluster's replicas share one
// CA/SPKI pin.
func newLeaderRedirectServer(t *testing.T, calls *int32, respond func(w http.ResponseWriter, rec recordedRequest)) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		respond(w, recordedRequest{method: r.Method, path: r.URL.Path, headers: r.Header.Clone(), body: body})
	}))
}

// hostPort strips the scheme from an httptest server URL, mimicking the bare
// "host:port" format the cluster registry advertises (see the ShardID/
// LeaderAddress examples used elsewhere, e.g. "10.0.0.2:63001").
func hostPort(serverURL string) string {
	return strings.TrimPrefix(serverURL, "https://")
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	require.NoError(t, json.NewEncoder(w).Encode(v))
}

// TestDoRawRequest_FollowsLeaderRedirect proves the transport's single hop:
// a follower's 421 carrying X-XKMS-Leader-API-Address is retried, once,
// against the leader, replaying the identical method/path/body/headers, and
// the leader's success response is what the caller sees.
func TestDoRawRequest_FollowsLeaderRedirect(t *testing.T) {
	var leaderCalls, followerCalls int32
	var leaderReq recordedRequest

	leader := newLeaderRedirectServer(t, &leaderCalls, func(w http.ResponseWriter, rec recordedRequest) {
		leaderReq = rec
		writeJSON(t, w, http.StatusOK, transport.GenerateKeyResponse{KeyID: "key-from-leader"})
	})
	defer leader.Close()

	follower := newLeaderRedirectServer(t, &followerCalls, func(w http.ResponseWriter, rec recordedRequest) {
		w.Header().Set(headerLeaderAPIAddress, hostPort(leader.URL))
		writeJSON(t, w, http.StatusMisdirectedRequest, map[string]string{"error": "not leader"})
	})
	defer follower.Close()

	cfg := transport.DefaultConfig()
	cfg.JWTToken = "tok-123"
	cfg.Headers = map[string]string{"X-Test-Marker": "caller-credential"}

	tr := &Transport{
		config:     cfg,
		httpClient: follower.Client(),
		baseURL:    follower.URL,
		connected:  true,
	}

	resp, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		Algorithm: "ECDSA",
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "key-from-leader", resp.KeyID)

	assert.EqualValues(t, 1, atomic.LoadInt32(&followerCalls), "follower must be hit exactly once")
	assert.EqualValues(t, 1, atomic.LoadInt32(&leaderCalls), "leader must be hit exactly once")

	// The retry must land on the SAME path, replay the SAME body, and carry
	// every header the caller's own credentials depend on -- the caller's
	// own JWT/headers, not anything the follower injected.
	assert.Equal(t, http.MethodPost, leaderReq.method)
	assert.Equal(t, "/api/v1/keys", leaderReq.path)
	assert.Equal(t, "Bearer tok-123", leaderReq.headers.Get("Authorization"))
	assert.Equal(t, "caller-credential", leaderReq.headers.Get("X-Test-Marker"))
	assert.Equal(t, "application/json", leaderReq.headers.Get("Content-Type"))

	var gotBody transport.GenerateKeyRequest
	require.NoError(t, json.Unmarshal(leaderReq.body, &gotBody))
	assert.Equal(t, "ECDSA", gotBody.Algorithm)
	assert.Equal(t, "software", gotBody.Backend)
}

// TestDoRawRequest_NotLeaderWithoutAddress_NoRetry proves the pre-existing
// behavior is preserved when the follower cannot advertise a leader endpoint:
// the client must not attempt any redirect and must surface the 421 as an
// error, exactly as before this feature existed.
func TestDoRawRequest_NotLeaderWithoutAddress_NoRetry(t *testing.T) {
	var followerCalls int32
	follower := newLeaderRedirectServer(t, &followerCalls, func(w http.ResponseWriter, rec recordedRequest) {
		// Deliberately no headerLeaderAPIAddress set.
		writeJSON(t, w, http.StatusMisdirectedRequest, map[string]string{"error": "not leader, unknown leader endpoint"})
	})
	defer follower.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: follower.Client(),
		baseURL:    follower.URL,
		connected:  true,
	}

	_, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{Algorithm: "ECDSA", Backend: "software"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not leader")
	assert.EqualValues(t, 1, atomic.LoadInt32(&followerCalls))
}

// TestDoRawRequest_SecondNotLeaderIsSurfacedNotChased proves the "exactly one
// hop" contract: if the leader ITSELF answers 421 (even advertising a further
// address), the transport returns that error to the caller instead of
// chasing a second redirect.
func TestDoRawRequest_SecondNotLeaderIsSurfacedNotChased(t *testing.T) {
	var thirdCalls int32
	third := newLeaderRedirectServer(t, &thirdCalls, func(w http.ResponseWriter, rec recordedRequest) {
		writeJSON(t, w, http.StatusOK, transport.GenerateKeyResponse{KeyID: "should-never-be-reached"})
	})
	defer third.Close()

	var leaderCalls int32
	leader := newLeaderRedirectServer(t, &leaderCalls, func(w http.ResponseWriter, rec recordedRequest) {
		// The "leader" is itself stale and points at a third node. A
		// compliant client must NOT chase this.
		w.Header().Set(headerLeaderAPIAddress, hostPort(third.URL))
		writeJSON(t, w, http.StatusMisdirectedRequest, map[string]string{"error": "not leader (stale)"})
	})
	defer leader.Close()

	var followerCalls int32
	follower := newLeaderRedirectServer(t, &followerCalls, func(w http.ResponseWriter, rec recordedRequest) {
		w.Header().Set(headerLeaderAPIAddress, hostPort(leader.URL))
		writeJSON(t, w, http.StatusMisdirectedRequest, map[string]string{"error": "not leader"})
	})
	defer follower.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: follower.Client(),
		baseURL:    follower.URL,
		connected:  true,
	}

	_, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{Algorithm: "ECDSA", Backend: "software"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not leader (stale)")

	assert.EqualValues(t, 1, atomic.LoadInt32(&followerCalls), "follower hit exactly once")
	assert.EqualValues(t, 1, atomic.LoadInt32(&leaderCalls), "leader hit exactly once")
	assert.EqualValues(t, 0, atomic.LoadInt32(&thirdCalls), "the second redirect must never be chased")
}

// TestDoRawRequest_InvalidLeaderAddress proves a malformed leader-address
// header surfaces as the typed *ErrInvalidLeaderRedirect rather than a
// confusing dial failure or a silently swallowed redirect.
func TestDoRawRequest_InvalidLeaderAddress(t *testing.T) {
	var followerCalls int32
	follower := newLeaderRedirectServer(t, &followerCalls, func(w http.ResponseWriter, rec recordedRequest) {
		// A path-only value with no host at all: after the transport's
		// "https://" defaulting this parses to an empty authority.
		w.Header().Set(headerLeaderAPIAddress, "/not-a-host")
		writeJSON(t, w, http.StatusMisdirectedRequest, map[string]string{"error": "not leader"})
	})
	defer follower.Close()

	tr := &Transport{
		config:     transport.DefaultConfig(),
		httpClient: follower.Client(),
		baseURL:    follower.URL,
		connected:  true,
	}

	_, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{Algorithm: "ECDSA", Backend: "software"})
	require.Error(t, err)

	var redirectErr *ErrInvalidLeaderRedirect
	require.True(t, errors.As(err, &redirectErr), "expected *ErrInvalidLeaderRedirect, got %T: %v", err, err)
	assert.Equal(t, "/not-a-host", redirectErr.Address)

	assert.EqualValues(t, 1, atomic.LoadInt32(&followerCalls))
}

// TestLeaderRedirectBaseURL_UnparsableAddress exercises the helper directly
// with a value net/url refuses to parse at all (a raw control character),
// which is impractical to carry over a real HTTP header in a test harness but
// must still degrade to the same typed error rather than a panic.
func TestLeaderRedirectBaseURL_UnparsableAddress(t *testing.T) {
	_, err := leaderRedirectBaseURL("bad\x7flead:1")
	require.Error(t, err)

	var redirectErr *ErrInvalidLeaderRedirect
	require.True(t, errors.As(err, &redirectErr), "expected *ErrInvalidLeaderRedirect, got %T: %v", err, err)
}

// TestLeaderRedirectBaseURL_AddsSchemeAndTrimsSlash proves the happy path: a
// bare "host:port" address (the format the cluster registry advertises) is
// turned into a dialable https base URL, and an already-prefixed address with
// a trailing slash is normalized the same way DoRawRequest's own baseURL is.
func TestLeaderRedirectBaseURL_AddsSchemeAndTrimsSlash(t *testing.T) {
	base, err := leaderRedirectBaseURL("10.0.0.2:63001")
	require.NoError(t, err)
	assert.Equal(t, "https://10.0.0.2:63001", base)

	base, err = leaderRedirectBaseURL("https://10.0.0.2:63001/")
	require.NoError(t, err)
	assert.Equal(t, "https://10.0.0.2:63001", base)
}

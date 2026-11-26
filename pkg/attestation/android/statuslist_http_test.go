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

package android

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statusEndpoint is an httptest stand-in for Google's status list
// endpoint. Tests never reach the real URL.
type statusEndpoint struct {
	server   *httptest.Server
	requests atomic.Int32

	mu      sync.Mutex
	body    string
	headers map[string]string
	status  int
	delay   time.Duration
}

func newStatusEndpoint(t *testing.T, body string, headers map[string]string) *statusEndpoint {
	t.Helper()
	e := &statusEndpoint{body: body, headers: headers, status: http.StatusOK}
	e.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.requests.Add(1)
		e.mu.Lock()
		body, headers, status, delay := e.body, e.headers, e.status, e.delay
		e.mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, err := w.Write([]byte(body))
		if err != nil {
			return
		}
	}))
	t.Cleanup(e.server.Close)
	return e
}

func (e *statusEndpoint) setDelay(delay time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.delay = delay
}

func (e *statusEndpoint) set(status int, body string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status, e.body = status, body
}

// testClock is a settable clock.
type testClock struct{ now atomic.Pointer[time.Time] }

func newTestClock() *testClock {
	c := &testClock{}
	c.set(time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC))
	return c
}

func (c *testClock) Now() time.Time      { return *c.now.Load() }
func (c *testClock) set(t time.Time)     { c.now.Store(&t) }
func (c *testClock) add(d time.Duration) { c.set(c.Now().Add(d)) }

func newSource(t *testing.T, e *statusEndpoint, clock *testClock, opts HTTPStatusListOptions) *HTTPStatusList {
	t.Helper()
	opts.URL = e.server.URL
	opts.Client = e.server.Client()
	if clock != nil {
		opts.Now = clock.Now
	}
	source, err := NewHTTPStatusList(opts)
	require.NoError(t, err)
	return source
}

func TestHTTPStatusList_FetchesAndCachesForMaxAge(t *testing.T) {
	e := newStatusEndpoint(t, googleExampleList, map[string]string{"Cache-Control": "public, max-age=3600"})
	clock := newTestClock()
	source := newSource(t, e, clock, HTTPStatusListOptions{})

	list, err := source.Current()
	require.NoError(t, err)
	assert.Equal(t, 2, list.Len())

	clock.add(59 * time.Minute)
	again, err := source.Current()
	require.NoError(t, err)
	assert.Same(t, list, again)
	assert.EqualValues(t, 1, e.requests.Load(), "a fresh list is not fetched again")

	clock.add(2 * time.Minute)
	_, err = source.Current()
	require.NoError(t, err)
	assert.EqualValues(t, 2, e.requests.Load(), "a stale list is fetched again")
}

func TestHTTPStatusList_ChecksAChain(t *testing.T) {
	e := newStatusEndpoint(t, `{"entries":{"b2":{"status":"REVOKED","reason":"CA_COMPROMISE"}}}`, nil)
	source := newSource(t, e, nil, HTTPStatusListOptions{})
	chain := newTestChain(t, serial(t, "a1"), serial(t, "b2"), serial(t, "c3"))

	err := CheckRevocation(source, chain.certs())

	var revoked *RevokedCertificateError
	require.ErrorAs(t, err, &revoked)
	assert.Equal(t, RevokedCertificateError{Serial: "b2", Status: CertificateStatusRevoked, Reason: RevocationReasonCACompromise}, *revoked)
}

func TestHTTPStatusList_StaleCacheWithEndpointDownFailsClosed(t *testing.T) {
	e := newStatusEndpoint(t, googleExampleList, map[string]string{"Cache-Control": "max-age=60"})
	clock := newTestClock()
	source := newSource(t, e, clock, HTTPStatusListOptions{})
	_, err := source.Current()
	require.NoError(t, err)

	e.set(http.StatusServiceUnavailable, "down")
	clock.add(61 * time.Second)

	list, err := source.Current()
	require.ErrorIs(t, err, ErrStatusListUnavailable)
	require.ErrorIs(t, err, ErrStatusListHTTPStatus)
	assert.Nil(t, list, "a stale list is never used")
	assert.Contains(t, err.Error(), e.server.URL)

	e.server.Close()
	_, err = source.Current()
	require.ErrorIs(t, err, ErrStatusListUnavailable, "an unreachable endpoint fails closed too")
}

func TestHTTPStatusList_MalformedBody(t *testing.T) {
	e := newStatusEndpoint(t, `{"entries":{"ab":{"status":"VALID"}}}`, nil)
	_, err := newSource(t, e, nil, HTTPStatusListOptions{}).Current()
	require.ErrorIs(t, err, ErrStatusListUnavailable)
	require.ErrorIs(t, err, ErrStatusListMalformed)
}

func TestHTTPStatusList_OverSizeBody(t *testing.T) {
	big := `{"entries":{}}` + strings.Repeat(" ", 1024)

	t.Run("declared length", func(t *testing.T) {
		e := newStatusEndpoint(t, big, nil)
		_, err := newSource(t, e, nil, HTTPStatusListOptions{MaxBytes: 512}).Current()
		require.ErrorIs(t, err, ErrStatusListTooLarge)
		require.ErrorIs(t, err, ErrStatusListUnavailable)
	})

	t.Run("streamed body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}
			// Flushing before the body is done sends it chunked, with no
			// Content-Length to refuse up front.
			for _, chunk := range []string{big[:600], big[600:]} {
				if _, err := w.Write([]byte(chunk)); err != nil {
					return
				}
				flusher.Flush()
			}
		}))
		t.Cleanup(server.Close)
		source, err := NewHTTPStatusList(HTTPStatusListOptions{URL: server.URL, Client: server.Client(), MaxBytes: 512})
		require.NoError(t, err)

		_, err = source.Current()
		require.ErrorIs(t, err, ErrStatusListTooLarge)
	})
}

func TestHTTPStatusList_Timeout(t *testing.T) {
	e := newStatusEndpoint(t, googleExampleList, nil)
	e.setDelay(5 * time.Second)
	source := newSource(t, e, nil, HTTPStatusListOptions{Timeout: 50 * time.Millisecond})

	start := time.Now()
	_, err := source.Current()

	require.ErrorIs(t, err, ErrStatusListUnavailable)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 2*time.Second, "the fetch is bounded by the timeout")
}

func TestHTTPStatusList_ConcurrentStaleCallersFetchOnce(t *testing.T) {
	e := newStatusEndpoint(t, googleExampleList, map[string]string{"Cache-Control": "max-age=600"})
	e.setDelay(20 * time.Millisecond)
	source := newSource(t, e, newTestClock(), HTTPStatusListOptions{})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := source.Current()
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.EqualValues(t, 1, e.requests.Load())
}

func TestNewHTTPStatusList(t *testing.T) {
	t.Run("defaults to Google", func(t *testing.T) {
		source, err := NewHTTPStatusList(HTTPStatusListOptions{})
		require.NoError(t, err)
		assert.Equal(t, GoogleStatusListURL, source.URL())
	})

	for _, bad := range []string{"ftp://example.test/status", "/attestation/status", "https://", "http://[::1"} {
		t.Run(bad, func(t *testing.T) {
			_, err := NewHTTPStatusList(HTTPStatusListOptions{URL: bad})
			require.ErrorIs(t, err, ErrInvalidStatusListURL)
		})
	}
}

func TestFreshUntil_AgeBeyondLifetimeIsStale(t *testing.T) {
	received := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	for _, age := range []string{"60", "120"} {
		t.Run("Age "+age, func(t *testing.T) {
			header := http.Header{"Cache-Control": {"max-age=60"}, "Age": {age}}
			got, stale := freshUntil(header, received, received)
			assert.True(t, stale, "RFC 9111 §4.2: fresh only while freshness_lifetime > current_age")
			assert.False(t, got.After(received))
		})
	}
}

// staleOnceEndpoint answers its first request as a cache holding a list
// past its max-age would, and later ones as the origin, recording whether
// each request asked for revalidation.
func staleOnceEndpoint(t *testing.T, staleAnswers int32) (*httptest.Server, *atomic.Int32, func() []string) {
	t.Helper()
	var requests atomic.Int32
	var mu sync.Mutex
	var cacheControl []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		mu.Lock()
		cacheControl = append(cacheControl, r.Header.Get("Cache-Control"))
		mu.Unlock()
		w.Header().Set("Cache-Control", "max-age=60")
		if n <= staleAnswers {
			w.Header().Set("Age", "120")
		}
		if _, err := w.Write([]byte(googleExampleList)); err != nil {
			return
		}
	}))
	t.Cleanup(server.Close)
	seen := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), cacheControl...)
	}
	return server, &requests, seen
}

func TestHTTPStatusList_StaleResponseIsRevalidatedOnce(t *testing.T) {
	server, requests, cacheControl := staleOnceEndpoint(t, 1)
	clock := newTestClock()
	source, err := NewHTTPStatusList(HTTPStatusListOptions{URL: server.URL, Client: server.Client(), Now: clock.Now})
	require.NoError(t, err)

	list, err := source.Current()
	require.NoError(t, err)
	assert.Equal(t, 2, list.Len())
	assert.EqualValues(t, 2, requests.Load())
	assert.Equal(t, []string{"", "no-cache"}, cacheControl(), "the retry forces revalidation (RFC 9111 §5.2.1.4)")

	clock.add(59 * time.Second)
	again, err := source.Current()
	require.NoError(t, err)
	assert.Same(t, list, again, "the revalidated list is cached for its freshness")
	assert.EqualValues(t, 2, requests.Load())
}

func TestHTTPStatusList_StillStaleResponseIsRefused(t *testing.T) {
	server, requests, cacheControl := staleOnceEndpoint(t, 1<<30)
	source, err := NewHTTPStatusList(HTTPStatusListOptions{URL: server.URL, Client: server.Client()})
	require.NoError(t, err)

	list, err := source.Current()
	require.ErrorIs(t, err, ErrStatusListUnavailable)
	require.ErrorIs(t, err, ErrStatusListStale)
	assert.Nil(t, list, "a list stale on arrival is never used")
	assert.EqualValues(t, 2, requests.Load(), "revalidated once, not more")
	assert.Equal(t, []string{"", "no-cache"}, cacheControl())

	_, err = source.Current()
	require.ErrorIs(t, err, ErrStatusListStale, "nothing stale was cached")
	assert.EqualValues(t, 4, requests.Load())
}

func TestFreshUntil(t *testing.T) {
	received := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	requested := received.Add(-2 * time.Second)
	date := func(t time.Time) string { return t.Format(http.TimeFormat) }

	cases := []struct {
		name    string
		headers map[string]string
		want    time.Duration // after received
	}{
		{"max-age", map[string]string{"Cache-Control": "max-age=3600"}, time.Hour},
		{"quoted max-age", map[string]string{"Cache-Control": `max-age="60"`}, time.Minute},
		{"max-age less Age and round trip", map[string]string{"Cache-Control": "max-age=3600", "Age": "100"}, time.Hour - 102*time.Second},
		{"max-age less apparent age", map[string]string{"Cache-Control": "max-age=3600", "Date": date(received.Add(-10 * time.Minute))}, 50 * time.Minute},
		{"max-age wins over Expires", map[string]string{"Cache-Control": "max-age=60", "Expires": date(received.Add(time.Hour)), "Date": date(received)}, time.Minute},
		{"no-cache", map[string]string{"Cache-Control": "max-age=3600, no-cache"}, 0},
		{"no-store", map[string]string{"Cache-Control": "no-store"}, 0},
		{"invalid max-age", map[string]string{"Cache-Control": "max-age=soon"}, 0},
		{"negative max-age", map[string]string{"Cache-Control": "max-age=-5"}, 0},
		{"Expires less Date", map[string]string{"Expires": date(received.Add(30 * time.Minute)), "Date": date(received)}, 30 * time.Minute},
		{"Expires without Date", map[string]string{"Expires": date(received.Add(30 * time.Minute))}, 30 * time.Minute},
		{"Expires 0", map[string]string{"Expires": "0"}, 0},
		{"Expires in the past", map[string]string{"Expires": date(received.Add(-time.Hour)), "Date": date(received)}, 0},
		{"no caching headers", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			for k, v := range tc.headers {
				header.Set(k, v)
			}
			got, stale := freshUntil(header, requested, received)
			assert.False(t, stale, "only a response with a lifetime it already outlived is stale")
			if tc.want <= 0 {
				assert.False(t, got.After(received), "a response with no remaining freshness is stale on receipt")
				return
			}
			assert.Equal(t, received.Add(tc.want), got)
		})
	}
}

func TestParseDeltaSeconds(t *testing.T) {
	seconds, ok := parseDeltaSeconds("99999999999999999999999")
	assert.True(t, ok)
	assert.EqualValues(t, maxDeltaSeconds, seconds, "RFC 9111 §1.2.2 saturates an unrepresentable value")

	_, ok = parseDeltaSeconds("")
	assert.False(t, ok)
	_, ok = parseDeltaSeconds("1.5")
	assert.False(t, ok)
}

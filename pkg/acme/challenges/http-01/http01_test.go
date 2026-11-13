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

package http01

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// loopbackClient returns a validation client that may reach the loopback
// httptest servers these tests run against.
func loopbackClient() *validation.Client {
	return validation.NewClient(validation.Config{AllowPrivateTargets: true})
}

func TestVerify_WithWhitespace(t *testing.T) {
	expectedKeyAuth := "test-token.test-thumbprint"

	// Create a test HTTP server that serves key auth with surrounding whitespace
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "  %s  \n", expectedKeyAuth)
	}))
	defer ts.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}

	client := loopbackClient()

	err = Verify(client, host, port, "test-token", expectedKeyAuth)
	if err != nil {
		t.Errorf("Verify() should handle whitespace trimming: %v", err)
	}
}

func TestChallengeHandlerHTTPx_CorrectHeaders(t *testing.T) {
	keyAuth := "test-key-authorization-headers"
	handler := challengeHandlerHTTPx(keyAuth)

	req := httptest.NewRequest(http.MethodGet, wellKnownChallengePath+"test-token", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/plain" {
		t.Errorf("Expected Content-Type 'text/plain', got %q", contentType)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != keyAuth {
		t.Errorf("Expected body %q, got %q", keyAuth, string(body))
	}
}

func TestChallengeHandlerHTTPx_DifferentMethods(t *testing.T) {
	keyAuth := "test-key-authorization-methods"
	handler := challengeHandlerHTTPx(keyAuth)

	methods := []string{http.MethodGet, http.MethodPost, http.MethodHead}

	for _, method := range methods {
		req := httptest.NewRequest(method, wellKnownChallengePath+"test-token", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		resp := w.Result()
		_ = resp.Body.Close()

		// The handler should respond to all methods
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Method %s: Expected status 200, got %d", method, resp.StatusCode)
		}
	}
}

// TestVerify_FollowsRedirect pins RFC 8555 section 8.3: the server follows
// a redirect when dereferencing the challenge URL, and the redirect target's
// key authorization is what is checked.
func TestVerify_FollowsRedirect(t *testing.T) {
	expectedKeyAuth := "test-token.test-thumbprint"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, expectedKeyAuth)
	}))
	defer target.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirectServer.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(redirectServer.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}

	if err := Verify(loopbackClient(), host, port, "test-token", expectedKeyAuth); err != nil {
		t.Fatalf("Verify() through a redirect failed: %v", err)
	}
}

// TestVerify_RefusesLoopbackByDefault proves the production client -- no
// AllowPrivateTargets -- will not fetch a challenge from a loopback target.
func TestVerify_RefusesLoopbackByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a reserved target must never be contacted")
	}))
	defer ts.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to parse test server URL: %v", err)
	}

	err = Verify(validation.NewClient(validation.Config{}), host, port, "test-token", "keyauth")
	var verr *validation.Error
	if !errors.As(err, &verr) || verr.Kind != validation.KindTargetRefused {
		t.Fatalf("Verify() error = %v, want a KindTargetRefused *validation.Error", err)
	}
}

// TestVerify_RejectsInjectedDomain proves an identifier carrying URL syntax
// is refused before any request is made.
func TestVerify_RejectsInjectedDomain(t *testing.T) {
	err := Verify(loopbackClient(), "169.254.169.254/latest/meta-data#", "80", "token", "keyauth")
	var verr *validation.Error
	if !errors.As(err, &verr) || verr.Kind != validation.KindInvalidTarget {
		t.Fatalf("Verify() error = %v, want a KindInvalidTarget *validation.Error", err)
	}
}

// TestVerify_NilClient proves a verifier wired without a client fails
// closed.
func TestVerify_NilClient(t *testing.T) {
	if err := Verify(nil, "example.com", "80", "token", "keyauth"); !errors.Is(err, validation.ErrNilClient) {
		t.Fatalf("Verify(nil client) error = %v, want ErrNilClient", err)
	}
}

func TestVerify_ReadBodyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("short"))
	}))
	defer ts.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))

	client := loopbackClient()

	err := Verify(client, host, port, "test-token", "expected-keyauth")
	if err == nil {
		t.Error("Verify() should fail when body reading fails due to content-length mismatch")
	}
}

type failingWriter struct {
	headerWritten bool
}

func (fw *failingWriter) Header() http.Header {
	return make(http.Header)
}

func (fw *failingWriter) Write([]byte) (int, error) {
	if fw.headerWritten {
		return 0, caerrors.InternalServerError("write failed")
	}
	fw.headerWritten = true
	return 0, caerrors.InternalServerError("write failed")
}

func (fw *failingWriter) WriteHeader(statusCode int) {
}

func TestChallengeHandlerHTTPx_WriteError(t *testing.T) {
	keyAuth := "test-key-authorization-write-error"
	handler := challengeHandlerHTTPx(keyAuth)

	req := httptest.NewRequest(http.MethodGet, wellKnownChallengePath+"test-token", nil)
	w := &failingWriter{}

	handler(w, req)
}

func TestVerify_HTTPStatusCodes(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		shouldFail bool
	}{
		{"StatusOK", http.StatusOK, false},
		{"StatusBadRequest", http.StatusBadRequest, true},
		{"StatusUnauthorized", http.StatusUnauthorized, true},
		{"StatusForbidden", http.StatusForbidden, true},
		{"StatusInternalServerError", http.StatusInternalServerError, true},
		{"StatusServiceUnavailable", http.StatusServiceUnavailable, true},
	}

	expectedKeyAuth := "test-token.test-thumbprint"

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				if tc.statusCode == http.StatusOK {
					_, _ = fmt.Fprint(w, expectedKeyAuth)
				}
			}))
			defer ts.Close()

			host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			client := loopbackClient()

			err = Verify(client, host, port, "test-token", expectedKeyAuth)

			if tc.shouldFail && (err == nil || !strings.Contains(err.Error(), "unexpected HTTP status")) {
				t.Errorf("Verify() error = %v, want an 'unexpected HTTP status' error", err)
			}
			if !tc.shouldFail && err != nil {
				t.Errorf("Expected Verify to succeed but got error: %v", err)
			}
		})
	}
}

func TestVerify_CustomResolver(t *testing.T) {
	expectedKeyAuth := "test-token.test-thumbprint"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, expectedKeyAuth)
	}))
	defer ts.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	// Create a custom resolver
	customResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	client := validation.NewClient(validation.Config{AllowPrivateTargets: true, Resolver: customResolver})
	err = Verify(client, host, port, "test-token", expectedKeyAuth)
	if err != nil {
		t.Errorf("Verify with custom resolver failed: %v", err)
	}
}

func TestVerify_EmptyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// Send empty response
	}))
	defer ts.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}

	client := loopbackClient()

	err = Verify(client, host, port, "test-token", "expected-keyauth")
	if err == nil {
		t.Error("Verify should fail with empty response")
	}
	if !strings.Contains(err.Error(), "key authorization mismatch") {
		t.Errorf("Expected key authorization mismatch error, got: %v", err)
	}
}

func BenchmarkVerify(b *testing.B) {
	expectedKeyAuth := "bench-token.bench-thumbprint"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, expectedKeyAuth)
	}))
	defer ts.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		b.Fatalf("Failed to parse test server URL: %v", err)
	}

	client := loopbackClient()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(client, host, port, "bench-token", expectedKeyAuth)
	}
}

// occupyEphemeralPort binds port 0 and returns the still-open listener along
// with the port the kernel assigned, so a caller can collide with it on
// purpose.
func occupyEphemeralPort(t *testing.T) (net.Listener, string) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatalf("split listener address: %v", err)
	}
	return listener, port
}

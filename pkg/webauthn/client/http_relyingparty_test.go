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

package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

// ----------------------------------------------------------------------------
// NewHTTPRelyingParty construction.
// ----------------------------------------------------------------------------

func TestNewHTTPRelyingParty_EmptyServerURL(t *testing.T) {
	rp, err := NewHTTPRelyingParty("", nil)
	if rp != nil {
		t.Fatal("expected a nil RelyingParty for an empty server URL")
	}
	if !errors.Is(err, ErrServerURLRequired) {
		t.Errorf("error = %v, want %v", err, ErrServerURLRequired)
	}
}

func TestNewHTTPRelyingParty_NilHTTPClientBuildsDefault(t *testing.T) {
	rp, err := NewHTTPRelyingParty("https://xkms.example.com", nil)
	if err != nil {
		t.Fatalf("NewHTTPRelyingParty: %v", err)
	}
	if rp.httpClient == nil {
		t.Fatal("a nil httpClient argument must be replaced with a default *http.Client")
	}
	if rp.httpClient.Timeout <= 0 {
		t.Error("the default client must carry a non-zero timeout")
	}
}

// ----------------------------------------------------------------------------
// Malformed server URL: every RP call must surface the request-construction
// failure through wrapError rather than panicking or dialing.
// ----------------------------------------------------------------------------

// malformedServerURL embeds a raw control character, which net/url.Parse
// (and therefore http.NewRequestWithContext) rejects outright.
const malformedServerURL = "http://xkms.example.com/\x7f"

func TestHTTPRelyingParty_MalformedServerURL_FailsRequestConstruction(t *testing.T) {
	rp := &HTTPRelyingParty{httpClient: http.DefaultClient, serverURL: malformedServerURL}
	ctx := context.Background()

	t.Run("BeginRegistration", func(t *testing.T) {
		_, err := rp.BeginRegistration(ctx, &RegistrationRequest{Username: "user"})
		assertClientError(t, err, "create request")
	})

	t.Run("FinishRegistration", func(t *testing.T) {
		_, err := rp.FinishRegistration(ctx, &BeginResult{SessionID: "s1"}, &RegistrationRequest{Username: "user"}, []byte("{}"))
		assertClientError(t, err, "create request")
	})

	t.Run("BeginAuthentication", func(t *testing.T) {
		_, err := rp.BeginAuthentication(ctx, &AuthenticationRequest{Username: "user"})
		assertClientError(t, err, "create request")
	})

	t.Run("FinishAuthentication", func(t *testing.T) {
		_, err := rp.FinishAuthentication(ctx, &BeginResult{SessionID: "s1"}, &AuthenticationRequest{Username: "user"}, []byte("{}"))
		assertClientError(t, err, "create request")
	})

	t.Run("Available", func(t *testing.T) {
		if rp.Available(ctx) {
			t.Error("Available() must report false when the health-check request cannot even be constructed")
		}
	})
}

func assertClientError(t *testing.T, err error, wantOp string) {
	t.Helper()
	var clientErr *ClientError
	if !errors.As(err, &clientErr) {
		t.Fatalf("expected *ClientError, got %T: %v", err, err)
	}
	if clientErr.Op != wantOp {
		t.Errorf("Op = %q, want %q", clientErr.Op, wantOp)
	}
}

// ----------------------------------------------------------------------------
// A response body that fails mid-read: every RP call that decodes a body
// must surface that failure rather than treating a truncated read as a
// legitimate (if empty) response.
// ----------------------------------------------------------------------------

var errBrokenBody = errors.New("http_relyingparty test: body read failure")

// brokenBody is an io.ReadCloser that always fails, so io.ReadAll on a
// response built from it returns errBrokenBody without ever reaching a real
// network read.
type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errBrokenBody }
func (brokenBody) Close() error             { return nil }

// brokenBodyTransport is an http.RoundTripper stand-in that answers every
// request with 200 OK and a session header, but a body that fails on Read
// — the seam needed to force the io.ReadAll branch in each RP call without
// a real network fault.
type brokenBodyTransport struct{}

func (brokenBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	header := make(http.Header)
	header.Set(headerSessionID, "session-1")
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     header,
		Body:       brokenBody{},
		Request:    req,
	}, nil
}

func TestHTTPRelyingParty_BrokenResponseBody_SurfacesReadFailure(t *testing.T) {
	rp := &HTTPRelyingParty{
		httpClient: &http.Client{Transport: brokenBodyTransport{}},
		serverURL:  "https://xkms.example.com",
	}
	ctx := context.Background()

	t.Run("BeginRegistration", func(t *testing.T) {
		_, err := rp.BeginRegistration(ctx, &RegistrationRequest{Username: "user"})
		assertWrapsBrokenBody(t, err)
	})

	t.Run("FinishRegistration", func(t *testing.T) {
		_, err := rp.FinishRegistration(ctx, &BeginResult{SessionID: "s1"}, &RegistrationRequest{Username: "user"}, []byte("{}"))
		assertWrapsBrokenBody(t, err)
	})

	t.Run("BeginAuthentication", func(t *testing.T) {
		_, err := rp.BeginAuthentication(ctx, &AuthenticationRequest{Username: "user"})
		assertWrapsBrokenBody(t, err)
	})

	t.Run("FinishAuthentication", func(t *testing.T) {
		_, err := rp.FinishAuthentication(ctx, &BeginResult{SessionID: "s1"}, &AuthenticationRequest{Username: "user"}, []byte("{}"))
		assertWrapsBrokenBody(t, err)
	})
}

func assertWrapsBrokenBody(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errBrokenBody) {
		t.Fatalf("expected the broken-body read failure in the chain, got %T: %v", err, err)
	}
	var clientErr *ClientError
	if !errors.As(err, &clientErr) || clientErr.Op != "read response" {
		t.Fatalf("expected a *ClientError{Op: \"read response\"}, got %T: %v", err, err)
	}
}

var _ io.ReadCloser = brokenBody{}

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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// guardOn turns the mandatory-TLS guard back on for one test (TestMain opts
// the package out of it): with the variable empty, the config field decides.
func guardOn(t *testing.T) {
	t.Helper()
	t.Setenv(transport.EnvAllowInsecureTransport, "")
}

func TestNew_RefusesPlaintextHTTP(t *testing.T) {
	guardOn(t)

	for name, cfg := range map[string]*transport.Config{
		"http url":              {Address: "http://10.0.0.1:8443"},
		"bare host without tls": {Address: "127.0.0.1:8443"},
		"http url despite tls":  {Address: "http://10.0.0.1:8443", TLSEnabled: true},
		"default config":        nil,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewWithConfig(cfg)
			assert.ErrorIs(t, err, transport.ErrInsecureTransport)
		})
	}

	_, err := New(transport.WithAddress("http://10.0.0.1:8443"))
	assert.ErrorIs(t, err, transport.ErrInsecureTransport)
}

func TestNew_AdmitsSecureOrOptedOutEndpoints(t *testing.T) {
	guardOn(t)

	for name, cfg := range map[string]*transport.Config{
		"https url":          {Address: "https://10.0.0.1:8443"},
		"bare host with tls": {Address: "10.0.0.1:8443", TLSEnabled: true},
		"loopback opt-out":   {Address: "http://127.0.0.1:8443", AllowInsecureTransport: true},
	} {
		t.Run(name, func(t *testing.T) {
			tr, err := NewWithConfig(cfg)
			require.NoError(t, err)
			assert.Same(t, cfg, tr.Config())
		})
	}

	tr, err := New(transport.WithAddress("http://127.0.0.1:8443"), transport.WithAllowInsecureTransport(true))
	require.NoError(t, err)
	assert.True(t, tr.Config().AllowInsecureTransport, "the option sets the opt-out")
}

func TestSignImage_RefusesRegistryCredentialsOverPlaintext(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			t.Errorf("write health response: %v", err)
		}
	}))
	defer srv.Close()

	cfg := &transport.Config{Address: srv.URL, AllowInsecureTransport: true}
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))

	// The opt-out is withdrawn after the connection is up; the credential
	// must still never leave the process.
	guardOn(t)
	cfg.AllowInsecureTransport = false
	before := requests.Load()
	_, err = tr.SignImage(context.Background(), &transport.SignImageRequest{
		Reference: "registry.example/app:1",
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: types.SecretBytes("hunter2")},
	})
	require.ErrorIs(t, err, transport.ErrInsecureTransport)
	assert.NotContains(t, err.Error(), "hunter2")
	assert.Equal(t, before, requests.Load(), "no request reached the server")
}

func TestSignImage_GuardAdmitsCredentialFreeOrSecureRequests(t *testing.T) {
	guardOn(t)

	plaintext, err := NewWithConfig(&transport.Config{Address: "http://127.0.0.1:8443", AllowInsecureTransport: true})
	require.NoError(t, err)
	plaintext.Config().AllowInsecureTransport = false
	_, err = plaintext.SignImage(context.Background(), &transport.SignImageRequest{Reference: "registry.example/app:1"})
	assert.ErrorIs(t, err, ErrNotConnected, "a request without registry credentials passes the guard")

	secure, err := NewWithConfig(&transport.Config{Address: "https://10.0.0.1:8443"})
	require.NoError(t, err)
	_, err = secure.SignImage(context.Background(), &transport.SignImageRequest{
		Reference: "registry.example/app:1",
		Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: types.SecretBytes("hunter2")},
	})
	assert.ErrorIs(t, err, ErrNotConnected, "credentials over TLS pass the guard")
}

// redirectingServer is an https server that redirects /redirect to location
// with status and answers every other path, the health check included, with
// a JSON body naming the path.
func redirectingServer(t *testing.T, status int, location string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, location, status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := fmt.Fprintf(w, `{"status":"ok","path":%q}`, r.URL.Path); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// plaintextLanding is an http server that records how many requests reach
// it and the body of the last one.
type plaintextLanding struct {
	srv      *httptest.Server
	requests atomic.Int32
	body     atomic.Value
}

func newPlaintextLanding(t *testing.T) *plaintextLanding {
	t.Helper()
	l := &plaintextLanding{}
	l.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		l.body.Store(string(body))
		l.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(l.srv.Close)
	return l
}

// connectOverTLS connects a transport to the httptest TLS server srv,
// trusting its certificate.
func connectOverTLS(t *testing.T, srv *httptest.Server, allowInsecure bool) *Transport {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	tr, err := NewWithConfig(&transport.Config{
		Address:                srv.URL,
		TLSEnabled:             true,
		TLSConfig:              &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		AllowInsecureTransport: allowInsecure,
	})
	require.NoError(t, err)
	require.NoError(t, tr.Connect(context.Background()))
	return tr
}

var registryCredential = map[string]string{"password": "hunter2"}

func TestRedirect_RefusesHTTPSToHTTP(t *testing.T) {
	guardOn(t)

	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			landing := newPlaintextLanding(t)
			tr := connectOverTLS(t, redirectingServer(t, status, landing.srv.URL+"/landing"), false)

			_, err := tr.DoRawRequest(context.Background(), http.MethodPost, "/redirect", registryCredential)
			require.ErrorIs(t, err, transport.ErrInsecureTransport)
			assert.Zero(t, landing.requests.Load(), "the body is never replayed over plaintext")
		})
	}
}

func TestRedirect_AdmitsHTTPSToHTTPWithOptOut(t *testing.T) {
	guardOn(t)

	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			landing := newPlaintextLanding(t)
			tr := connectOverTLS(t, redirectingServer(t, status, landing.srv.URL+"/landing"), true)

			_, err := tr.DoRawRequest(context.Background(), http.MethodPost, "/redirect", registryCredential)
			require.NoError(t, err)
			assert.Equal(t, int32(1), landing.requests.Load())
			assert.Contains(t, landing.body.Load(), "hunter2", "the opt-out lets the redirect replay the body")
		})
	}
}

func TestRedirect_FollowsHTTPSToHTTPS(t *testing.T) {
	guardOn(t)

	tr := connectOverTLS(t, redirectingServer(t, http.StatusTemporaryRedirect, "/landing"), false)

	body, err := tr.DoRawRequest(context.Background(), http.MethodPost, "/redirect", registryCredential)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"/landing"`, "the redirect was followed")
}

func TestRedirect_StopsAfterTenRedirects(t *testing.T) {
	guardOn(t)

	tr := connectOverTLS(t, redirectingServer(t, http.StatusFound, "/redirect"), false)

	_, err := tr.DoRawRequest(context.Background(), http.MethodGet, "/redirect", nil)
	require.ErrorIs(t, err, ErrTooManyRedirects)
}

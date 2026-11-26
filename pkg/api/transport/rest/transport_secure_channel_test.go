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

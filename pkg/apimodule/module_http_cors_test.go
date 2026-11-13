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

package apimodule

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
	"github.com/jeremyhahn/go-qrdb/sdk/go/testutil/qrdbdharness"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// corsHeaderNames returns the Access-Control-* header names of a response.
func corsHeaderNames(h http.Header) []string {
	var names []string
	for name := range h {
		if strings.HasPrefix(name, "Access-Control-") {
			names = append(names, name)
		}
	}
	return names
}

// TestRegisterHTTP_AppliesTheConfiguredCORSPolicy: the routes the module
// registers on the unified API surface do not pass through the chi router's
// global middleware chain, so the module itself applies the REST server's
// CORS policy to each route and answers the preflight of each pattern.
func TestRegisterHTTP_AppliesTheConfiguredCORSPolicy(t *testing.T) {
	const allowed = "https://rp.example"
	const other = "https://other.example"

	srv, err := rest.NewServer(&rest.Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		CORS:          &rest.CORSOptions{AllowedOrigins: []string{allowed}},
	})
	require.NoError(t, err)

	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv }))
	require.NoError(t, err)

	reg, recs := newCaptureRegistrar()
	m.RegisterHTTP(reg)

	// One public POST route, and the preflight route of the same pattern.
	var post, preflight http.HandlerFunc
	var pattern string
	for _, rec := range *recs {
		if rec.public && rec.method == http.MethodPost {
			post, pattern = rec.handler, rec.pattern
			break
		}
	}
	require.NotNil(t, post, "a public POST route must be registered")
	options := 0
	for _, rec := range *recs {
		if rec.method == http.MethodOptions && rec.pattern == pattern {
			options++
			assert.True(t, rec.public, "the preflight route of %s must be public", pattern)
			preflight = rec.handler
		}
	}
	require.Equal(t, 1, options, "OPTIONS %s must be registered exactly once", pattern)

	send := func(h http.HandlerFunc, method, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, pattern, strings.NewReader("{}"))
		req.Header.Set("Origin", origin)
		if method == http.MethodOptions {
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		}
		w := httptest.NewRecorder()
		h(w, req)
		return w
	}

	// Allowed origin: the response of the route carries the origin.
	w := send(post, http.MethodPost, allowed)
	assert.Equal(t, allowed, w.Header().Get("Access-Control-Allow-Origin"))

	// Allowed origin: the preflight is answered with the policy.
	w = send(preflight, http.MethodOptions, allowed)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, allowed, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "X-Session-Id")

	// Any other origin: no CORS header, and the preflight serves nothing.
	w = send(post, http.MethodPost, other)
	assert.Empty(t, corsHeaderNames(w.Header()))
	w = send(preflight, http.MethodOptions, other)
	assert.Empty(t, corsHeaderNames(w.Header()))
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	assert.Empty(t, w.Body.String())
}

// TestUnifiedServer_CORSOnAuthRefusals drives the real go-qrdb unified
// server the module is mounted on: its authentication and authorization
// middleware refuses a request before any module route handler runs, and the
// refusal must still carry the configured CORS policy, or a cross-origin
// browser sees a network error instead of the 401 or 403.
func TestUnifiedServer_CORSOnAuthRefusals(t *testing.T) {
	const allowed = "https://rp.example"

	srv, err := rest.NewServer(&rest.Config{
		Authenticator: auth.NewNoOpAuthenticator(),
		Backends:      map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		CORS:          &rest.CORSOptions{AllowedOrigins: []string{allowed}},
	})
	require.NoError(t, err)
	m, err := NewModule(func() *xkms.XKMSService { return nil },
		WithRESTServer(func() *rest.Server { return srv }))
	require.NoError(t, err)

	certDir := t.TempDir()
	ca, err := qrdbdharness.NewCA(certDir)
	require.NoError(t, err)
	serverKP, err := ca.Issue(certDir, qrdbdharness.WithSubject("node", ""), qrdbdharness.WithServerAuth())
	require.NoError(t, err)
	serverCert, err := serverKP.TLSCertificate()
	require.NoError(t, err)
	// A certificate the CA issued but no account is bound to: authenticated
	// transport, no permission.
	strangerKP, err := ca.Issue(certDir, qrdbdharness.WithSubject("stranger", ""))
	require.NoError(t, err)
	strangerCert, err := strangerKP.TLSCertificate()
	require.NoError(t, err)
	ports, err := qrdbdharness.ReserveTCPPorts(1)
	require.NoError(t, err)

	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.AdminPort = ports[0]
	// The node's outer CORS layer (outside go-qrdb's auth middleware) takes
	// the module's policy, so refusals carry it.
	cfg.CORS, err = m.NodeCORS()
	require.NoError(t, err)
	require.Equal(t, []string{allowed}, cfg.CORS.AllowedOrigins)

	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, []qrdbserver.ServerOption{
		qrdbserver.WithServerTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    ca.Pool,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			MinVersion:   tls.VersionTLS13,
		}),
		qrdbserver.WithModule(m),
	}, serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, node.Close()) })

	client := func(certs ...tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      ca.Pool,
			Certificates: certs,
			MinVersion:   tls.VersionTLS13,
		}}}
	}
	send := func(c *http.Client, bearer string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, "https://"+node.Server().RESTAddr()+"/api/v1/keys", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", allowed)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := c.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp
	}

	// No credential, and an invalid bearer: the auth chain refuses (go-qrdb
	// answers an anonymous caller 401 or 403), with the policy.
	for _, bearer := range []string{"", "expired.or.forged"} {
		resp := send(client(), bearer)
		assert.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, resp.StatusCode,
			"bearer %q", bearer)
		assert.Equal(t, allowed, resp.Header.Get("Access-Control-Allow-Origin"), "refusal, bearer %q", bearer)
	}

	// An authenticated caller without keys:read: 403 with the policy.
	resp := send(client(strangerCert), "")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, allowed, resp.Header.Get("Access-Control-Allow-Origin"), "403")
}

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

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/spki"
)

// newLoginTestServer serves the session-plane routes over TLS, asserting a
// client certificate is present on the PIV route (possession of the card key
// IS the credential) and echoing a token pair.
func newLoginTestServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login/piv", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"client certificate required"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(TokenPair{
			AccessToken: "at", RefreshToken: "rt", TokenType: "Bearer", ExpiresIn: 900,
		})
	})
	mux.HandleFunc("POST /api/v1/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.RefreshToken != "rt" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(TokenPair{AccessToken: "at2", RefreshToken: "rt2"})
	})
	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// The real xkmsd handler answers 204 No Content on logout
		// (pkg/api/rest/handlers_auth.go handleAuthLogout), never 200.
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/v1/auth/validate", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewUnstartedServer(mux)
	// Request (not require) a client certificate so the PIV route can
	// distinguish callers with and without one.
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	t.Cleanup(srv.Close)
	return srv, pool
}

// newTestClientCertificate mints a self-signed client certificate standing
// in for a PIV slot certificate: the private key plays the card key.
func newTestClientCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "piv-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	require.NoError(t, err)
	return cert
}

// TestLoginClient_PIVLogin proves the mTLS-bound PIV login: with a client
// certificate the pair is returned; without one the server's 401 surfaces
// as a typed error carrying the status.
func TestLoginClient_PIVLogin(t *testing.T) {
	srv, pool := newLoginTestServer(t)

	cert := newTestClientCertificate(t)
	c, err := NewLoginClient(LoginClientConfig{
		BaseURL:           srv.URL,
		ClientCertificate: &cert,
		RootCAs:           pool,
	})
	require.NoError(t, err)

	pair, err := c.PIVLogin(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "at", pair.AccessToken)
	assert.Equal(t, "rt", pair.RefreshToken)

	// Without a client certificate: denied, with the HTTP status surfaced.
	anon, err := NewLoginClient(LoginClientConfig{BaseURL: srv.URL, RootCAs: pool})
	require.NoError(t, err)
	_, err = anon.PIVLogin(context.Background())
	var lce *LoginClientError
	require.ErrorAs(t, err, &lce)
	assert.Equal(t, http.StatusUnauthorized, lce.Status)
}

// TestLoginClient_SessionLifecycle proves refresh, validate, and logout over
// the same client, plus the wrong-token failure paths.
func TestLoginClient_SessionLifecycle(t *testing.T) {
	srv, pool := newLoginTestServer(t)
	c, err := NewLoginClient(LoginClientConfig{BaseURL: srv.URL, RootCAs: pool})
	require.NoError(t, err)
	ctx := context.Background()

	pair, err := c.Refresh(ctx, "rt")
	require.NoError(t, err)
	assert.Equal(t, "at2", pair.AccessToken)

	_, err = c.Refresh(ctx, "stolen")
	var lce *LoginClientError
	require.ErrorAs(t, err, &lce)
	assert.Equal(t, http.StatusUnauthorized, lce.Status)

	require.NoError(t, c.Validate(ctx, "at"))
	require.Error(t, c.Validate(ctx, "garbage"))
	require.NoError(t, c.Logout(ctx, "at", "rt"))
}

// TestNewLoginClient_RequiresBaseURL pins the configuration contract.
func TestNewLoginClient_RequiresBaseURL(t *testing.T) {
	_, err := NewLoginClient(LoginClientConfig{})
	var lce *LoginClientError
	require.True(t, errors.As(err, &lce))
	assert.Equal(t, "configure", lce.Op)
}

// TestLoginClientError_MessageAndUnwrap pins the Error() formatting (with
// and without an underlying cause) and the Unwrap() contract.
func TestLoginClientError_MessageAndUnwrap(t *testing.T) {
	withCause := &LoginClientError{Op: "login/piv", Status: 401, Reason: "denied", Err: errors.New("tls: bad certificate")}
	want := "xkms login client: login/piv: denied: tls: bad certificate"
	assert.Equal(t, want, withCause.Error())
	assert.True(t, errors.Is(withCause, withCause.Err))

	noCause := &LoginClientError{Op: "configure", Reason: "BaseURL is required"}
	assert.Equal(t, "xkms login client: configure: BaseURL is required", noCause.Error())
	assert.Nil(t, noCause.Unwrap())
}

// TestLoginClient_SPKIPin proves a LoginClient configured with an SPKI pin
// (the TOFU trust path xkey's server registry records) authenticates the
// server by its SPKI hash instead of a CA chain, without requiring RootCAs
// at all.
func TestLoginClient_SPKIPin(t *testing.T) {
	srv, pool := newLoginTestServer(t)
	_ = pool // the SPKI-pinned config never consults a CA pool

	leaf := srv.Certificate()
	pin, err := spki.ComputePin(leaf)
	require.NoError(t, err)

	c, err := NewLoginClient(LoginClientConfig{BaseURL: srv.URL, SPKIPin: pin})
	require.NoError(t, err)
	require.NoError(t, c.Validate(context.Background(), "at"))

	// A wrong pin must fail the handshake, not silently trust the server.
	wrong, err := NewLoginClient(LoginClientConfig{BaseURL: srv.URL, SPKIPin: "wrong-pin"})
	require.NoError(t, err)
	err = wrong.Validate(context.Background(), "at")
	require.Error(t, err)
}

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

//go:build integration && logins

package logins

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"
)

// defaultLoginTestTimeout bounds a single request/ceremony step. It is
// generous because the fido2 leg drives a real CTAP2 exchange through a
// subprocess.
const defaultLoginTestTimeout = 30 * time.Second

// target describes one server in the login verification matrix.
type target struct {
	// Name identifies the target in subtest names.
	Name string
	// BaseURL is the server's REST base, e.g. "https://xkms-server:8443".
	BaseURL string
	// WebAuthnURL is the base the WebAuthn ceremony legs dial. It differs
	// from BaseURL because a WebAuthn RPID must be "localhost" or contain a
	// dot (go-webauthn validates it as a domain string), so the compose
	// service carries a dotted network alias matching the server's
	// configured rp_id. xkey registers with an SPKI pin, whose TLS trust is
	// the pin itself rather than CA + hostname, so the alias needs no
	// certificate SAN.
	WebAuthnURL string
	// CAFile is the published CA bundle used to verify this server.
	CAFile string
	// AdminCertFile/AdminKeyFile locate this server's first-boot admin
	// mTLS credential.
	AdminCertFile string
	AdminKeyFile  string
}

// targets returns every server target the matrix currently covers. xkmsd is
// always present; the quicbaasd leg joins when QUICBAAS_REST_URL is set
// (the integration-test-logins-quicbaas Makefile lane starts the compose
// quicbaas-server and publishes its CA + first-boot admin credential before
// exporting it). Every test in this package is table-driven over this slice
// for exactly that reason.
func targets() []target {
	ts := []target{
		{
			Name:          "xkmsd",
			BaseURL:       getEnv("KEYSTORE_REST_URL", "https://xkms-server:8443"),
			WebAuthnURL:   getEnv("KEYSTORE_REST_WEBAUTHN_URL", "https://xkms-server.test:8443"),
			CAFile:        getEnv("XKMS_GRPC_TLS_CA", "/tmp/xkms/ca.crt"),
			AdminCertFile: getEnv("XKMS_ADMIN_CERT", "/tmp/xkms/admin-cert.pem"),
			AdminKeyFile:  getEnv("XKMS_ADMIN_KEY", "/tmp/xkms/admin-key.pem"),
		},
	}
	if u := os.Getenv("QUICBAAS_REST_URL"); u != "" {
		ts = append(ts, target{
			Name:          "quicbaasd",
			BaseURL:       u,
			WebAuthnURL:   getEnv("QUICBAAS_REST_WEBAUTHN_URL", "https://quicbaas-server.test:8443"),
			CAFile:        getEnv("QUICBAAS_TLS_CA", "/tmp/quicbaas/ca.crt"),
			AdminCertFile: getEnv("QUICBAAS_ADMIN_CERT", "/tmp/quicbaas/admin.crt"),
			AdminKeyFile:  getEnv("QUICBAAS_ADMIN_KEY", "/tmp/quicbaas/admin.key"),
		})
	}
	return ts
}

// getEnv reads an environment variable, falling back to def when unset or
// empty.
func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadCAPool loads the target's published CA bundle into a cert pool used
// to verify the server, exactly as the other network-lane integration
// suites do.
func loadCAPool(t *testing.T, tgt target) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile(tgt.CAFile)
	require.NoError(t, err, "read CA bundle at %s (did the %s fixture publish it? see the Makefile logins lanes)", tgt.CAFile, tgt.Name)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(data), "parse CA bundle at %s", tgt.CAFile)
	return pool
}

// loadAdminCredential loads the target's first-boot administrator mTLS
// credential. The admin's certificate is SPKI-bound to the admin user by
// qrdb's firstboot ceremony, so it doubles as the minimal honest PIV login
// fixture: no separate enrollment step is needed to prove the route works.
func loadAdminCredential(t *testing.T, tgt target) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(tgt.AdminCertFile, tgt.AdminKeyFile)
	require.NoError(t, err, "load %s admin credential (%s, %s); did the fixture publish it?", tgt.Name, tgt.AdminCertFile, tgt.AdminKeyFile)
	return cert
}

// bindUserCertRequest mirrors pkg/api/rest's bindUserCertBody wire shape.
type bindUserCertRequest struct {
	Thumbprint string `json:"thumbprint"`
}

// ensureAdminCertBinding SPKI-binds the first-boot admin credential to the
// "admin" user via POST /api/v1/users/{username}/cert-bindings, using the
// admin credential itself (mTLS resolves it to "admin" through its
// Subject CN even before any binding exists - see handlers_auth.go's
// certificate fallback) to authenticate the call.
//
// This is test-fixture bootstrapping, not a workaround for the PIV login
// route: qrdb's firstboot ceremony issues the admin's mTLS credential but
// does not itself record a cert-binding credential for it (confirmed via
// GET /api/v1/users/admin/credentials returning empty on a fresh compose
// deployment), so nothing has bound the credential's SPKI thumbprint to the
// admin user until this call does it, exactly as an operator would via
// "xkmsctl user bind-cert" or the admin console. See the accompanying
// report for the upstream gap this papers over.
func ensureAdminCertBinding(t *testing.T, tgt target, admin tls.Certificate) {
	t.Helper()

	require.NotEmpty(t, admin.Certificate, "admin credential has no certificate")
	cert, err := x509.ParseCertificate(admin.Certificate[0])
	require.NoError(t, err, "parse admin certificate")

	body, err := json.Marshal(bindUserCertRequest{Thumbprint: qrdbsdk.ComputeSPKIThumbprint(cert)})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), defaultLoginTestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tgt.BaseURL+"/api/v1/users/admin/cert-bindings", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient(t, tgt, &admin).Do(req)
	require.NoError(t, err, "bind the admin credential's SPKI thumbprint to the admin user")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "cert-binding request must succeed")
}

// httpClient builds an http.Client trusting the target's published CA and,
// when cert is non-nil, presenting it as the TLS client certificate.
func httpClient(t *testing.T, tgt target, cert *tls.Certificate) *http.Client {
	t.Helper()
	tlsCfg := &tls.Config{
		RootCAs:    loadCAPool(t, tgt),
		MinVersion: tls.VersionTLS13,
	}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

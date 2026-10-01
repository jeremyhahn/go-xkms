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

//go:build integration

package oidccredentials

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverid/serveridtest"
)

// TestXKeyLoginServesEveryTransport logs in once with `xkey auth login
// --piv` over REST and proves that one stored login authenticates xkey on
// every transport to the same server: the login is bound to the server's
// TLS identity, not to the URL it was made through. No XKMSD_TOKEN is
// given, and no client certificate except where the server still demands
// one (certOnlyTransports), so the stored login is the credential a call
// carries; the control run with no login is refused. A decoy server
// on the same host with a different certificate never receives the login.
func TestXKeyLoginServesEveryTransport(t *testing.T) {
	home := t.TempDir()
	base := append(xkeyHome(home), "XKMSD_TOKEN=", "XKMSD_TLS_CERT=", "XKMSD_TLS_KEY=", "XKMSD_TLS_CA="+env.caFile)
	base = append(base, pivToken(t, home)...)

	// A PIV credential on the token, issued by the server's CA and bound to
	// the admin user.
	out, err := runXKey(base, "", "piv", "generate", "9a", "--subject", "admin-piv", "--pin-policy", "never")
	require.NoError(t, err, out)
	csr := filepath.Join(home, "piv.csr")
	out, err = runXKey(base, "", "piv", "csr", "9a", "--cn", "admin-piv", "--output", csr)
	require.NoError(t, err, out)
	certFile := filepath.Join(home, "piv.pem")
	out, err = xkmsctl("rest", "ca", "sign-csr", "--csr", csr, "--profile", "client", "--output", certFile)
	require.NoError(t, err, out)
	out, err = runXKey(base, "", "piv", "import", "9a", certFile)
	require.NoError(t, err, out)
	require.NoError(t, bindAdminCert(env.admin, env.urls["rest"], readCert(t, certFile)))

	out, err = runXKey(base, "", "auth", "login", "--piv", "--server", env.urls["rest"],
		"--tls-ca", env.caFile, "--backend", "pkcs11")
	require.NoError(t, err, out)

	for _, transport := range transports {
		t.Run(transport, func(t *testing.T) {
			vars := append(base, "XKMSD_URL="+env.urls[transport], "XKMSD_SERVER_NAME=localhost")
			if certOnlyTransports[transport] {
				vars = append(vars, "XKMSD_TLS_CERT="+env.adminCert, "XKMSD_TLS_KEY="+env.adminKey)
			}
			out, err := runXKey(vars, "", "oidc", "providers", "list")
			require.NoError(t, err, "the REST login authenticates %s:\n%s", transport, out)
		})
	}

	t.Run("no login is refused", func(t *testing.T) {
		vars := append(xkeyHome(t.TempDir()), "XKMSD_TOKEN=", "XKMSD_TLS_CERT=", "XKMSD_TLS_KEY=",
			"XKMSD_TLS_CA="+env.caFile, "XKMSD_URL="+env.urls["rest"])
		out, err := runXKey(vars, "", "oidc", "providers", "list")
		require.Error(t, err, "without the login the call is unauthenticated:\n%s", out)
	})

	t.Run("another certificate on the same host gets no login", func(t *testing.T) {
		var mu sync.Mutex
		var seen []string
		decoy, decoyCA := serveridtest.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = append(seen, r.Header.Get("Authorization"))
			mu.Unlock()
			http.Error(w, "decoy", http.StatusTeapot)
		}))
		vars := append(base, "XKMSD_TLS_CA="+decoyCA, "XKMSD_URL="+decoy.URL)
		out, err := runXKey(vars, "", "oidc", "providers", "list")
		require.Error(t, err, "the decoy is not an xkmsd:\n%s", out)

		mu.Lock()
		defer mu.Unlock()
		require.NotEmpty(t, seen, "xkey reached the decoy")
		for _, auth := range seen {
			assert.Empty(t, auth, "the login never leaves for a different server")
		}
	})
}

// certOnlyTransports are the transports where the stored login alone does
// not yet authenticate. xkmsd verifies its session tokens in the embedded
// qrdb node's auth chain (bearerAuthenticator, through qrdb's
// WithAuthenticators), which covers gRPC; on MCP qrdb hands the request's
// Authorization header to authenticators only through a context accessor
// its SDK does not re-export, so until it does the MCP cell also presents
// the client certificate the server demands.
var certOnlyTransports = map[string]bool{"mcp": true}

// pivToken initializes a SoftHSM token private to the test and points
// xkey's PIV at it through home's xkey config, so the PIV key outlives each
// xkey process (the software PIV backend keeps keys in memory only). It
// returns the environment xkey needs to reach the token.
func pivToken(t *testing.T, home string) []string {
	t.Helper()
	tokens := filepath.Join(home, "tokens")
	require.NoError(t, os.MkdirAll(tokens, 0o700))
	conf := filepath.Join(home, "softhsm2.conf")
	require.NoError(t, os.WriteFile(conf, []byte("directories.tokendir = "+tokens+"\nobjectstore.backend = file\n"), 0o600))
	vars := []string{"SOFTHSM2_CONF=" + conf, "XKEY_PIV_PKCS11_PIN=123456", "XKEY_PIV_PKCS11_SO_PIN=12345678"}

	cmd := exec.Command("softhsm2-util", "--init-token", "--free", "--label", "xkey-piv", "--pin", "123456", "--so-pin", "12345678")
	cmd.Env = append(os.Environ(), vars...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	config := "piv:\n  backend: pkcs11\n  pkcs11_library: /usr/lib/softhsm/libsofthsm2.so\n  pkcs11_token: xkey-piv\n"
	require.NoError(t, os.WriteFile(filepath.Join(home, "config.yaml"), []byte(config), 0o600))
	return vars
}

// readCert parses the PEM certificate in path.
func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block, "no PEM in %s", path)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

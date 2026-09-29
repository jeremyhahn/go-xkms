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

package loopback

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// minimalLoopbackConfig builds the smallest config that Launch can boot: a
// file-backed software engine with every network protocol off (desktopConfig
// overwrites Protocols anyway, so what matters here is that construction
// itself does not need qrdb storage or TLS material).
func minimalLoopbackConfig(t *testing.T) *config.Config {
	t.Helper()
	tempDir := t.TempDir()
	return &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1"},
		Logging: config.LoggingConfig{
			Level:  "error",
			Format: "json",
		},
		TLS:       config.TLSConfig{Enabled: false},
		Auth:      config.AuthConfig{Enabled: false},
		Datastore: config.DatastoreConfig{Engine: "file", Path: tempDir},
		Default:   config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{
				Enabled: true,
				Path:    filepath.Join(tempDir, "software"),
			},
		},
	}
}

// generateSelfSignedTLSCert writes a throwaway self-signed ECDSA certificate
// and private key as PEM files, for a test that needs to enable
// cfg.TLS.Enabled without a real CA: server.New's file-based TLS path
// (pkg/server buildTLSConfig) loads these directly.
func generateSelfSignedTLSCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls-cert.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath = filepath.Join(dir, "tls-key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// generateJWTPublicKeyFile writes a throwaway ECDSA public key as a PEM file
// so a test can configure Auth.Type="jwt" without any real token issuer: it
// is a fail-closed base authenticator that never validates any bearer string
// the test presents to it, which is exactly the point of using it as the
// backdrop for exercising the loopback per-launch token.
func generateJWTPublicKeyFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "jwt-pub.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return path
}

// TestLaunch_BindsLoopbackOnly pins the invariant the desktop standalone mode
// depends on for its off-box-unreachable claim: Launch always binds
// 127.0.0.1, never the wildcard or an IPv6 address, regardless of what the
// caller's Server.Host says.
func TestLaunch_BindsLoopbackOnly(t *testing.T) {
	cfg := minimalLoopbackConfig(t)
	cfg.Server.Host = "0.0.0.0" // caller's remote-daemon setting; must be ignored

	inst, err := Launch(context.Background(), Options{Config: cfg})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close(context.Background()) })

	if !strings.HasPrefix(inst.BaseURL, "http://127.0.0.1:") {
		t.Fatalf("BaseURL = %q, want http://127.0.0.1:<port>", inst.BaseURL)
	}

	// The listener must be reachable on the loopback address...
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(inst.Port), 2*time.Second)
	if err != nil {
		t.Fatalf("dial 127.0.0.1:%d: %v", inst.Port, err)
	}
	_ = conn.Close()

	// ...and it must be bound to that address alone, not a wildcard
	// (":0"/"0.0.0.0:0") that also happens to answer on 127.0.0.1: a
	// wildcard bind on Linux accepts on every interface's IPv6 loopback too,
	// while a literal "127.0.0.1:0" bind does not, so a connection to the
	// same port over ::1 discriminates the two. (A same-port 0.0.0.0 rebind
	// cannot be used for this: Linux refuses it with EADDRINUSE whenever
	// 127.0.0.1 already holds the port, which would misreport a correct
	// loopback-only bind as a failure.)
	if v6Conn, err := net.DialTimeout("tcp", "[::1]:"+itoa(inst.Port), 200*time.Millisecond); err == nil {
		_ = v6Conn.Close()
		t.Fatalf("port %d also answers on [::1]; Launch must bind 127.0.0.1 only, not a wildcard", inst.Port)
	}
}

// TestLaunch_TokenPerLaunch proves each Launch mints its own random token
// rather than reusing one across instances: two launches must never produce
// the same token or the same port.
func TestLaunch_TokenPerLaunch(t *testing.T) {
	inst1, err := Launch(context.Background(), Options{Config: minimalLoopbackConfig(t)})
	if err != nil {
		t.Fatalf("Launch 1: %v", err)
	}
	t.Cleanup(func() { _ = inst1.Close(context.Background()) })

	inst2, err := Launch(context.Background(), Options{Config: minimalLoopbackConfig(t)})
	if err != nil {
		t.Fatalf("Launch 2: %v", err)
	}
	t.Cleanup(func() { _ = inst2.Close(context.Background()) })

	if inst1.Token == "" || inst2.Token == "" {
		t.Fatal("token must not be empty")
	}
	if inst1.Token == inst2.Token {
		t.Fatal("two launches minted the same token")
	}
	if len(inst1.Token) != 64 { // 32 bytes hex-encoded
		t.Fatalf("token length = %d, want 64 (32 bytes hex)", len(inst1.Token))
	}
	if inst1.Port == inst2.Port {
		t.Fatal("two launches bound the same ephemeral port")
	}
}

// TestLaunch_BearerTokenEnforced drives real HTTP traffic through the engine
// Launch boots: a request with no Authorization header, one with the wrong
// bearer token, and one with the exact per-launch token. The base
// authenticator is a JWT authenticator that never accepts any of the plain
// strings this test presents, so a 200 response can only come from the
// loopback token path Launch composes in front of it — proving the token is
// actually required and a wrong or missing one is refused.
func TestLaunch_BearerTokenEnforced(t *testing.T) {
	cfg := minimalLoopbackConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt"
	cfg.Auth.JWT = &config.JWTConfig{
		PublicKeyFile: generateJWTPublicKeyFile(t),
		Issuer:        "test-issuer",
		Audience:      []string{"test-audience"},
	}

	inst, err := Launch(context.Background(), Options{Config: cfg})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close(context.Background()) })

	url := inst.BaseURL + "/api/v1/backends"
	client := &http.Client{Timeout: 5 * time.Second}

	get := func(t *testing.T, authHeader string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		var resp *http.Response
		// The REST listener starts asynchronously in Launch; poll briefly for
		// it to come up instead of racing a fixed sleep against it.
		deadline := time.Now().Add(5 * time.Second)
		for {
			resp, err = client.Do(req)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("GET %s never became reachable: %v", url, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	if got := get(t, ""); got != http.StatusUnauthorized {
		t.Errorf("no Authorization header: status = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := get(t, "Bearer not-the-token"); got != http.StatusUnauthorized {
		t.Errorf("wrong bearer token: status = %d, want %d", got, http.StatusUnauthorized)
	}
	if got := get(t, "Bearer "+inst.Token); got == http.StatusUnauthorized {
		t.Errorf("correct per-launch bearer token: status = %d, must not be %d", got, http.StatusUnauthorized)
	}
}

// TestLaunch_TLSEnabled_UsesHTTPSScheme proves the scheme branch Launch
// computes from cfg.TLS.Enabled (loopback.go's "scheme := https / if
// !cfg.TLS.Enabled { scheme = http }"): with TLS enabled and a self-signed
// cert/key pair, BaseURL must report "https://" and the loopback listener
// must actually answer TLS, not plaintext HTTP, on the reported port. Every
// other Launch test in this file runs TLS disabled, so this is the one
// exercise of the https branch.
func TestLaunch_TLSEnabled_UsesHTTPSScheme(t *testing.T) {
	certPath, keyPath := generateSelfSignedTLSCert(t)
	cfg := minimalLoopbackConfig(t)
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certPath
	cfg.TLS.KeyFile = keyPath

	inst, err := Launch(context.Background(), Options{Config: cfg})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close(context.Background()) })

	if !strings.HasPrefix(inst.BaseURL, "https://127.0.0.1:") {
		t.Fatalf("BaseURL = %q, want https://127.0.0.1:<port>", inst.BaseURL)
	}

	// Trust exactly the loopback listener's own self-signed certificate,
	// which carries a 127.0.0.1 IP SAN, so the handshake is fully verified.
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read loopback cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("loopback cert PEM did not parse")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		},
	}
	url := inst.BaseURL + "/api/v1/backends"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+inst.Token)

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s never became reachable over TLS: %v", url, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.TLS == nil {
		t.Fatal("response carries no TLS connection state; loopback listener served plaintext")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("GET with the correct per-launch token = %d, want an authenticated response", resp.StatusCode)
	}

	// A plain HTTP client dialing the same port must not get the normal
	// authenticated response: the listener is wrapped in TLS, not left
	// plaintext alongside it. Go's net/http server detects a client
	// speaking HTTP over what it expects to be a TLS handshake and answers
	// with its own plaintext 400 rather than erroring the connection, so
	// the discriminator is the status code, not a dial/read failure.
	plainClient := &http.Client{Timeout: 2 * time.Second}
	plainURL := "http://127.0.0.1:" + itoa(inst.Port) + "/api/v1/backends"
	plainResp, plainErr := plainClient.Get(plainURL)
	if plainErr == nil {
		defer func() { _ = plainResp.Body.Close() }()
		if plainResp.StatusCode == http.StatusOK {
			t.Fatalf("plaintext GET %s succeeded with 200; want the TLS-wrapped listener to refuse a non-TLS request", plainURL)
		}
	}
}

// TestLaunch_ConstructEngineError proves a configuration that fails server
// construction (an auth.type requiring configuration Launch's caller did not
// supply) surfaces as a *LaunchError wrapping the underlying cause, rather
// than a bare or swallowed error.
func TestLaunch_ConstructEngineError(t *testing.T) {
	cfg := minimalLoopbackConfig(t)
	cfg.Auth.Enabled = true
	cfg.Auth.Type = "jwt" // no cfg.Auth.JWT: server.New must fail closed

	_, err := Launch(context.Background(), Options{Config: cfg})
	if err == nil {
		t.Fatal("expected error when auth.type=jwt has no jwt config")
	}
	var le *LaunchError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LaunchError, got %T", err)
	}
	if le.Reason != "construct engine" {
		t.Errorf("Reason = %q, want %q", le.Reason, "construct engine")
	}
	if le.Err == nil {
		t.Fatal("expected the underlying construction error to be preserved, got nil")
	}
}

// TestInstance_Close_StopsTheListener proves Close actually tears the engine
// down: after Close returns, the port Launch reported is free again instead
// of the listener leaking for the life of the process.
func TestInstance_Close_StopsTheListener(t *testing.T) {
	inst, err := Launch(context.Background(), Options{Config: minimalLoopbackConfig(t)})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	port := inst.Port

	if err := inst.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The port must be free within a bounded window; Shutdown drains
	// asynchronously so a single immediate dial would be flaky both ways.
	deadline := time.Now().Add(5 * time.Second)
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:"+itoa(port))
		if err == nil {
			_ = ln.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %d still bound after Close: %v", port, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestInstance_Close_NilServer proves Close on a zero-value Instance (never
// launched, e.g. a struct literal built by a caller for testing purposes) is
// a safe no-op rather than a nil-pointer panic.
func TestInstance_Close_NilServer(t *testing.T) {
	inst := &Instance{}
	if err := inst.Close(context.Background()); err != nil {
		t.Fatalf("Close on zero-value Instance: %v", err)
	}
}

// TestLaunchError_WrapsUnderlyingCause proves LaunchError participates
// correctly in the standard error chain: every caller in this codebase that
// inspects a returned error reaches for errors.Is/errors.As, so a wrapped
// cause that Unwrap does not expose would make LaunchError invisible to
// those checks even though the message looks wrapped. It also pins that
// Error's message carries both the reason and the cause, since the shell
// embedding this engine has no other surface to report a launch failure to
// than this string.
func TestLaunchError_WrapsUnderlyingCause(t *testing.T) {
	sentinel := errors.New("bind: address already in use")
	le := &LaunchError{Reason: "bind loopback listener", Err: sentinel}

	if !errors.Is(le, sentinel) {
		t.Fatal("errors.Is must see through LaunchError to the wrapped cause")
	}
	if got := errors.Unwrap(le); got != sentinel {
		t.Fatalf("Unwrap() = %v, want the wrapped sentinel", got)
	}
	msg := le.Error()
	if !strings.Contains(msg, "bind loopback listener") || !strings.Contains(msg, sentinel.Error()) {
		t.Fatalf("Error() = %q, want it to contain both the reason and the cause", msg)
	}

	// A LaunchError with no wrapped cause (e.g. the "config is required"
	// case) must still produce a message and answer Unwrap with nil rather
	// than panicking on a nil e.Err.
	bare := &LaunchError{Reason: "config is required"}
	if errors.Unwrap(bare) != nil {
		t.Fatal("Unwrap() of a LaunchError with no cause must be nil")
	}
	if bare.Error() != "loopback: config is required" {
		t.Fatalf("Error() = %q, want %q", bare.Error(), "loopback: config is required")
	}
}

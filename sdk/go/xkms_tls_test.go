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
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// tlsHandshakeRecordType is the TLS record content type for a handshake
// record. Every TLS connection opens with one (a ClientHello), so observing
// this byte first on the wire proves the client attempted a TLS handshake
// rather than sending application data in the clear.
const tlsHandshakeRecordType = byte(0x16)

// firstByteServer is a TCP listener that records the first byte of every
// connection it accepts. It never replies, so clients fail fast; the test
// only cares about what the client put on the wire.
type firstByteServer struct {
	addr string
	seen chan byte
}

// newFirstByteServer starts a first-byte recording listener bound to a
// loopback ephemeral port. The listener is closed when the test ends.
func newFirstByteServer(t *testing.T) *firstByteServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Logf("close listener: %v", closeErr)
		}
	})

	srv := &firstByteServer{
		addr: listener.Addr().String(),
		seen: make(chan byte, 16),
	}

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1)
				if _, readErr := io.ReadFull(c, buf); readErr != nil {
					return
				}
				select {
				case srv.seen <- buf[0]:
				default:
				}
			}(conn)
		}
	}()

	return srv
}

// firstByte waits for a client to send its first byte and returns it.
func (s *firstByteServer) firstByte(t *testing.T) byte {
	t.Helper()
	select {
	case b := <-s.seen:
		return b
	case <-time.After(20 * time.Second):
		t.Fatal("no client bytes observed on the wire")
		return 0
	}
}

// TestNew_TLSEnabledNegotiatesTLS is the security regression test for the
// silent-plaintext defect: a BackendConfig with TLSEnabled set and no custom
// trust material must still open a TLS handshake on the wire. Before the fix
// the SDK dropped TLSEnabled on the floor and dialed in cleartext.
func TestNew_TLSEnabledNegotiatesTLS(t *testing.T) {
	protocols := []struct {
		name     string
		protocol Protocol
	}{
		{name: "rest", protocol: ProtocolREST},
		{name: "grpc", protocol: ProtocolGRPC},
		{name: "mcp", protocol: ProtocolMCP},
	}

	for _, tc := range protocols {
		t.Run(tc.name+"_enabled", func(t *testing.T) {
			srv := newFirstByteServer(t)

			client, err := New(&BackendConfig{
				Protocol:   tc.protocol,
				Address:    srv.addr,
				TLSEnabled: true,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			// The server never completes the handshake, so Connect fails; the
			// assertion is about the bytes that reached the server.
			_ = client.Connect(ctx)
			_ = client.Close()

			if got := srv.firstByte(t); got != tlsHandshakeRecordType {
				t.Fatalf("TLSEnabled client sent plaintext: first wire byte 0x%02x, want TLS handshake 0x%02x", got, tlsHandshakeRecordType)
			}
		})

		t.Run(tc.name+"_disabled", func(t *testing.T) {
			srv := newFirstByteServer(t)

			client, err := New(&BackendConfig{
				Protocol: tc.protocol,
				Address:  srv.addr,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = client.Connect(ctx)
			_ = client.Close()

			if got := srv.firstByte(t); got == tlsHandshakeRecordType {
				t.Fatal("plaintext client unexpectedly opened a TLS handshake")
			}
		})
	}
}

// selfSignedTLSServer starts an HTTPS test server whose certificate is signed
// by a throw-away root. It returns the server, the on-disk PEM path of that
// root, and a flag that reports whether a request ever arrived over a
// completed TLS handshake.
func selfSignedTLSServer(t *testing.T) (*httptest.Server, string, *atomic.Bool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkms-sdk-tls-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build keypair: %v", err)
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}

	handshakeSeen := &atomic.Bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.TLS.HandshakeComplete {
			handshakeSeen.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, writeErr := w.Write([]byte(`{"status":"ok","version":"test"}`)); writeErr != nil {
			t.Errorf("write health response: %v", writeErr)
		}
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv, caPath, handshakeSeen
}

// TestNew_TLSCAFileCompletesHandshake proves the private-CA path performs a
// full, verified TLS handshake end to end.
func TestNew_TLSCAFileCompletesHandshake(t *testing.T) {
	srv, caPath, handshakeSeen := selfSignedTLSServer(t)

	client, err := New(&BackendConfig{
		Protocol:   ProtocolREST,
		Address:    strings.TrimPrefix(srv.URL, "https://"),
		TLSEnabled: true,
		TLSCAFile:  caPath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = client.Connect(ctx); err != nil {
		t.Fatalf("Connect over TLS failed: %v", err)
	}

	if !handshakeSeen.Load() {
		t.Fatal("server never observed a completed TLS handshake")
	}
}

// TestNew_TLSEnabledVerifiesAgainstSystemRoots proves the bare-enabled path
// verifies the peer against the system trust store instead of downgrading:
// an untrusted server certificate must be rejected, not silently accepted or
// bypassed by a plaintext retry.
func TestNew_TLSEnabledVerifiesAgainstSystemRoots(t *testing.T) {
	srv, _, handshakeSeen := selfSignedTLSServer(t)

	client, err := New(&BackendConfig{
		Protocol:   ProtocolREST,
		Address:    strings.TrimPrefix(srv.URL, "https://"),
		TLSEnabled: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = client.Connect(ctx); err == nil {
		t.Fatal("Connect succeeded against a server whose certificate is not in the system trust store")
	}

	if handshakeSeen.Load() {
		t.Fatal("request reached the server handler despite an untrusted certificate")
	}
}

// applyBackendConfig resolves a BackendConfig into the transport config the
// SDK would hand to a transport implementation.
func applyBackendConfig(t *testing.T, cfg *BackendConfig) *transport.Config {
	t.Helper()

	opts, err := optsFromConfig(cfg, "127.0.0.1:9443")
	if err != nil {
		t.Fatalf("optsFromConfig: %v", err)
	}

	resolved := transport.DefaultConfig()
	if err = transport.ApplyOptions(resolved, opts...); err != nil {
		t.Fatalf("ApplyOptions: %v", err)
	}
	return resolved
}

// TestOptsFromConfig_TLSPrecedence pins the precedence order of the TLS
// options so a more specific credential is never displaced by the bare
// TLSEnabled flag.
func TestOptsFromConfig_TLSPrecedence(t *testing.T) {
	custom := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "custom"}

	t.Run("tls_config_wins", func(t *testing.T) {
		resolved := applyBackendConfig(t, &BackendConfig{
			TLSEnabled:  true,
			TLSConfig:   custom,
			TLSCAFile:   "/path/to/ca.pem",
			TLSCertFile: "/path/to/cert.pem",
			TLSKeyFile:  "/path/to/key.pem",
		})
		if resolved.TLSConfig != custom {
			t.Fatalf("expected caller TLS config to win, got %v", resolved.TLSConfig)
		}
		if !resolved.TLSEnabled {
			t.Fatal("expected TLS to be enabled")
		}
		if resolved.TLSCAFile != "" || resolved.TLSCertFile != "" {
			t.Fatal("file-based material must not override a caller-built TLS config")
		}
	})

	t.Run("mtls_wins_over_bare_enabled", func(t *testing.T) {
		resolved := applyBackendConfig(t, &BackendConfig{
			TLSEnabled:  true,
			TLSCertFile: "/path/to/cert.pem",
			TLSKeyFile:  "/path/to/key.pem",
			TLSCAFile:   "/path/to/ca.pem",
		})
		if !resolved.TLSEnabled {
			t.Fatal("expected TLS to be enabled")
		}
		if resolved.TLSCertFile != "/path/to/cert.pem" || resolved.TLSKeyFile != "/path/to/key.pem" {
			t.Fatalf("mTLS material lost: %+v", resolved)
		}
		if resolved.TLSCAFile != "/path/to/ca.pem" {
			t.Fatalf("CA bundle lost: %q", resolved.TLSCAFile)
		}
	})

	t.Run("ca_file_wins_over_bare_enabled", func(t *testing.T) {
		resolved := applyBackendConfig(t, &BackendConfig{
			TLSEnabled: true,
			TLSCAFile:  "/path/to/ca.pem",
		})
		if !resolved.TLSEnabled {
			t.Fatal("expected TLS to be enabled")
		}
		if resolved.TLSCAFile != "/path/to/ca.pem" {
			t.Fatalf("CA bundle lost: %q", resolved.TLSCAFile)
		}
		if resolved.TLSConfig != nil {
			t.Fatal("CA path must not fabricate a TLS config")
		}
	})

	t.Run("bare_enabled_uses_system_roots", func(t *testing.T) {
		resolved := applyBackendConfig(t, &BackendConfig{TLSEnabled: true})
		if !resolved.TLSEnabled {
			t.Fatal("TLSEnabled was dropped")
		}
		if resolved.TLSConfig != nil || resolved.TLSCAFile != "" || resolved.TLSCertFile != "" || resolved.TLSKeyFile != "" {
			t.Fatalf("bare TLS must carry no trust material (system roots): %+v", resolved)
		}
	})

	t.Run("plaintext_stays_plaintext", func(t *testing.T) {
		resolved := applyBackendConfig(t, &BackendConfig{})
		if resolved.TLSEnabled {
			t.Fatal("TLS enabled without being requested")
		}
	})
}

// TestNew_IncompleteTLSMaterialFailsClosed verifies that half-configured
// client-certificate material is rejected instead of quietly producing a
// client without the credential.
func TestNew_IncompleteTLSMaterialFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		cfg     *BackendConfig
		missing string
	}{
		{
			name:    "cert_without_key",
			cfg:     &BackendConfig{Protocol: ProtocolGRPC, Address: "127.0.0.1:9443", TLSEnabled: true, TLSCertFile: "/path/to/cert.pem"},
			missing: "TLSKeyFile",
		},
		{
			name:    "key_without_cert",
			cfg:     &BackendConfig{Protocol: ProtocolGRPC, Address: "127.0.0.1:9443", TLSEnabled: true, TLSKeyFile: "/path/to/key.pem"},
			missing: "TLSCertFile",
		},
		{
			name:    "cert_without_key_with_ca",
			cfg:     &BackendConfig{Protocol: ProtocolREST, Address: "127.0.0.1:8443", TLSCertFile: "/path/to/cert.pem", TLSCAFile: "/path/to/ca.pem"},
			missing: "TLSKeyFile",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New(tc.cfg)
			if err == nil {
				_ = client.Close()
				t.Fatal("expected incomplete TLS material to fail closed")
			}
			if client != nil {
				t.Fatalf("expected nil client on failure, got %T", client)
			}
			if !errors.Is(err, ErrIncompleteTLSMaterial) {
				t.Fatalf("expected ErrIncompleteTLSMaterial, got %v", err)
			}
			var typed *IncompleteTLSMaterialError
			if !errors.As(err, &typed) {
				t.Fatalf("expected *IncompleteTLSMaterialError, got %T", err)
			}
			if typed.Missing != tc.missing {
				t.Fatalf("expected missing field %q, got %q", tc.missing, typed.Missing)
			}
		})
	}
}

// TestConfigFromURL_SchemeImpliedTLS pins which URL schemes imply TLS.
func TestConfigFromURL_SchemeImpliedTLS(t *testing.T) {
	cases := []struct {
		rawURL     string
		protocol   Protocol
		tlsEnabled bool
	}{
		{rawURL: "https://localhost:8443", protocol: ProtocolREST, tlsEnabled: true},
		{rawURL: "grpcs://localhost:9443", protocol: ProtocolGRPC, tlsEnabled: true},
		{rawURL: "mcps://localhost:9444", protocol: ProtocolMCP, tlsEnabled: true},
		{rawURL: "quic://localhost:9445", protocol: ProtocolQUIC, tlsEnabled: true},
		{rawURL: "http://localhost:8443", protocol: ProtocolREST, tlsEnabled: false},
		{rawURL: "grpc://localhost:9443", protocol: ProtocolGRPC, tlsEnabled: false},
		{rawURL: "mcp://localhost:9444", protocol: ProtocolMCP, tlsEnabled: false},
		{rawURL: "unix:///var/run/xkms.sock", protocol: ProtocolUnix, tlsEnabled: true},
		{rawURL: "localhost:8443", protocol: ProtocolREST, tlsEnabled: false},
	}

	for _, tc := range cases {
		t.Run(tc.rawURL, func(t *testing.T) {
			cfg, err := configFromURL(tc.rawURL)
			if err != nil {
				t.Fatalf("configFromURL: %v", err)
			}
			if cfg.Protocol != tc.protocol {
				t.Fatalf("expected protocol %q, got %q", tc.protocol, cfg.Protocol)
			}
			if cfg.TLSEnabled != tc.tlsEnabled {
				t.Fatalf("expected TLSEnabled %v, got %v", tc.tlsEnabled, cfg.TLSEnabled)
			}
		})
	}
}

// TestConfigFromURL_UnsupportedScheme keeps the unsupported-scheme path typed.
func TestConfigFromURL_UnsupportedScheme(t *testing.T) {
	cfg, err := configFromURL("ftp://localhost:21")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if cfg != nil {
		t.Fatal("expected nil config for unsupported scheme")
	}
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("expected ErrUnsupportedProtocol, got %v", err)
	}
}

// TestNewFromURL_TLSSchemesNegotiateTLS proves the TLS-implying schemes put a
// TLS handshake on the wire without any CA bundle being supplied.
func TestNewFromURL_TLSSchemesNegotiateTLS(t *testing.T) {
	cases := []struct {
		scheme  string
		wantTLS bool
	}{
		{scheme: "https://", wantTLS: true},
		{scheme: "grpcs://", wantTLS: true},
		{scheme: "mcps://", wantTLS: true},
		{scheme: "http://", wantTLS: false},
		{scheme: "grpc://", wantTLS: false},
		{scheme: "mcp://", wantTLS: false},
	}

	for _, tc := range cases {
		t.Run(tc.scheme, func(t *testing.T) {
			srv := newFirstByteServer(t)

			client, err := NewFromURL(tc.scheme + srv.addr)
			if err != nil {
				t.Fatalf("NewFromURL: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = client.Connect(ctx)
			_ = client.Close()

			got := srv.firstByte(t)
			if tc.wantTLS && got != tlsHandshakeRecordType {
				t.Fatalf("%s dialed in cleartext: first wire byte 0x%02x", tc.scheme, got)
			}
			if !tc.wantTLS && got == tlsHandshakeRecordType {
				t.Fatalf("%s unexpectedly opened a TLS handshake", tc.scheme)
			}
		})
	}
}

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

package main

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestConfig_backendConfig_MapsCredentialFlags(t *testing.T) {
	cfg := NewConfig()
	cfg.TLSCert = "/etc/xkms/client.pem"
	cfg.TLSKey = "/etc/xkms/client-key.pem"
	cfg.TLSCACert = "/etc/xkms/ca.pem"
	cfg.JWTToken = "session-token"
	cfg.SPKIPin = strings.Repeat("ab", 32)

	bc, err := cfg.backendConfig()
	if err != nil {
		t.Fatalf("backendConfig() error = %v", err)
	}
	if bc.TLSCertFile != cfg.TLSCert || bc.TLSKeyFile != cfg.TLSKey || bc.TLSCAFile != cfg.TLSCACert {
		t.Errorf("backendConfig() TLS files = %q/%q/%q, want the flag values", bc.TLSCertFile, bc.TLSKeyFile, bc.TLSCAFile)
	}
	// --spki-pin must reach the SDK, or a server whose certificate does not
	// chain to --tls-ca is unreachable from every protocol (#794).
	if bc.SPKIPin != cfg.SPKIPin {
		t.Errorf("backendConfig() SPKIPin = %q, want %q", bc.SPKIPin, cfg.SPKIPin)
	}
	if bc.JWTToken != cfg.JWTToken {
		t.Errorf("backendConfig() JWTToken = %q, want %q", bc.JWTToken, cfg.JWTToken)
	}
	if bc.TLSConfig != nil || bc.TLSEnabled {
		t.Error("backendConfig() must leave TLS to the caller when no PKCS#11 module is set")
	}
}

func TestConfig_backendConfig_PKCS11ModuleError(t *testing.T) {
	cfg := NewConfig()
	cfg.PKCS11Module = "/nonexistent/pkcs11.so"

	_, err := cfg.backendConfig()
	if !errors.Is(err, ErrCreatePKCS11TLSConfigFailed) {
		t.Fatalf("backendConfig() error = %v, want ErrCreatePKCS11TLSConfigFailed", err)
	}
}

// TestConfig_CreateClient_UnixURLSpeaksTLS proves a unix:// server dials
// xkmsd's socket -- the qrdb node's TLS listener -- with TLS even when no
// credential flag is set: the handshake against an untrusted server
// certificate fails on verification, and with the CA trusted it completes.
func TestConfig_CreateClient_UnixURLSpeaksTLS(t *testing.T) {
	socketPath, caFile := startTLSUnixServer(t)

	// Each subtest owns its deadline: a refused handshake can spend its
	// whole budget, and a shared one would leave the next subtest none.
	t.Run("untrusted certificate is refused", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		cfg := NewConfig()
		cfg.Server = "unix://" + socketPath

		cl, err := cfg.CreateClient()
		if err != nil {
			t.Fatalf("CreateClient() error = %v", err)
		}
		defer func() { _ = cl.Close() }()

		err = cl.Connect(ctx)
		if err == nil || !errorMentionsCertificate(err) {
			t.Fatalf("Connect() error = %v, want a certificate verification failure", err)
		}
	})

	t.Run("trusted CA completes the handshake", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		cfg := NewConfig()
		cfg.Server = "unix://" + socketPath
		cfg.TLSCACert = caFile

		cl, err := cfg.CreateClient()
		if err != nil {
			t.Fatalf("CreateClient() error = %v", err)
		}
		defer func() { _ = cl.Close() }()

		// The test server registers no service: an "unknown service"
		// answer means the TLS handshake succeeded.
		err = cl.Connect(ctx)
		if err == nil || !strings.Contains(err.Error(), "unknown service") {
			t.Fatalf("Connect() error = %v, want unknown service after a completed handshake", err)
		}
	})
}

func errorMentionsCertificate(err error) bool {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "certificate") || strings.Contains(msg, "x509")
}

// startTLSUnixServer serves gRPC over TLS on a Unix socket with a
// self-signed certificate naming localhost (the authority gRPC uses for a
// unix target) and returns the socket path and the certificate's PEM file.
// opts are added to the server's options.
func startTLSUnixServer(t *testing.T, opts ...grpc.ServerOption) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	socketPath := filepath.Join(dir, "xkms.sock")
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	srv := grpc.NewServer(append([]grpc.ServerOption{grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}))}, opts...)...)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return socketPath, caFile
}

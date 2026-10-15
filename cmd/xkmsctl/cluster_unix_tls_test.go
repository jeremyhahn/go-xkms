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
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	qrdbunix "github.com/jeremyhahn/go-qrdb/sdk/go/transport/unix"
)

// TestNewQRDBControlTransport_UnixSpeaksTLS proves the cluster verbs reach
// xkmsd's socket -- the qrdb node's TLS listener -- over TLS: an untrusted
// server certificate fails verification, and with --tls-ca the handshake
// completes.
func TestNewQRDBControlTransport_UnixSpeaksTLS(t *testing.T) {
	socketPath, caFile := startTLSUnixServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("untrusted certificate is refused", func(t *testing.T) {
		tr, err := newQRDBControlTransport(&Config{Server: "unix://" + socketPath})
		if err != nil {
			t.Fatalf("newQRDBControlTransport() error = %v", err)
		}
		defer func() { _ = tr.Close() }()

		_, err = probeHealth(ctx, t, tr)
		if err == nil || !errorMentionsCertificate(err) {
			t.Fatalf("Health() error = %v, want a certificate verification failure", err)
		}
	})

	t.Run("trusted CA completes the handshake", func(t *testing.T) {
		tr, err := newQRDBControlTransport(&Config{Server: "unix://" + socketPath, TLSCACert: caFile})
		if err != nil {
			t.Fatalf("newQRDBControlTransport() error = %v", err)
		}
		defer func() { _ = tr.Close() }()

		// The test server registers no service: an "unknown service"
		// answer means the TLS handshake succeeded.
		_, err = probeHealth(ctx, t, tr)
		if err == nil || !strings.Contains(err.Error(), "unknown service") {
			t.Fatalf("Health() error = %v, want unknown service after a completed handshake", err)
		}
	})
}

// probeHealth connects tr -- which must fail against the test server, as it
// serves no health service -- and returns the Health RPC's own error, which
// Connect reduces to "health check failed".
func probeHealth(ctx context.Context, t *testing.T, tr qrdbtransport.Transport) (*qrdbtransport.HealthResponse, error) {
	t.Helper()
	unixTr, ok := tr.(*qrdbunix.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *unix.Transport", tr)
	}
	if err := unixTr.Connect(ctx); err == nil {
		t.Fatal("Connect() succeeded against a server without a health service")
	}
	return unixTr.Health(ctx)
}

// TestNewQRDBControlUnixTransport_ClientCertLoadError verifies an unloadable
// --tls-cert/--tls-key pair is the typed error rather than a silent
// anonymous connection.
func TestNewQRDBControlUnixTransport_ClientCertLoadError(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		TLSCert: filepath.Join(dir, "missing-cert.pem"),
		TLSKey:  filepath.Join(dir, "missing-key.pem"),
	}

	_, err := newQRDBControlUnixTransport(cfg, filepath.Join(dir, "xkms.sock"))
	var certErr *QRDBControlClientCertError
	if !errors.As(err, &certErr) {
		t.Fatalf("newQRDBControlUnixTransport() error = %v, want *QRDBControlClientCertError", err)
	}
	if certErr.Unwrap() == nil {
		t.Error("QRDBControlClientCertError must carry the load failure")
	}
}

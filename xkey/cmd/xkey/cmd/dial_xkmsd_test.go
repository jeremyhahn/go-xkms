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

package cmd

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDialXKMSd_Success dials a real, in-process xkmsd unix-socket gRPC
// server over TLS (the same harness ca/cert tests use) with the client
// certificate it admits, proving dialXKMSd's "unix" protocol path actually
// connects rather than only being exercised through a stub.
func TestDialXKMSd_Success(t *testing.T) {
	address, _ := startTestXKMSd(t)

	client, err := dialXKMSd(testBridgeConfig(address), discardLogger())
	require.NoError(t, err)
	require.NotNil(t, client)
	defer func() { _ = client.Close() }()
}

// TestDialXKMSd_NoClientCertificateRefused proves xkmsd's TLS socket refuses
// a caller that presents no client certificate.
func TestDialXKMSd_NoClientCertificateRefused(t *testing.T) {
	address, _ := startTestXKMSd(t)
	cfg := testBridgeConfig(address)
	cfg.TLSCertFile = ""
	cfg.TLSKeyFile = ""

	_, err := dialXKMSd(cfg, discardLogger())
	require.ErrorIs(t, err, ErrXKMSdConnectionFailed)
}

// TestDialXKMSd_UnreadableClientCertificate proves a client certificate
// that cannot be loaded fails before any dial, with the typed cause.
func TestDialXKMSd_UnreadableClientCertificate(t *testing.T) {
	cfg := &XKMSdBridgeConfig{
		Protocol:    "unix",
		Address:     t.TempDir() + "/xkmsd.sock",
		TLSCertFile: t.TempDir() + "/absent-cert.pem",
		TLSKeyFile:  t.TempDir() + "/absent-key.pem",
	}

	_, err := dialXKMSd(cfg, discardLogger())
	require.ErrorIs(t, err, ErrXKMSdConnectionFailed)
	require.ErrorIs(t, err, ErrXKMSdTLSConfigFailed)
}

// testBridgeConfig returns a bridge configuration for the harness server at
// address, carrying the TLS material startTestXKMSd published.
func testBridgeConfig(address string) *XKMSdBridgeConfig {
	return &XKMSdBridgeConfig{
		Protocol:       "unix",
		Address:        strings.TrimPrefix(address, "unix://"),
		ConnectTimeout: 5 * time.Second,
		TLSCAFile:      os.Getenv(envXKMSdTLSCA),
		TLSCertFile:    os.Getenv(envXKMSdTLSCert),
		TLSKeyFile:     os.Getenv(envXKMSdTLSKey),
	}
}

// TestDialXKMSd_NoServer proves the connection-failure path wraps
// ErrXKMSdConnectionFailed when nothing is listening on the socket.
func TestDialXKMSd_NoServer(t *testing.T) {
	_, cleanup := startTestXKMSd(t)
	cleanup()

	cfg := &XKMSdBridgeConfig{
		Protocol:       "unix",
		Address:        t.TempDir() + "/no-such.sock",
		ConnectTimeout: 2 * time.Second,
	}

	_, err := dialXKMSd(cfg, discardLogger())
	require.ErrorIs(t, err, ErrXKMSdConnectionFailed)
}

// TestDialXKMSd_UnsupportedProtocol proves the protocol dispatch itself is
// covered end to end, not only createXKMSdClient in isolation.
func TestDialXKMSd_UnsupportedProtocol(t *testing.T) {
	cfg := &XKMSdBridgeConfig{Protocol: "websocket", Address: "ws://localhost"}

	_, err := dialXKMSd(cfg, discardLogger())
	require.ErrorIs(t, err, ErrXKMSdConnectionFailed)
	require.ErrorIs(t, err, ErrXKMSdUnsupportedProtocol)
}

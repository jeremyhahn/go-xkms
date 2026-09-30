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

package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// freePort returns a TCP port that is currently available on the loopback
// interface. There is an unavoidable, and here harmless, gap between the
// probe closing its listener and the caller binding the same port: this
// package's tests only need a port a concurrent test is not also using.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	return port
}

// discardLogger returns a *slog.Logger that writes nowhere, for tests that
// need a non-nil logger but do not assert on log output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestNewChallengeServer_BindsAndReleasesPortOnShutdown verifies that
// newChallengeServer binds the requested port synchronously (the caller
// gets no error back), and that shutdown frees the port immediately: a
// second listener can bind the same address the instant shutdown returns,
// with no sleep or retry loop required.
func TestNewChallengeServer_BindsAndReleasesPortOnShutdown(t *testing.T) {
	port := freePort(t)
	addr := net.JoinHostPort("", port)

	cs, err := newChallengeServer(addr, http.NewServeMux(), discardLogger(), "test")
	require.NoError(t, err)
	require.NotNil(t, cs)

	// The port is bound: a second listener on the same address must fail.
	_, err = net.Listen("tcp", addr)
	require.Error(t, err, "port must be bound while the challenge server is running")

	cs.shutdown()

	// shutdown blocks until the listener is closed, so the port is free
	// again the instant it returns -- no sleep needed.
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err, "port must be free immediately after shutdown returns")
	_ = ln.Close()
}

// TestNewChallengeServer_PortInUse_ReturnsTypedErrorPromptly verifies that
// binding a port another listener already holds fails fast with a typed
// error identifying the cause, instead of starting a background goroutine
// whose bind failure is only ever logged (go-xkms#1125): the caller of
// EnrollDevice or DeviceAttest needs that error to return it to its own
// caller, not an opaque timeout several RTTs later.
func TestNewChallengeServer_PortInUse_ReturnsTypedErrorPromptly(t *testing.T) {
	port := freePort(t)
	addr := net.JoinHostPort("", port)

	occupied, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()

	start := time.Now()
	cs, err := newChallengeServer(addr, http.NewServeMux(), discardLogger(), "enroll-01")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, cs)
	assert.Less(t, elapsed, time.Second, "a bind conflict must fail immediately, not after a retry or timeout loop")

	var caErr *caerrors.TrustedCAError
	require.True(t, errors.As(err, &caErr), "bind failure must be a typed *caerrors.TrustedCAError, got %T", err)
	assert.Contains(t, err.Error(), "enroll-01")
	assert.Contains(t, err.Error(), addr)
}

// TestChallengeServer_Shutdown_NilAndDoubleSafe verifies shutdown is safe to
// call on a nil *challengeServer (so a caller can defer it unconditionally
// even when newChallengeServer failed) and safe to call more than once.
func TestChallengeServer_Shutdown_NilAndDoubleSafe(t *testing.T) {
	var nilServer *challengeServer
	assert.NotPanics(t, func() { nilServer.shutdown() })

	port := freePort(t)
	cs, err := newChallengeServer(net.JoinHostPort("", port), http.NewServeMux(), discardLogger(), "test")
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		cs.shutdown()
		cs.shutdown()
	})
}

func newTestClientForMockACMEServer(t *testing.T, server *mockACMEServer) *Client {
	t.Helper()

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serverCert := server.Certificate()
	require.NotNil(t, serverCert)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})

	client, err := NewClient(&Params{
		AccountEmail:  "test@example.com",
		AccountSigner: accountKey,
		Config: &Config{
			DirectoryURL:   server.URL + "/directory",
			SystemCertPool: false,
			TrustedRoots:   []string{string(certPEM)},
			Timeout:        10 * time.Second,
		},
		Storage:            newMockStorage(),
		CertificateStorage: newMockCertStorage(),
		OrderStorage:       newMockOrderStorage(),
	})
	require.NoError(t, err)
	return client
}

// TestEnrollDevice_ReleasesPortOnSuccess drives EnrollDevice through a
// complete enroll-01 round trip against mockACMEServer and asserts that the
// configured challenge port is free again immediately after EnrollDevice
// returns: before the fix, the enroll-01 HTTP server begun in EnrollDevice
// was never shut down on any return path (go-xkms#1125), so the port
// remained bound for the life of the process and a second enrollment on the
// same client -- or, as here, a probe listener -- found it still held.
func TestEnrollDevice_ReleasesPortOnSuccess(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	// A second certificate so the finalized chain carries both the IAK and
	// IDevID certificates EnrollDevice requires (len(certChain) >= 2).
	certDER2, _ := generateTestCert(t)
	server.certDER2 = certDER2

	client := newTestClientForMockACMEServer(t, server)

	port := freePort(t)
	config := &EnrollmentConfig{
		Challenge:  "enroll-01",
		TPMModule:  newMockTPMForEnrollment(t),
		IPAddress:  "192.168.1.1",
		CommonName: "test-device",
		Port:       port,
		Timeout:    10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.EnrollDevice(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, result.IAKCertificate)
	assert.NotNil(t, result.IDevIDCertificate)

	// The port must be free the instant EnrollDevice returns -- no sleep,
	// no retry loop.
	ln, err := net.Listen("tcp", net.JoinHostPort("", port))
	require.NoError(t, err, "enroll-01 challenge port must be free immediately after EnrollDevice succeeds")
	_ = ln.Close()
}

// TestEnrollDevice_InstallsIAKCertificate drives EnrollDevice through a
// complete enroll-01 round trip and asserts the issued IAK certificate is
// installed via TPMModule.ProvisionIAKCert -- go-xkms#1100: previously the
// certificate was parsed out of the finalized chain and returned to the
// caller, but never installed, so a later device-attest-01 challenge (run
// against the same TPM, commonly in a separate process) had no certificate
// to answer with even though enrollment had succeeded.
func TestEnrollDevice_InstallsIAKCertificate(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	certDER2, _ := generateTestCert(t)
	server.certDER2 = certDER2

	client := newTestClientForMockACMEServer(t, server)

	tpm := newMockTPMForEnrollment(t)
	config := &EnrollmentConfig{
		Challenge:  "enroll-01",
		TPMModule:  tpm,
		IPAddress:  "192.168.1.4",
		CommonName: "test-device",
		Port:       freePort(t),
		Timeout:    10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.EnrollDevice(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, tpm.provisionedIAKCert, "EnrollDevice must install the issued IAK certificate via ProvisionIAKCert")
	assert.True(t, result.IAKCertificate.Equal(tpm.provisionedIAKCert),
		"the certificate installed via ProvisionIAKCert must be the one EnrollDevice returned")
}

// TestEnrollDevice_ProvisionIAKCertFailure_ReturnsTypedError asserts that
// when installing the issued IAK certificate fails, EnrollDevice reports a
// typed error naming the cause instead of returning a certificate the
// device never actually has -- a later device-attest-01 challenge would
// otherwise fail confusingly with no certificate available, far from this
// actual root cause.
func TestEnrollDevice_ProvisionIAKCertFailure_ReturnsTypedError(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	certDER2, _ := generateTestCert(t)
	server.certDER2 = certDER2

	client := newTestClientForMockACMEServer(t, server)

	tpm := newMockTPMForEnrollment(t)
	wantErr := errors.New("simulated NVRAM write failure")
	tpm.errors["ProvisionIAKCert"] = wantErr

	config := &EnrollmentConfig{
		Challenge:  "enroll-01",
		TPMModule:  tpm,
		IPAddress:  "192.168.1.5",
		CommonName: "test-device",
		Port:       freePort(t),
		Timeout:    10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.EnrollDevice(ctx, config)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to install IAK certificate")
	assert.ErrorIs(t, err, wantErr)
}

// TestEnrollDevice_ReleasesPortOnMidFlightFailure exercises the same
// concern on an error path that happens after the enroll-01 challenge
// server has already been started: mockACMEServer's default single
// certificate makes EnrollDevice fail its "expected 2 certificates" check
// at finalization, well after the challenge server bound its port and
// served the accepted challenge. The port must still be free once
// EnrollDevice returns the error.
func TestEnrollDevice_ReleasesPortOnMidFlightFailure(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	client := newTestClientForMockACMEServer(t, server)

	port := freePort(t)
	config := &EnrollmentConfig{
		Challenge:  "enroll-01",
		TPMModule:  newMockTPMForEnrollment(t),
		IPAddress:  "192.168.1.2",
		CommonName: "test-device",
		Port:       port,
		Timeout:    10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := client.EnrollDevice(ctx, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 2 certificates")

	ln, err := net.Listen("tcp", net.JoinHostPort("", port))
	require.NoError(t, err, "enroll-01 challenge port must be free immediately after EnrollDevice fails")
	_ = ln.Close()
}

// TestEnrollDevice_ChallengeServerBindConflict_ReturnsTypedErrorPromptly
// occupies the configured enroll-01 challenge port before calling
// EnrollDevice, and asserts the bind conflict is reported as a typed error
// promptly -- before WaitAuthorization or WaitOrder ever run -- rather than
// as an opaque authorization timeout several seconds later.
func TestEnrollDevice_ChallengeServerBindConflict_ReturnsTypedErrorPromptly(t *testing.T) {
	server := newMockACMEServer(t)
	defer server.Close()

	client := newTestClientForMockACMEServer(t, server)

	port := freePort(t)
	occupied, err := net.Listen("tcp", net.JoinHostPort("", port))
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()

	config := &EnrollmentConfig{
		Challenge:  "enroll-01",
		TPMModule:  newMockTPMForEnrollment(t),
		IPAddress:  "192.168.1.3",
		CommonName: "test-device",
		Port:       port,
		Timeout:    10 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err = client.EnrollDevice(ctx, config)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start challenge server")
	assert.Less(t, elapsed, 2*time.Second, "a bind conflict must fail fast, not after an authorization wait")

	var caErr *caerrors.TrustedCAError
	require.True(t, errors.As(err, &caErr), "bind failure must surface as a typed *caerrors.TrustedCAError, got %T", err)
}

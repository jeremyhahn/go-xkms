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

package service

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// freePort returns a TCP port that is currently available.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	return port
}

// TestNewChallengeServer verifies that a ChallengeServer is constructed with
// the correct token, keyAuth, port, and logger fields.
func TestNewChallengeServer(t *testing.T) {
	logger := testLogger()
	cs := NewChallengeServer("8080", "test-token", "test-key-auth", logger)

	require.NotNil(t, cs)
	assert.Equal(t, "test-token", cs.token)
	assert.Equal(t, "test-key-auth", cs.keyAuth)
	assert.Equal(t, "8080", cs.port)
	assert.Equal(t, logger, cs.logger)
	assert.Nil(t, cs.server, "server must be nil before Start is called")
}

// TestNewChallengeServer_EmptyFields verifies construction with empty values.
func TestNewChallengeServer_EmptyFields(t *testing.T) {
	cs := NewChallengeServer("", "", "", testLogger())

	require.NotNil(t, cs)
	assert.Empty(t, cs.token)
	assert.Empty(t, cs.keyAuth)
	assert.Empty(t, cs.port)
}

// TestChallengeServer_StartAndShutdown verifies the server starts on a free
// port and shuts down cleanly.
func TestChallengeServer_StartAndShutdown(t *testing.T) {
	port := freePort(t)
	cs := NewChallengeServer(port, "tok", "keyauth", testLogger())

	err := cs.Start()
	require.NoError(t, err)
	require.NotNil(t, cs.server)

	// Shut down and verify idempotent shutdown
	cs.Shutdown()
	cs.Shutdown() // second call must be a no-op
}

// TestChallengeServer_Start_PortInUse verifies that Start returns an error
// when the port is already bound.
func TestChallengeServer_Start_PortInUse(t *testing.T) {
	port := freePort(t)

	// Occupy the port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	require.NoError(t, err)
	defer listener.Close()

	cs := NewChallengeServer(port, "tok", "ka", testLogger())
	err = cs.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to listen")
}

// TestChallengeServer_HandleChallenge_Success verifies that the server
// responds with the key authorization for a matching token request.
func TestChallengeServer_HandleChallenge_Success(t *testing.T) {
	port := freePort(t)
	token := "challenge-token-abc"
	keyAuth := "challenge-token-abc.thumbprint123"

	cs := NewChallengeServer(port, token, keyAuth, testLogger())
	require.NoError(t, cs.Start())
	defer cs.Shutdown()

	url := fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/%s", port, token)
	resp, err := http.Get(url) // nolint:gosec
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, keyAuth, string(body))
}

// TestChallengeServer_HandleChallenge_WrongToken verifies that requesting
// a non-matching token returns 404.
func TestChallengeServer_HandleChallenge_WrongToken(t *testing.T) {
	port := freePort(t)
	cs := NewChallengeServer(port, "expected-token", "ka", testLogger())
	require.NoError(t, cs.Start())
	defer cs.Shutdown()

	url := fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/wrong-token", port)
	resp, err := http.Get(url) // nolint:gosec
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestChallengeServer_ShutdownWithoutStart verifies that calling Shutdown
// on a server that was never started does not panic.
func TestChallengeServer_ShutdownWithoutStart(t *testing.T) {
	cs := NewChallengeServer("0", "tok", "ka", testLogger())
	// Must not panic
	cs.Shutdown()
}

// TestWriteHTTP01TokenFile_Success verifies that the token file is written
// to the correct path under the webroot.
func TestWriteHTTP01TokenFile_Success(t *testing.T) {
	webroot := t.TempDir()
	token := "test-token-xyz"
	keyAuth := "test-token-xyz.thumbprint"

	err := WriteHTTP01TokenFile(webroot, token, keyAuth, testLogger())
	require.NoError(t, err)

	tokenPath := filepath.Join(webroot, ".well-known", "acme-challenge", token)
	content, err := os.ReadFile(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, keyAuth, string(content))

	// Verify directory permissions
	info, err := os.Stat(filepath.Join(webroot, ".well-known", "acme-challenge"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// TestWriteHTTP01TokenFile_InvalidWebroot verifies that an error is returned
// when the webroot path is not writable.
func TestWriteHTTP01TokenFile_InvalidWebroot(t *testing.T) {
	err := WriteHTTP01TokenFile("/dev/null/impossible", "tok", "ka", testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create challenge directory")
}

// TestCleanupHTTP01TokenFile_Success verifies that the token file is removed.
func TestCleanupHTTP01TokenFile_Success(t *testing.T) {
	webroot := t.TempDir()
	token := "cleanup-token"

	// Create the token file first
	require.NoError(t, WriteHTTP01TokenFile(webroot, token, "ka", testLogger()))

	tokenPath := filepath.Join(webroot, ".well-known", "acme-challenge", token)
	_, err := os.Stat(tokenPath)
	require.NoError(t, err, "token file must exist before cleanup")

	CleanupHTTP01TokenFile(webroot, token, testLogger())

	_, err = os.Stat(tokenPath)
	assert.True(t, os.IsNotExist(err), "token file must be removed after cleanup")
}

// TestCleanupHTTP01TokenFile_EmptyWebroot verifies that cleanup with an empty
// webroot is a no-op and does not panic.
func TestCleanupHTTP01TokenFile_EmptyWebroot(t *testing.T) {
	CleanupHTTP01TokenFile("", "tok", testLogger())
}

// TestCleanupHTTP01TokenFile_NonExistentFile verifies cleanup of a file that
// does not exist completes without error.
func TestCleanupHTTP01TokenFile_NonExistentFile(t *testing.T) {
	webroot := t.TempDir()
	CleanupHTTP01TokenFile(webroot, "no-such-token", testLogger())
}

// TestComputeDNS01Response verifies the DNS-01 response computation matches
// RFC 8555 Section 8.4: base64url(SHA-256(keyAuthorization)).
func TestComputeDNS01Response(t *testing.T) {
	keyAuth := "token.thumbprint"
	hash := sha256.Sum256([]byte(keyAuth))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	result := ComputeDNS01Response(keyAuth)
	assert.Equal(t, expected, result)
}

// TestComputeDNS01Response_EmptyInput verifies the response for an empty
// key authorization string.
func TestComputeDNS01Response_EmptyInput(t *testing.T) {
	result := ComputeDNS01Response("")
	hash := sha256.Sum256([]byte(""))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	assert.Equal(t, expected, result)
}

// TestSetupHTTP01Challenge_ServerMode verifies that SetupHTTP01Challenge starts
// an HTTP server when no webroot is configured.
func TestSetupHTTP01Challenge_ServerMode(t *testing.T) {
	port := freePort(t)
	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				Port: port,
			},
		},
	}

	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	require.NoError(t, err)
	require.NotNil(t, server)
	defer server.Shutdown()
}

// TestSetupHTTP01Challenge_WebrootMode verifies that SetupHTTP01Challenge
// writes the token file when a webroot is configured.
func TestSetupHTTP01Challenge_WebrootMode(t *testing.T) {
	webroot := t.TempDir()
	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				WebRoot: webroot,
			},
		},
	}

	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	require.NoError(t, err)
	assert.Nil(t, server, "server must be nil in webroot mode")

	tokenPath := filepath.Join(webroot, ".well-known", "acme-challenge", "tok")
	content, err := os.ReadFile(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, "ka", string(content))
}

// TestSetupHTTP01Challenge_DefaultPort verifies that the default port 80 is
// used when no port is specified (expects failure since port 80 requires root).
func TestSetupHTTP01Challenge_DefaultPort(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{},
		},
	}

	// Port 80 typically requires root, so this should fail in non-root tests
	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	if err != nil {
		var setupErr ErrChallengeSetupFailed
		assert.ErrorAs(t, err, &setupErr)
		assert.Equal(t, "http-01", setupErr.ChallengeType)
	} else {
		require.NotNil(t, server)
		server.Shutdown()
	}
}

// TestSetupHTTP01Challenge_PortInUse verifies that SetupHTTP01Challenge returns
// an ErrChallengeSetupFailed when the port is occupied.
func TestSetupHTTP01Challenge_PortInUse(t *testing.T) {
	port := freePort(t)

	// Occupy the port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	require.NoError(t, err)
	defer listener.Close()

	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				Port: port,
			},
		},
	}

	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	require.Error(t, err)
	assert.Nil(t, server)

	var setupErr ErrChallengeSetupFailed
	assert.ErrorAs(t, err, &setupErr)
	assert.Equal(t, "http-01", setupErr.ChallengeType)
}

// TestSetupHTTP01Challenge_WebrootInvalidPath verifies that
// SetupHTTP01Challenge returns an error when the webroot path is invalid.
func TestSetupHTTP01Challenge_WebrootInvalidPath(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			HTTP01: HTTP01Config{
				WebRoot: "/dev/null/impossible",
			},
		},
	}

	server, err := SetupHTTP01Challenge(config, testLogger(), "tok", "ka")
	require.Error(t, err)
	assert.Nil(t, server)
}

// TestSetupDNS01Challenge verifies that SetupDNS01Challenge returns nil error
// and does not panic.
func TestSetupDNS01Challenge(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			DNS01: DNS01Config{
				TTL: 300,
			},
		},
	}

	err := SetupDNS01Challenge(config, testLogger(), "example.com", "tok", "ka")
	assert.NoError(t, err)
}

// TestSetupDNS01Challenge_WithProvider verifies the provider log path.
func TestSetupDNS01Challenge_WithProvider(t *testing.T) {
	config := &Config{
		Challenge: ChallengeConfig{
			DNS01: DNS01Config{
				TTL:      60,
				Provider: "cloudflare",
			},
		},
	}

	err := SetupDNS01Challenge(config, testLogger(), "example.com", "tok", "ka")
	assert.NoError(t, err)
}

// TestSetupDeviceAttest01Challenge verifies that SetupDeviceAttest01Challenge
// always returns ErrTPMModuleRequired.
func TestSetupDeviceAttest01Challenge(t *testing.T) {
	config := &Config{}
	_, err := SetupDeviceAttest01Challenge(config, testLogger(), "tok", "ka", []int{0, 1, 7})

	require.Error(t, err)
	var tpmErr ErrTPMModuleRequired
	assert.ErrorAs(t, err, &tpmErr)
}

// TestSetupDeviceAttest01Challenge_EmptyPCRs verifies error with empty PCR list.
func TestSetupDeviceAttest01Challenge_EmptyPCRs(t *testing.T) {
	config := &Config{}
	result, err := SetupDeviceAttest01Challenge(config, testLogger(), "tok", "ka", nil)

	assert.Nil(t, result)
	require.Error(t, err)
	var tpmErr ErrTPMModuleRequired
	assert.ErrorAs(t, err, &tpmErr)
}

// TestChallengeServer_ConcurrentRequests verifies the server handles
// concurrent requests correctly.
func TestChallengeServer_ConcurrentRequests(t *testing.T) {
	port := freePort(t)
	token := "concurrent-token"
	keyAuth := "concurrent-ka"

	cs := NewChallengeServer(port, token, keyAuth, testLogger())
	require.NoError(t, cs.Start())
	defer cs.Shutdown()

	// Allow server to fully start
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()

			url := fmt.Sprintf("http://127.0.0.1:%s/.well-known/acme-challenge/%s", port, token)
			resp, err := http.Get(url) // nolint:gosec
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, keyAuth, string(body))
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

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

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestBootCompletionFailure_OnlyTheBootStage pins that only the
// boot-completion stage after unseal keeps xkmsd up (#2290); every other
// New failure still exits.
func TestBootCompletionFailure_OnlyTheBootStage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "sealed window wrapping boot completion",
			err: &QRDBNodeError{Stage: "sealed window", Err: &QRDBNodeError{
				Stage: StageBootAfterSealedWindow, Err: io.ErrUnexpectedEOF}},
			want: true,
		},
		{
			name: "sealed window wrapping a plain error",
			err:  &QRDBNodeError{Stage: "sealed window", Err: errors.New("window canceled")},
		},
		{name: "bind refusal", err: &SealedWindowBindError{}},
		{name: "nil error", err: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nodeErr, ok := BootCompletionFailure(tc.err)
			assert.Equal(t, tc.want, ok)
			if tc.want {
				require.NotNil(t, nodeErr)
				assert.Equal(t, StageBootAfterSealedWindow, nodeErr.Stage)
				assert.ErrorIs(t, nodeErr, io.ErrUnexpectedEOF)
			} else {
				assert.Nil(t, nodeErr)
			}
		})
	}
}

// TestServeBootFailure_RefusesRemoteBind pins that the failed-boot listener
// takes the sealed window's bind rule.
func TestServeBootFailure_RefusesRemoteBind(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Host = "0.0.0.0"
	cfg.Barrier.SealedWindowAllowRemote = false
	err := ServeBootFailure(context.Background(), cfg,
		&QRDBNodeError{Stage: StageBootAfterSealedWindow, Err: io.ErrUnexpectedEOF}, slog.Default())
	var bindErr *SealedWindowBindError
	require.ErrorAs(t, err, &bindErr)
	assert.Equal(t, "0.0.0.0", bindErr.Host)
}

// bootFailureTestListener starts ServeBootFailure on a free loopback port with
// the test CA's server certificate and the given tls.client_auth, and returns
// the address, the CA file and a stop function that requires a nil return.
func bootFailureTestListener(t *testing.T, clientAuth string, bootErr *QRDBNodeError) (addr, caFile string, stop func()) {
	t.Helper()
	certFile, keyFile, caFile := createTestTLSFiles(t)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := probe.Addr().(*net.TCPAddr).Port
	require.NoError(t, probe.Close())

	cfg := &config.Config{}
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.RESTPort = port
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = certFile
	cfg.TLS.KeyFile = keyFile
	cfg.TLS.CAFile = caFile
	cfg.TLS.ClientAuth = clientAuth
	cfg.Datastore.Path = t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeBootFailure(ctx, cfg, bootErr, slog.Default()) }()

	addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	require.Eventually(t, func() bool {
		select {
		case err := <-done:
			done <- err
			return true
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond)
	select {
	case err := <-done:
		cancel()
		require.NoError(t, err, "ServeBootFailure returned before serving")
	default:
	}

	return addr, caFile, func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("ServeBootFailure did not return after cancel")
		}
	}
}

// bootFailureTestClient returns an HTTPS client trusting caFile, with no
// client certificate, capped at maxVersion when it is non-zero.
func bootFailureTestClient(t *testing.T, caFile string, maxVersion uint16) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
			MaxVersion: maxVersion,
		}},
	}
}

// TestServeBootFailure_KeepsUnifiedTLSPolicy pins that the failed-boot
// listener serves the unified TLS policy (Codex round 3 on #2291): under
// tls.client_auth require, a client without a certificate gets no response,
// and a TLS 1.2-only client fails the handshake.
func TestServeBootFailure_KeepsUnifiedTLSPolicy(t *testing.T) {
	addr, caFile, stop := bootFailureTestListener(t, "require",
		&QRDBNodeError{Stage: StageBootAfterSealedWindow, Err: io.ErrUnexpectedEOF})

	t.Run("no client certificate", func(t *testing.T) {
		client := bootFailureTestClient(t, caFile, 0)
		resp, err := client.Get("https://" + addr + "/v1/barrier/status")
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err)
		require.Nil(t, resp)
	})

	t.Run("TLS 1.2 only", func(t *testing.T) {
		client := bootFailureTestClient(t, caFile, tls.VersionTLS12)
		resp, err := client.Get("https://" + addr + "/v1/barrier/status")
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err)
		require.Nil(t, resp)
	})

	stop()
}

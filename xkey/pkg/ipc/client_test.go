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

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTestServer creates a server with the given handler, starts it in a
// goroutine, and returns the client and a cleanup function.
func startTestServer(t *testing.T, handler Handler) (*Client, func()) {
	t.Helper()

	sockPath := filepath.Join(t.TempDir(), "test.sock")

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)

	// Allow the server to start accepting.
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)

	cleanup := func() {
		client.Close()
		cancel()
		srv.Close()
	}

	return client, cleanup
}

func TestClient_Touch(t *testing.T) {
	handler := &mockHandler{
		touchResp: OKResponse(ActionApprovedUP),
	}

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	resp, err := client.Touch()
	require.NoError(t, err)
	assert.Equal(t, StatusOK, resp.Status)
	assert.Equal(t, ActionApprovedUP, resp.Action)
}

func TestClient_TypePassword(t *testing.T) {
	handler := &mockHandler{
		passwordResp: OKResponse(ActionTypedPassword),
	}

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	resp, err := client.TypePassword("github")
	require.NoError(t, err)
	assert.Equal(t, StatusOK, resp.Status)
	assert.Equal(t, ActionTypedPassword, resp.Action)
	assert.Equal(t, "github", handler.getLastName())
}

func TestClient_Status(t *testing.T) {
	handler := &mockHandler{
		statusResp: OKResponse(ActionDaemonReady),
	}

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	resp, err := client.Status()
	require.NoError(t, err)
	assert.Equal(t, StatusOK, resp.Status)
	assert.Equal(t, ActionDaemonReady, resp.Action)
}

func TestClient_DaemonNotRunning(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "nonexistent.sock")
	client := NewClient(sockPath)
	defer client.Close()

	resp, err := client.Touch()
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrDaemonNotRunning),
		"expected ErrDaemonNotRunning, got: %v", err)
}

func TestClient_DaemonNotRunning_TypePassword(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "nonexistent.sock")
	client := NewClient(sockPath)
	defer client.Close()

	resp, err := client.TypePassword("test")
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrDaemonNotRunning))
}

func TestClient_DaemonNotRunning_Status(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "nonexistent.sock")
	client := NewClient(sockPath)
	defer client.Close()

	resp, err := client.Status()
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrDaemonNotRunning))
}

func TestClient_Close(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	client := NewClient(sockPath)

	assert.NoError(t, client.Close())

	// Operations after close should fail.
	resp, err := client.Touch()
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrClientClosed))
}

func TestClient_Close_AllMethods(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	client := NewClient(sockPath)
	require.NoError(t, client.Close())

	tests := []struct {
		name string
		fn   func() (*Response, error)
	}{
		{"Touch", client.Touch},
		{"TypePassword", func() (*Response, error) { return client.TypePassword("test") }},
		{"Status", client.Status},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.fn()
			assert.Nil(t, resp)
			assert.True(t, errors.Is(err, ErrClientClosed))
		})
	}
}

func TestClient_HandlerError_ReturnsErrorResponse(t *testing.T) {
	handler := &mockHandler{
		touchErr: errors.New("hardware busy"),
	}

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	resp, err := client.Touch()
	require.NoError(t, err)
	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "handler returned error")
}

func TestClient_MultipleCalls(t *testing.T) {
	handler := &mockHandler{
		touchResp:    OKResponse(ActionApprovedUP),
		statusResp:   OKResponse(ActionDaemonReady),
		passwordResp: OKResponse(ActionTypedPassword),
	}

	client, cleanup := startTestServer(t, handler)
	defer cleanup()

	// Make multiple sequential calls to verify each creates a fresh connection.
	resp1, err := client.Touch()
	require.NoError(t, err)
	assert.Equal(t, ActionApprovedUP, resp1.Action)

	resp2, err := client.Status()
	require.NoError(t, err)
	assert.Equal(t, ActionDaemonReady, resp2.Action)

	resp3, err := client.TypePassword("mypass")
	require.NoError(t, err)
	assert.Equal(t, ActionTypedPassword, resp3.Action)
}

func TestClient_ServerClosesBeforeResponse(t *testing.T) {
	// Create a raw Unix socket that accepts and immediately closes.
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		// Close immediately without sending a response.
		conn.Close()
	}()

	client := NewClient(sockPath)
	defer client.Close()

	resp, err := client.Touch()
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrProtocolError),
		"expected ErrProtocolError, got: %v", err)
}

func TestIsDaemonNotRunning_ErrNotExist(t *testing.T) {
	assert.True(t, isDaemonNotRunning(os.ErrNotExist))
}

func TestIsDaemonNotRunning_RawENOENT(t *testing.T) {
	// Test with raw syscall.ENOENT (not wrapped in SyscallError).
	// This exercises the ENOENT branch directly because raw Errno does not
	// match os.ErrNotExist.
	assert.True(t, isDaemonNotRunning(syscall.ENOENT))
}

func TestIsDaemonNotRunning_RawECONNREFUSED(t *testing.T) {
	// Test with raw syscall.ECONNREFUSED (not wrapped).
	assert.True(t, isDaemonNotRunning(syscall.ECONNREFUSED))
}

func TestIsDaemonNotRunning_WrappedENOENT(t *testing.T) {
	err := &net.OpError{
		Op:  "dial",
		Net: "unix",
		Addr: &net.UnixAddr{
			Name: "/tmp/test.sock",
			Net:  "unix",
		},
		Err: &os.SyscallError{
			Syscall: "connect",
			Err:     syscall.ENOENT,
		},
	}
	assert.True(t, isDaemonNotRunning(err))
}

func TestIsDaemonNotRunning_WrappedECONNREFUSED(t *testing.T) {
	err := &net.OpError{
		Op:  "dial",
		Net: "unix",
		Addr: &net.UnixAddr{
			Name: "/tmp/test.sock",
			Net:  "unix",
		},
		Err: &os.SyscallError{
			Syscall: "connect",
			Err:     syscall.ECONNREFUSED,
		},
	}
	assert.True(t, isDaemonNotRunning(err))
}

func TestIsDaemonNotRunning_FmtWrappedENOENT(t *testing.T) {
	// Test with fmt.Errorf wrapping of ENOENT.
	err := fmt.Errorf("dial: %w", syscall.ENOENT)
	assert.True(t, isDaemonNotRunning(err))
}

func TestIsDaemonNotRunning_FmtWrappedECONNREFUSED(t *testing.T) {
	// Test with fmt.Errorf wrapping of ECONNREFUSED.
	err := fmt.Errorf("dial: %w", syscall.ECONNREFUSED)
	assert.True(t, isDaemonNotRunning(err))
}

func TestIsDaemonNotRunning_OtherError(t *testing.T) {
	assert.False(t, isDaemonNotRunning(errors.New("some other error")))
}

func TestIsDaemonNotRunning_NilWrappedOpError(t *testing.T) {
	err := &net.OpError{
		Op:  "dial",
		Net: "unix",
		Addr: &net.UnixAddr{
			Name: "/tmp/test.sock",
			Net:  "unix",
		},
		Err: errors.New("unrelated"),
	}
	assert.False(t, isDaemonNotRunning(err))
}

func TestIsDaemonNotRunning_OtherSyscallError(t *testing.T) {
	// Test with a syscall error that is neither ENOENT nor ECONNREFUSED.
	err := &net.OpError{
		Op:  "dial",
		Net: "unix",
		Addr: &net.UnixAddr{
			Name: "/tmp/test.sock",
			Net:  "unix",
		},
		Err: &os.SyscallError{
			Syscall: "connect",
			Err:     syscall.EACCES,
		},
	}
	assert.False(t, isDaemonNotRunning(err))
}

func TestNewClient_SetsDefaultTimeout(t *testing.T) {
	client := NewClient("/tmp/test.sock")
	assert.Equal(t, DefaultTimeout, client.timeout)
}

func TestClient_ConnectionFailed_PermissionDenied(t *testing.T) {
	// Create a socket that is not accessible due to permissions.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	// Create a listener, then remove access permissions.
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()

	// Remove all permissions from the socket.
	require.NoError(t, os.Chmod(sockPath, 0000))
	defer os.Chmod(sockPath, 0600) // Restore for cleanup.

	client := NewClient(sockPath)
	defer client.Close()

	resp, err := client.Touch()
	assert.Nil(t, resp)
	assert.Error(t, err)
	// Should be ErrConnectionFailed (EACCES is not daemon not running).
	assert.True(t, errors.Is(err, ErrConnectionFailed),
		"expected ErrConnectionFailed, got: %v", err)
}

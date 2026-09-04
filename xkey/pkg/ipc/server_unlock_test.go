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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockUnlockHandler implements Handler and UnlockHandler. It reports unlock
// outcomes in band, the way the real GUI and headless handlers do: a refused
// unlock comes back as UnlockResult{Success: false} with a nil Go error.
type mockUnlockHandler struct {
	mockHandler
	unlockResult *UnlockResult
	unlockErr    error
	lastPIN      string
}

func (h *mockUnlockHandler) HandleUnlock(pin string) (*UnlockResult, error) {
	h.lastPIN = pin
	return h.unlockResult, h.unlockErr
}

// serveUnlockHandler starts a server on a temporary socket and returns a
// client connected to it. Both are torn down when the test ends.
func serveUnlockHandler(t *testing.T, handler Handler) *Client {
	t.Helper()

	sockPath := testSocketPath(t)
	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go srv.Serve(ctx)

	// Allow the server to start accepting.
	time.Sleep(50 * time.Millisecond)

	client := NewClient(sockPath)
	t.Cleanup(func() {
		_ = client.Close()
		cancel()
		_ = srv.Close()
	})
	return client
}

// TestServer_Unlock_RefusedReportsErrorStatus is the protocol half of #250
// defect 2. A handler that refuses the unlock must not produce a response a
// client can read as success. Before the fix the dispatcher stamped StatusOK
// on every nil-error handler return, so a refused unlock arrived at the CLI
// indistinguishable from a granted one.
func TestServer_Unlock_RefusedReportsErrorStatus(t *testing.T) {
	handler := &mockUnlockHandler{
		unlockResult: &UnlockResult{Success: false, Error: "app lock: PIN is invalid"},
	}
	client := serveUnlockHandler(t, handler)

	resp, err := client.Unlock("1234")
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, StatusError, resp.Status,
		"a refused unlock must report StatusError, not StatusOK")
	assert.Contains(t, resp.Error, "PIN is invalid",
		"the response must carry the handler's reason")
	require.NotNil(t, resp.Unlock)
	assert.False(t, resp.Unlock.Success)
}

// TestServer_Unlock_GrantedReportsOKStatus is the companion success case: a
// granted unlock still reports StatusOK with Success true.
func TestServer_Unlock_GrantedReportsOKStatus(t *testing.T) {
	handler := &mockUnlockHandler{
		unlockResult: &UnlockResult{Success: true},
	}
	client := serveUnlockHandler(t, handler)

	resp, err := client.Unlock("correct-pin")
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, StatusOK, resp.Status)
	require.NotNil(t, resp.Unlock)
	assert.True(t, resp.Unlock.Success)
	assert.Equal(t, "correct-pin", handler.lastPIN)
}

// TestServer_Unlock_NilResultReportsErrorStatus covers a handler that returns
// neither a result nor an error. Absence of a result is not success.
func TestServer_Unlock_NilResultReportsErrorStatus(t *testing.T) {
	handler := &mockUnlockHandler{unlockResult: nil}
	client := serveUnlockHandler(t, handler)

	resp, err := client.Unlock("1234")
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, StatusError, resp.Status,
		"a handler that returns no result must not be read as success")
}

// TestServer_Unlock_HandlerErrorReportsErrorStatus covers a handler that fails
// outright rather than refusing in band.
func TestServer_Unlock_HandlerErrorReportsErrorStatus(t *testing.T) {
	handler := &mockUnlockHandler{unlockErr: errors.New("storage unavailable")}
	client := serveUnlockHandler(t, handler)

	resp, err := client.Unlock("1234")
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, StatusError, resp.Status)
}

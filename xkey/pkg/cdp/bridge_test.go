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

package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBridgeWithTestServer creates a Bridge backed by a test WebSocket server.
// The handler receives each CDP request and returns a raw JSON response.
func newBridgeWithTestServer(t *testing.T, handler func(msg []byte) []byte) (*Bridge, func()) {
	t.Helper()

	srv := newTestWSServer(t, handler)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)

	bridge := NewBridge(client, testLogger())

	cleanup := func() {
		client.Close()
		srv.Close()
	}

	return bridge, cleanup
}

// successHandler returns a handler that responds with empty success for all
// requests, except addVirtualAuthenticator which returns a fixed authenticator ID.
func successHandler() func(msg []byte) []byte {
	return func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}

		if req.Method == "WebAuthn.addVirtualAuthenticator" {
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"authenticatorId":"test-auth-001"}}`, req.ID))
		}
		return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
	}
}

// --- NewBridge tests ---

func TestNewBridge(t *testing.T) {
	bridge := NewBridge(nil, testLogger())
	require.NotNil(t, bridge)
	assert.False(t, bridge.started.Load())
	assert.Empty(t, bridge.AuthenticatorID())
}

func TestNewBridge_NilClientPreventsStart(t *testing.T) {
	bridge := NewBridge(nil, testLogger())
	err := bridge.Start(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBridgeNilClient))
}

// --- Start tests ---

func TestBridge_Start(t *testing.T) {
	bridge, cleanup := newBridgeWithTestServer(t, successHandler())
	defer cleanup()

	err := bridge.Start(context.Background())
	require.NoError(t, err)

	assert.True(t, bridge.started.Load())
	assert.Equal(t, "test-auth-001", bridge.AuthenticatorID())
}

func TestBridge_Start_AlreadyStarted(t *testing.T) {
	bridge, cleanup := newBridgeWithTestServer(t, successHandler())
	defer cleanup()

	err := bridge.Start(context.Background())
	require.NoError(t, err)

	err = bridge.Start(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBridgeAlreadyStarted))
}

func TestBridge_Start_EnableFails(t *testing.T) {
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		if req.Method == "WebAuthn.enable" {
			return []byte(fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"enable failed"}}`, req.ID))
		}
		return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
	}

	bridge, cleanup := newBridgeWithTestServer(t, handler)
	defer cleanup()

	err := bridge.Start(context.Background())
	require.Error(t, err)
	assert.False(t, bridge.started.Load())
}

func TestBridge_Start_AddAuthenticatorFails(t *testing.T) {
	callCount := 0
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		if req.Method == "WebAuthn.addVirtualAuthenticator" {
			return []byte(fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"add failed"}}`, req.ID))
		}
		if req.Method == "WebAuthn.disable" {
			callCount++
		}
		return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
	}

	bridge, cleanup := newBridgeWithTestServer(t, handler)
	defer cleanup()

	err := bridge.Start(context.Background())
	require.Error(t, err)
	assert.False(t, bridge.started.Load())
	assert.Empty(t, bridge.AuthenticatorID())
}

// --- SyncCredentials tests ---

func TestBridge_SyncCredentials(t *testing.T) {
	bridge, cleanup := newBridgeWithTestServer(t, successHandler())
	defer cleanup()

	require.NoError(t, bridge.Start(context.Background()))

	creds := []StoredCredential{
		{
			CredentialID:         "Y3JlZC0x",
			IsResidentCredential: true,
			RpID:                 "example.com",
			PrivateKey:           "cHJpdmF0ZS1rZXk",
			UserHandle:           "dXNlci0x",
			SignCount:            0,
		},
		{
			CredentialID:         "Y3JlZC0y",
			IsResidentCredential: true,
			RpID:                 "example.com",
			PrivateKey:           "cHJpdmF0ZS1rZXky",
			UserHandle:           "dXNlci0y",
			SignCount:            5,
		},
	}

	err := bridge.SyncCredentials(context.Background(), creds)
	assert.NoError(t, err)
}

func TestBridge_SyncCredentials_NotStarted(t *testing.T) {
	bridge := NewBridge(nil, testLogger())

	err := bridge.SyncCredentials(context.Background(), []StoredCredential{
		{CredentialID: "x", RpID: "y", PrivateKey: "z"},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBridgeNotStarted))
}

func TestBridge_SyncCredentials_Empty(t *testing.T) {
	bridge, cleanup := newBridgeWithTestServer(t, successHandler())
	defer cleanup()

	require.NoError(t, bridge.Start(context.Background()))

	err := bridge.SyncCredentials(context.Background(), nil)
	assert.NoError(t, err)
}

func TestBridge_SyncCredentials_PartialFailure(t *testing.T) {
	callIdx := 0
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}

		if req.Method == "WebAuthn.addVirtualAuthenticator" {
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"authenticatorId":"test-auth-001"}}`, req.ID))
		}

		if req.Method == "WebAuthn.addCredential" {
			callIdx++
			if callIdx == 2 {
				return []byte(fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"bad key"}}`, req.ID))
			}
		}

		return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
	}

	bridge, cleanup := newBridgeWithTestServer(t, handler)
	defer cleanup()

	require.NoError(t, bridge.Start(context.Background()))

	creds := []StoredCredential{
		{CredentialID: "ok-1", RpID: "a.com", PrivateKey: "k1"},
		{CredentialID: "fail-2", RpID: "b.com", PrivateKey: "k2"},
		{CredentialID: "ok-3", RpID: "c.com", PrivateKey: "k3"},
	}

	err := bridge.SyncCredentials(context.Background(), creds)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPCredentialFailed))
	assert.Contains(t, err.Error(), "1 of 3")
}

// --- Close tests ---

func TestBridge_Close(t *testing.T) {
	bridge, cleanup := newBridgeWithTestServer(t, successHandler())
	defer cleanup()

	require.NoError(t, bridge.Start(context.Background()))
	assert.True(t, bridge.started.Load())

	err := bridge.Close()
	assert.NoError(t, err)
	assert.False(t, bridge.started.Load())
	assert.Empty(t, bridge.AuthenticatorID())
}

func TestBridge_Close_NotStarted(t *testing.T) {
	bridge := NewBridge(nil, testLogger())
	err := bridge.Close()
	assert.NoError(t, err, "closing an un-started bridge should be a no-op")
}

func TestBridge_Close_RemoveFails(t *testing.T) {
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}

		if req.Method == "WebAuthn.addVirtualAuthenticator" {
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"authenticatorId":"test-auth-001"}}`, req.ID))
		}

		if req.Method == "WebAuthn.removeVirtualAuthenticator" {
			return []byte(fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"remove failed"}}`, req.ID))
		}

		return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
	}

	bridge, cleanup := newBridgeWithTestServer(t, handler)
	defer cleanup()

	require.NoError(t, bridge.Start(context.Background()))

	err := bridge.Close()
	require.Error(t, err)
	// Should still be marked as stopped despite the error.
	assert.False(t, bridge.started.Load())
}

func TestBridge_Close_DisableFails(t *testing.T) {
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}

		if req.Method == "WebAuthn.addVirtualAuthenticator" {
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"authenticatorId":"test-auth-001"}}`, req.ID))
		}

		if req.Method == "WebAuthn.disable" {
			return []byte(fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"disable failed"}}`, req.ID))
		}

		return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
	}

	bridge, cleanup := newBridgeWithTestServer(t, handler)
	defer cleanup()

	require.NoError(t, bridge.Start(context.Background()))

	err := bridge.Close()
	require.Error(t, err)
	// firstErr should come from Disable since Remove succeeds.
	assert.True(t, errors.Is(err, ErrCDPDisableFailed))
	assert.False(t, bridge.started.Load())
}

// --- AuthenticatorID tests ---

func TestBridge_AuthenticatorID_BeforeStart(t *testing.T) {
	bridge := NewBridge(nil, testLogger())
	assert.Empty(t, bridge.AuthenticatorID())
}

func TestBridge_AuthenticatorID_AfterStart(t *testing.T) {
	bridge, cleanup := newBridgeWithTestServer(t, successHandler())
	defer cleanup()

	require.NoError(t, bridge.Start(context.Background()))
	assert.Equal(t, "test-auth-001", bridge.AuthenticatorID())
}

// --- StoredCredential tests ---

func TestStoredCredential_Marshal(t *testing.T) {
	sc := StoredCredential{
		CredentialID:         "cred-1",
		IsResidentCredential: true,
		RpID:                 "example.com",
		PrivateKey:           "private-key-data",
		UserHandle:           "user-handle",
		SignCount:            7,
	}

	data, err := json.Marshal(sc)
	require.NoError(t, err)

	var decoded StoredCredential
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, sc, decoded)
}

func TestStoredCredential_ZeroValue(t *testing.T) {
	var sc StoredCredential
	assert.Empty(t, sc.CredentialID)
	assert.Empty(t, sc.RpID)
	assert.False(t, sc.IsResidentCredential)
	assert.Equal(t, 0, sc.SignCount)
}

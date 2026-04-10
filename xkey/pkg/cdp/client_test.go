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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger returns a no-op logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestWSServer creates an httptest server that upgrades to WebSocket and
// calls handler for each text message received. The handler returns the
// response bytes to send back.
func newTestWSServer(t *testing.T, handler func(msg []byte) []byte) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade error: %v", err)
			return
		}
		defer conn.Close()

		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.TextMessage {
				resp := handler(msg)
				if resp != nil {
					if writeErr := conn.WriteMessage(websocket.TextMessage, resp); writeErr != nil {
						return
					}
				}
			}
		}
	}))
	return srv
}

// connectTestClient dials a test WebSocket server and returns a Client.
func connectTestClient(t *testing.T, wsURL string) *Client {
	t.Helper()
	dialer := websocket.DefaultDialer
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)

	c := &Client{
		conn:    conn,
		logger:  testLogger(),
		pending: make(map[int64]chan rawResponse),
		done:    make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// --- MarshalRequest tests ---

func TestMarshalRequest_EnableMethod(t *testing.T) {
	data, err := MarshalRequest("WebAuthn.enable", nil)
	require.NoError(t, err)

	var req cdpRequest
	require.NoError(t, json.Unmarshal(data, &req))

	assert.Equal(t, "WebAuthn.enable", req.Method)
	assert.Equal(t, int64(1), req.ID)
}

func TestMarshalRequest_WithParams(t *testing.T) {
	opts := &AuthenticatorOptions{
		Protocol:                    "ctap2",
		Transport:                   "usb",
		HasResidentKey:              true,
		HasUserVerification:         true,
		IsUserVerified:              true,
		AutomaticPresenceSimulation: true,
	}

	type addParams struct {
		Options *AuthenticatorOptions `json:"options"`
	}

	data, err := MarshalRequest("WebAuthn.addVirtualAuthenticator", &addParams{Options: opts})
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Contains(t, string(raw["method"]), "addVirtualAuthenticator")
	assert.NotEmpty(t, raw["params"])

	var params addParams
	require.NoError(t, json.Unmarshal(raw["params"], &params))
	assert.Equal(t, "ctap2", params.Options.Protocol)
	assert.Equal(t, "usb", params.Options.Transport)
	assert.True(t, params.Options.HasResidentKey)
	assert.True(t, params.Options.HasUserVerification)
	assert.True(t, params.Options.IsUserVerified)
	assert.True(t, params.Options.AutomaticPresenceSimulation)
}

func TestMarshalRequest_NilParams(t *testing.T) {
	data, err := MarshalRequest("WebAuthn.disable", nil)
	require.NoError(t, err)

	// Should have no params key or null params.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))

	// With omitempty, params won't appear when nil.
	_, hasParams := raw["params"]
	assert.False(t, hasParams, "nil params should be omitted")
}

// --- UnmarshalResponse tests ---

func TestUnmarshalResponse_Success(t *testing.T) {
	raw := `{"id":1,"result":{"authenticatorId":"abc-123"}}`
	resp, err := UnmarshalResponse([]byte(raw))
	require.NoError(t, err)

	assert.Equal(t, int64(1), resp.ID)
	assert.Nil(t, resp.Error)
	assert.Contains(t, string(resp.Result), "abc-123")
}

func TestUnmarshalResponse_ProtocolError(t *testing.T) {
	raw := `{"id":2,"error":{"code":-32000,"message":"Authenticator not found"}}`
	resp, err := UnmarshalResponse([]byte(raw))
	require.NoError(t, err)

	assert.Equal(t, int64(2), resp.ID)
	assert.NotNil(t, resp.Error)
	assert.Equal(t, -32000, resp.Error.Code)
	assert.Equal(t, "Authenticator not found", resp.Error.Message)
}

func TestUnmarshalResponse_InvalidJSON(t *testing.T) {
	_, err := UnmarshalResponse([]byte(`{invalid`))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPResponseParseFailed))
}

func TestUnmarshalResponse_EmptyResult(t *testing.T) {
	raw := `{"id":3,"result":{}}`
	resp, err := UnmarshalResponse([]byte(raw))
	require.NoError(t, err)

	assert.Equal(t, int64(3), resp.ID)
	assert.Nil(t, resp.Error)
}

// --- AuthenticatorOptions tests ---

func TestAuthenticatorOptions_Marshal(t *testing.T) {
	opts := AuthenticatorOptions{
		Protocol:                    "ctap2",
		Transport:                   "usb",
		HasResidentKey:              true,
		HasUserVerification:         true,
		IsUserVerified:              true,
		AutomaticPresenceSimulation: true,
	}

	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded AuthenticatorOptions
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, opts, decoded)
}

func TestAuthenticatorOptions_Defaults(t *testing.T) {
	var opts AuthenticatorOptions
	data, err := json.Marshal(opts)
	require.NoError(t, err)

	var decoded AuthenticatorOptions
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Empty(t, decoded.Protocol)
	assert.Empty(t, decoded.Transport)
	assert.False(t, decoded.HasResidentKey)
	assert.False(t, decoded.HasUserVerification)
	assert.False(t, decoded.IsUserVerified)
	assert.False(t, decoded.AutomaticPresenceSimulation)
}

// --- Credential tests ---

func TestCredential_MarshalFull(t *testing.T) {
	cred := Credential{
		CredentialID:         "Y3JlZC0x",
		IsResidentCredential: true,
		RpID:                 "example.com",
		PrivateKey:           "cHJpdmF0ZS1rZXk",
		UserHandle:           "dXNlci0x",
		SignCount:            42,
	}

	data, err := json.Marshal(cred)
	require.NoError(t, err)

	var decoded Credential
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, cred, decoded)
}

func TestCredential_OmitEmptyUserHandle(t *testing.T) {
	cred := Credential{
		CredentialID:         "Y3JlZC0x",
		IsResidentCredential: false,
		RpID:                 "example.com",
		PrivateKey:           "cHJpdmF0ZS1rZXk",
		SignCount:            0,
	}

	data, err := json.Marshal(cred)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "userHandle")
}

func TestCredential_UnmarshalMissingUserHandle(t *testing.T) {
	raw := `{"credentialId":"abc","isResidentCredential":true,"rpId":"x.com","privateKey":"key","signCount":1}`
	var cred Credential
	require.NoError(t, json.Unmarshal([]byte(raw), &cred))

	assert.Equal(t, "abc", cred.CredentialID)
	assert.True(t, cred.IsResidentCredential)
	assert.Empty(t, cred.UserHandle)
}

// --- Live WebSocket send/response tests ---

func TestClient_Enable(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	err := client.Enable(context.Background())
	assert.NoError(t, err)
}

func TestClient_Enable_ProtocolError(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"not supported"}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	err := client.Enable(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPEnableFailed))
}

func TestClient_AddVirtualAuthenticator(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"result":{"authenticatorId":"auth-abc-123"}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	opts := &AuthenticatorOptions{
		Protocol:       "ctap2",
		Transport:      "usb",
		HasResidentKey: true,
	}

	authID, err := client.AddVirtualAuthenticator(context.Background(), opts)
	require.NoError(t, err)
	assert.Equal(t, "auth-abc-123", authID)
}

func TestClient_AddVirtualAuthenticator_Error(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"error":{"code":-32602,"message":"invalid params"}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	opts := &AuthenticatorOptions{}
	_, err := client.AddVirtualAuthenticator(context.Background(), opts)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPAuthenticatorFailed))
}

func TestClient_AddCredential(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	cred := &Credential{
		CredentialID:         "Y3JlZC0x",
		IsResidentCredential: true,
		RpID:                 "example.com",
		PrivateKey:           "cHJpdmF0ZS1rZXk",
		UserHandle:           "dXNlci0x",
		SignCount:            0,
	}

	err := client.AddCredential(context.Background(), "auth-1", cred)
	assert.NoError(t, err)
}

func TestClient_AddCredential_Error(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"authenticator not found"}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	err := client.AddCredential(context.Background(), "bad-id", &Credential{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPCredentialFailed))
}

func TestClient_RemoveVirtualAuthenticator(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	err := client.RemoveVirtualAuthenticator(context.Background(), "auth-1")
	assert.NoError(t, err)
}

func TestClient_RemoveVirtualAuthenticator_Error(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"not found"}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	err := client.RemoveVirtualAuthenticator(context.Background(), "missing")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPRemoveFailed))
}

func TestClient_Disable(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	err := client.Disable(context.Background())
	assert.NoError(t, err)
}

func TestClient_Disable_Error(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		resp := fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"already disabled"}}`, req.ID)
		return []byte(resp)
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	err := client.Disable(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPDisableFailed))
}

func TestClient_Send_ContextCancelled(t *testing.T) {
	// Server that never responds.
	srv := newTestWSServer(t, func(msg []byte) []byte {
		return nil
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err := client.Enable(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPEnableFailed))
}

func TestClient_Close(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		return nil
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)

	err := client.Close()
	assert.NoError(t, err)
}

// --- discoverWebSocketURL tests ---

func TestDiscoverWebSocketURL_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/abc"}`)
	}))
	defer srv.Close()

	// Parse host:port from test server.
	addr := strings.TrimPrefix(srv.URL, "http://")
	parts := strings.SplitN(addr, ":", 2)
	host := parts[0]
	var port int
	fmt.Sscanf(parts[1], "%d", &port)

	url, err := discoverWebSocketURL(host, port)
	require.NoError(t, err)
	assert.Equal(t, "ws://127.0.0.1:9222/devtools/browser/abc", url)
}

func TestDiscoverWebSocketURL_MissingURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"Browser":"Chrome/120"}`)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	parts := strings.SplitN(addr, ":", 2)
	host := parts[0]
	var port int
	fmt.Sscanf(parts[1], "%d", &port)

	_, err := discoverWebSocketURL(host, port)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPWebSocketURLNotFound))
}

func TestDiscoverWebSocketURL_ConnectionRefused(t *testing.T) {
	_, err := discoverWebSocketURL("127.0.0.1", 1) // Port 1 is unlikely to be open.
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPVersionFetchFailed))
}

func TestDiscoverWebSocketURL_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `not json`)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	parts := strings.SplitN(addr, ":", 2)
	host := parts[0]
	var port int
	fmt.Sscanf(parts[1], "%d", &port)

	_, err := discoverWebSocketURL(host, port)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPResponseParseFailed))
}

// --- Request serialization correctness ---

func TestClient_Send_ConnectionClosed(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		return nil
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)

	// Forcibly close the underlying connection to trigger read loop exit.
	client.conn.Close()

	// Wait for the done channel to close.
	<-client.done

	// Now any send should fail because the connection is closed.
	_, err := client.send(context.Background(), "WebAuthn.enable", nil)
	require.Error(t, err)
}

func TestClient_AddVirtualAuthenticator_InvalidResultJSON(t *testing.T) {
	srv := newTestWSServer(t, func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		// Return result that is not a valid addAuthenticatorResult.
		return []byte(fmt.Sprintf(`{"id":%d,"result":"not-an-object"}`, req.ID))
	})
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := connectTestClient(t, wsURL)
	defer client.Close()

	opts := &AuthenticatorOptions{Protocol: "ctap2", Transport: "usb"}
	_, err := client.AddVirtualAuthenticator(context.Background(), opts)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPResponseParseFailed))
}

func TestRequestSerialization_AddCredentialParams(t *testing.T) {
	type addCredParams struct {
		AuthenticatorID string      `json:"authenticatorId"`
		Credential      *Credential `json:"credential"`
	}

	params := &addCredParams{
		AuthenticatorID: "auth-1",
		Credential: &Credential{
			CredentialID:         "Y3JlZC0x",
			IsResidentCredential: true,
			RpID:                 "example.com",
			PrivateKey:           "cHJpdmF0ZS1rZXk",
			UserHandle:           "dXNlci0x",
			SignCount:            10,
		},
	}

	data, err := MarshalRequest("WebAuthn.addCredential", params)
	require.NoError(t, err)

	// Verify the entire structure round-trips correctly.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))

	var decoded addCredParams
	require.NoError(t, json.Unmarshal(raw["params"], &decoded))

	assert.Equal(t, "auth-1", decoded.AuthenticatorID)
	assert.Equal(t, "Y3JlZC0x", decoded.Credential.CredentialID)
	assert.Equal(t, "example.com", decoded.Credential.RpID)
	assert.Equal(t, 10, decoded.Credential.SignCount)
}

func TestRequestSerialization_RemoveAuthenticator(t *testing.T) {
	type removeParams struct {
		AuthenticatorID string `json:"authenticatorId"`
	}

	data, err := MarshalRequest("WebAuthn.removeVirtualAuthenticator", &removeParams{
		AuthenticatorID: "auth-xyz",
	})
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))

	var decoded removeParams
	require.NoError(t, json.Unmarshal(raw["params"], &decoded))

	assert.Equal(t, "auth-xyz", decoded.AuthenticatorID)
}

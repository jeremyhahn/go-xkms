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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushableServer is a WebSocket test server that answers CDP requests via a
// handler and can also push unsolicited events to the connected client. This
// models Chrome emitting WebAuthn.credentialAdded events.
type pushableServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	conn    *websocket.Conn
	connCh  chan struct{}
	handler func(msg []byte) []byte
}

// newPushableServer starts a server. handler may be nil for default success.
func newPushableServer(t *testing.T, handler func(msg []byte) []byte) *pushableServer {
	t.Helper()

	if handler == nil {
		handler = successHandler()
	}

	ps := &pushableServer{
		connCh:  make(chan struct{}),
		handler: handler,
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	ps.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade error: %v", err)
			return
		}

		ps.mu.Lock()
		ps.conn = conn
		ps.mu.Unlock()
		close(ps.connCh)

		defer conn.Close()
		for {
			mt, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.TextMessage {
				continue
			}
			resp := ps.handler(msg)
			if resp == nil {
				continue
			}
			ps.mu.Lock()
			writeErr := conn.WriteMessage(websocket.TextMessage, resp)
			ps.mu.Unlock()
			if writeErr != nil {
				return
			}
		}
	}))

	return ps
}

// client connects a Client to the server.
func (ps *pushableServer) client(t *testing.T) *Client {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(ps.srv.URL, "http")
	return connectTestClient(t, wsURL)
}

// pushEvent sends an unsolicited CDP event to the connected client. It blocks
// until a client connection is present.
func (ps *pushableServer) pushEvent(t *testing.T, method string, params interface{}) {
	t.Helper()
	<-ps.connCh

	payload, err := json.Marshal(struct {
		Method string      `json:"method"`
		Params interface{} `json:"params"`
	}{Method: method, Params: params})
	require.NoError(t, err)

	ps.mu.Lock()
	conn := ps.conn
	ps.mu.Unlock()
	require.NotNil(t, conn)

	ps.mu.Lock()
	err = conn.WriteMessage(websocket.TextMessage, payload)
	ps.mu.Unlock()
	require.NoError(t, err)
}

func (ps *pushableServer) close() {
	ps.srv.Close()
}

// --- credentialAdded event capture ---

// TestBridge_CredentialAddedEventPersists asserts a WebAuthn.credentialAdded
// event drives a call to the configured sink (event-driven durability).
func TestBridge_CredentialAddedEventPersists(t *testing.T) {
	ps := newPushableServer(t, nil)
	defer ps.close()

	client := ps.client(t)
	defer client.Close()

	captured := make(chan StoredCredential, 1)
	bridge := NewBridge(client, testLogger())
	bridge.SetCredentialSink(func(c StoredCredential) error {
		captured <- c
		return nil
	})

	require.NoError(t, bridge.Start(context.Background()))

	// CDP delivers binary fields as standard base64 (with padding); the bridge
	// passes them through to the sink verbatim. Use the real, '/'-containing
	// credentialId observed live from Chrome to mirror production.
	const stdCredID = "T4Gj/BomswwcvyYxNjfPwegYkwc8qWQoFAnulkkI1HE="
	ps.pushEvent(t, "WebAuthn.credentialAdded", credentialAddedEvent{
		AuthenticatorID: "test-auth-001",
		Credential: Credential{
			CredentialID:         stdCredID,
			IsResidentCredential: true,
			RpID:                 "example.com",
			PrivateKey:           xkms.SecretBytes("cGtjczgta2V5"),
			UserHandle:           "dXNlci0x",
			SignCount:            0,
		},
	})

	select {
	case got := <-captured:
		assert.Equal(t, stdCredID, got.CredentialID)
		assert.Equal(t, "example.com", got.RpID)
		assert.Equal(t, "cGtjczgta2V5", privateKeyText(&got))
		assert.True(t, got.IsResidentCredential)
	case <-bridgeTestTimeout():
		t.Fatal("sink was not invoked for credentialAdded event")
	}
}

// TestBridge_CredentialAddedEvent_NoSinkNoSubscription asserts that without a
// sink the event subscription is not registered (no panic, no capture).
func TestBridge_CredentialAddedEvent_NoSinkNoSubscription(t *testing.T) {
	ps := newPushableServer(t, nil)
	defer ps.close()

	client := ps.client(t)
	defer client.Close()

	bridge := NewBridge(client, testLogger())
	require.NoError(t, bridge.Start(context.Background()))

	// Pushing an event must not panic even though no sink is registered.
	ps.pushEvent(t, "WebAuthn.credentialAdded", credentialAddedEvent{
		AuthenticatorID: "test-auth-001",
		Credential:      Credential{CredentialID: "x", RpID: "y", PrivateKey: xkms.SecretBytes("z")},
	})

	assert.Nil(t, client.eventHandler)
}

// TestBridge_CredentialAdded_MissingKeySkipped asserts a malformed event with
// no private key is skipped rather than persisted.
func TestBridge_CredentialAdded_MissingKeySkipped(t *testing.T) {
	ps := newPushableServer(t, nil)
	defer ps.close()

	client := ps.client(t)
	defer client.Close()

	var calls int
	var mu sync.Mutex
	bridge := NewBridge(client, testLogger())
	bridge.SetCredentialSink(func(c StoredCredential) error {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil
	})

	require.NoError(t, bridge.Start(context.Background()))

	ps.pushEvent(t, "WebAuthn.credentialAdded", credentialAddedEvent{
		AuthenticatorID: "test-auth-001",
		Credential:      Credential{CredentialID: "id-only", RpID: "rp"},
	})

	// Drain via a synchronous round-trip so the event has been processed.
	require.NoError(t, client.Enable(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 0, calls, "credential without a private key must be skipped")
}

// TestBridge_HandleEvent_IgnoresOtherMethods asserts that an event other
// than WebAuthn.credentialAdded is dropped without touching the sink: the
// bridge captures exactly one CDP event type, not every unsolicited message.
func TestBridge_HandleEvent_IgnoresOtherMethods(t *testing.T) {
	bridge := &Bridge{logger: testLogger()}
	bridge.SetCredentialSink(func(StoredCredential) error {
		t.Fatal("the sink must not run for a method the bridge does not capture")
		return nil
	})

	bridge.handleEvent("Target.targetCreated", json.RawMessage(`{"targetInfo":{}}`))
}

// TestBridge_HandleEvent_MalformedParamsLogsAndDrops asserts that a
// credentialAdded event whose params cannot be decoded is dropped rather
// than panicking or forwarding a zero-value credential to the sink.
func TestBridge_HandleEvent_MalformedParamsLogsAndDrops(t *testing.T) {
	bridge := &Bridge{logger: testLogger()}
	bridge.SetCredentialSink(func(StoredCredential) error {
		t.Fatal("the sink must not run for an event whose params failed to decode")
		return nil
	})

	bridge.handleEvent("WebAuthn.credentialAdded", json.RawMessage(`not json`))
}

// TestBridge_PersistCaptured_SinkErrorIsLoggedNotPanicked asserts that a
// sink failure is swallowed as a logged warning: capture is best-effort, and
// the caller (the CDP read loop) must keep running afterward.
func TestBridge_PersistCaptured_SinkErrorIsLoggedNotPanicked(t *testing.T) {
	bridge := &Bridge{logger: testLogger()}
	var called bool
	bridge.SetCredentialSink(func(StoredCredential) error {
		called = true
		return fmt.Errorf("storage unavailable")
	})

	assert.NotPanics(t, func() {
		bridge.persistCaptured(Credential{CredentialID: "id-1", PrivateKey: xkms.SecretBytes("key-1"), RpID: "example.com"})
	})
	assert.True(t, called, "the sink must still be invoked before its error is swallowed")
}

// --- shutdown sweep (CaptureAll) ---

// TestBridge_CaptureAll_Sweep asserts getCredentials results are forwarded to
// the sink as a complementary shutdown sweep.
func TestBridge_CaptureAll_Sweep(t *testing.T) {
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		switch req.Method {
		case "WebAuthn.addVirtualAuthenticator":
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"authenticatorId":"test-auth-001"}}`, req.ID))
		case "WebAuthn.getCredentials":
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"credentials":[`+
				`{"credentialId":"c1","isResidentCredential":true,"rpId":"a.com","privateKey":"k1","signCount":1},`+
				`{"credentialId":"c2","isResidentCredential":false,"rpId":"b.com","privateKey":"k2","signCount":2}`+
				`]}}`, req.ID))
		default:
			return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
		}
	}

	ps := newPushableServer(t, handler)
	defer ps.close()

	client := ps.client(t)
	defer client.Close()

	var mu sync.Mutex
	var seen []string
	bridge := NewBridge(client, testLogger())
	bridge.SetCredentialSink(func(c StoredCredential) error {
		mu.Lock()
		seen = append(seen, c.CredentialID)
		mu.Unlock()
		return nil
	})

	require.NoError(t, bridge.Start(context.Background()))
	require.NoError(t, bridge.CaptureAll(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	assert.ElementsMatch(t, []string{"c1", "c2"}, seen)
}

// TestBridge_CaptureAll_NotStarted asserts the sweep refuses to run before Start.
func TestBridge_CaptureAll_NotStarted(t *testing.T) {
	bridge := NewBridge(nil, testLogger())
	bridge.SetCredentialSink(func(StoredCredential) error { return nil })
	err := bridge.CaptureAll(context.Background())
	require.ErrorIs(t, err, ErrBridgeNotStarted)
}

// TestBridge_CaptureAll_NoSinkNoop asserts the sweep is a no-op without a sink.
func TestBridge_CaptureAll_NoSinkNoop(t *testing.T) {
	ps := newPushableServer(t, nil)
	defer ps.close()
	client := ps.client(t)
	defer client.Close()

	bridge := NewBridge(client, testLogger())
	require.NoError(t, bridge.Start(context.Background()))
	require.NoError(t, bridge.CaptureAll(context.Background()))
}

// TestBridge_Close_RunsSweep asserts Close performs the complementary sweep
// when a sink is configured.
func TestBridge_Close_RunsSweep(t *testing.T) {
	getCalled := make(chan struct{}, 1)
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		switch req.Method {
		case "WebAuthn.addVirtualAuthenticator":
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"authenticatorId":"test-auth-001"}}`, req.ID))
		case "WebAuthn.getCredentials":
			select {
			case getCalled <- struct{}{}:
			default:
			}
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"credentials":[]}}`, req.ID))
		default:
			return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
		}
	}

	ps := newPushableServer(t, handler)
	defer ps.close()
	client := ps.client(t)
	defer client.Close()

	bridge := NewBridge(client, testLogger())
	bridge.SetCredentialSink(func(StoredCredential) error { return nil })
	require.NoError(t, bridge.Start(context.Background()))
	require.NoError(t, bridge.Close())

	select {
	case <-getCalled:
	case <-bridgeTestTimeout():
		t.Fatal("Close did not invoke the getCredentials shutdown sweep")
	}
}

// bridgeTestTimeout returns a channel that fires after a generous test timeout.
// It guards against a hung test rather than introducing real latency: the
// happy path always completes via the event/round-trip channels first.
func bridgeTestTimeout() <-chan time.Time {
	return time.After(5 * time.Second)
}

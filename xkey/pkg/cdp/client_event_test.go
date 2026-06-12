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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClient_OnEvent_Dispatch asserts that a registered event handler receives
// unsolicited CDP events (no id) and that the params are forwarded verbatim.
func TestClient_OnEvent_Dispatch(t *testing.T) {
	ps := newPushableServer(t, nil)
	defer ps.close()

	client := ps.client(t)
	defer client.Close()

	type captured struct {
		method string
		params json.RawMessage
	}
	got := make(chan captured, 1)
	client.OnEvent(func(method string, params json.RawMessage) {
		got <- captured{method: method, params: params}
	})

	ps.pushEvent(t, "WebAuthn.credentialAdded", map[string]any{
		"authenticatorId": "auth-1",
	})

	select {
	case ev := <-got:
		assert.Equal(t, "WebAuthn.credentialAdded", ev.method)
		assert.Contains(t, string(ev.params), "auth-1")
	case <-bridgeTestTimeout():
		t.Fatal("event handler was not invoked")
	}
}

// TestClient_OnEvent_NilHandlerDropped asserts events are dropped silently when
// no handler is registered.
func TestClient_OnEvent_NilHandlerDropped(t *testing.T) {
	ps := newPushableServer(t, nil)
	defer ps.close()

	client := ps.client(t)
	defer client.Close()

	ps.pushEvent(t, "WebAuthn.credentialAdded", map[string]any{"x": 1})

	// A synchronous round-trip proves the read loop survived the dropped event.
	require.NoError(t, client.Enable(context.Background()))
}

// TestClient_GetCredentials_Success asserts getCredentials parses the response.
func TestClient_GetCredentials_Success(t *testing.T) {
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		if req.Method == "WebAuthn.getCredentials" {
			return []byte(fmt.Sprintf(`{"id":%d,"result":{"credentials":[`+
				`{"credentialId":"c1","isResidentCredential":true,"rpId":"a.com","privateKey":"k1","signCount":3}`+
				`]}}`, req.ID))
		}
		return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
	}

	ps := newPushableServer(t, handler)
	defer ps.close()
	client := ps.client(t)
	defer client.Close()

	creds, err := client.GetCredentials(context.Background(), "auth-1")
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "c1", creds[0].CredentialID)
	assert.Equal(t, "a.com", creds[0].RpID)
	assert.Equal(t, 3, creds[0].SignCount)
	assert.True(t, creds[0].IsResidentCredential)
}

// TestClient_GetCredentials_ProtocolError asserts a protocol error is wrapped.
func TestClient_GetCredentials_ProtocolError(t *testing.T) {
	handler := func(msg []byte) []byte {
		var req cdpRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			return nil
		}
		if req.Method == "WebAuthn.getCredentials" {
			return []byte(fmt.Sprintf(`{"id":%d,"error":{"code":-32000,"message":"boom"}}`, req.ID))
		}
		return []byte(fmt.Sprintf(`{"id":%d,"result":{}}`, req.ID))
	}

	ps := newPushableServer(t, handler)
	defer ps.close()
	client := ps.client(t)
	defer client.Close()

	_, err := client.GetCredentials(context.Background(), "auth-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrCDPGetCredentialsFailed)
}

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
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStateHandler implements Handler and StateHandler for testing.
type mockStateHandler struct {
	mockHandler

	pin           *PINStateResult
	barrier       *BarrierStatusResult
	passwordStore *PasswordStoreStateResult
	passwordList  *PasswordListResult
	err           error
}

func (h *mockStateHandler) HandleStatePIN() (*PINStateResult, error) {
	return h.pin, h.err
}

func (h *mockStateHandler) HandleStateBarrier() (*BarrierStatusResult, error) {
	return h.barrier, h.err
}

func (h *mockStateHandler) HandleStatePasswordStore() (*PasswordStoreStateResult, error) {
	return h.passwordStore, h.err
}

func (h *mockStateHandler) HandleStatePasswordList() (*PasswordListResult, error) {
	return h.passwordList, h.err
}

// startStateServer runs a server on a temp socket for the test's lifetime.
// The listener is already bound when NewServer returns, so a client may dial
// immediately without waiting on the accept loop.
func startStateServer(t *testing.T, handler Handler) string {
	t.Helper()

	sockPath := filepath.Join(privateDir(t), "xkey.sock")
	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-served
	})

	return sockPath
}

// --- payload validation ---

func TestStatePayload_ValidateAcceptsEveryDispatchedAction(t *testing.T) {
	// The validator and the dispatch table must agree, or an action is
	// accepted on the wire and then rejected as unknown.
	for action := range stateHandlers {
		payload := &StatePayload{Action: action}
		require.NoError(t, payload.Validate(), "action %q", action)
	}
	assert.Len(t, validStateActions, len(stateHandlers))
}

func TestStatePayload_ValidateRejectsEmptyAndUnknownActions(t *testing.T) {
	err := (&StatePayload{}).Validate()
	require.ErrorIs(t, err, ErrInvalidMessage)
	assert.Contains(t, err.Error(), "state action is required")

	err = (&StatePayload{Action: "read_pin_value"}).Validate()
	require.ErrorIs(t, err, ErrInvalidMessage)
	assert.Contains(t, err.Error(), `unknown state action "read_pin_value"`)
}

func TestMessage_ValidateRequiresAStatePayload(t *testing.T) {
	err := (&Message{Type: MessageTypeState}).Validate()
	require.ErrorIs(t, err, ErrInvalidMessage)
	assert.Contains(t, err.Error(), "state payload is required")

	require.NoError(t, (&Message{
		Type:  MessageTypeState,
		State: &StatePayload{Action: ActionStateBarrier},
	}).Validate())
}

func TestPasswordEntryInfo_CarriesNoSecretField(t *testing.T) {
	// A regression guard with teeth: the whole security argument for
	// listing passwords over a permission-only socket is that the wire type
	// cannot carry a value. Adding one must fail here.
	forbidden := map[string]bool{
		"Password": true,
		"Secret":   true,
		"Value":    true,
		"Notes":    true,
	}

	entryType := reflect.TypeOf(PasswordEntryInfo{})
	for i := 0; i < entryType.NumField(); i++ {
		name := entryType.Field(i).Name
		assert.Falsef(t, forbidden[name],
			"PasswordEntryInfo.%s would carry secret material over the IPC socket", name)
	}
}

// --- server dispatch ---

func TestServer_State_AnswersEachAction(t *testing.T) {
	handler := &mockStateHandler{
		mockHandler:   mockHandler{statusResp: OKResponse(ActionDaemonReady)},
		pin:           &PINStateResult{Initialized: true, SOPINSet: true, UserPINSet: true, Strategy: "software"},
		barrier:       &BarrierStatusResult{Initialized: true, Sealed: false, Strategy: "tpm2", HardwareBacked: true},
		passwordStore: &PasswordStoreStateResult{Available: true, Backend: "barrier", Count: 2},
		passwordList: &PasswordListResult{Entries: []PasswordEntryInfo{
			{Name: "DatabaseProd", Username: "admin"},
		}},
	}
	sockPath := startStateServer(t, handler)

	tests := []struct {
		name   string
		action string
		verify func(t *testing.T, result *StateResult)
	}{
		{
			name:   "pin",
			action: ActionStatePIN,
			verify: func(t *testing.T, result *StateResult) {
				require.NotNil(t, result.PIN)
				assert.True(t, result.PIN.SOPINSet)
				assert.True(t, result.PIN.UserPINSet)
			},
		},
		{
			name:   "barrier",
			action: ActionStateBarrier,
			verify: func(t *testing.T, result *StateResult) {
				require.NotNil(t, result.Barrier)
				assert.True(t, result.Barrier.Initialized)
				assert.False(t, result.Barrier.Sealed)
			},
		},
		{
			name:   "password store",
			action: ActionStatePasswordStore,
			verify: func(t *testing.T, result *StateResult) {
				require.NotNil(t, result.PasswordStore)
				assert.Equal(t, 2, result.PasswordStore.Count)
			},
		},
		{
			name:   "password list",
			action: ActionStatePasswordList,
			verify: func(t *testing.T, result *StateResult) {
				require.NotNil(t, result.PasswordList)
				require.Len(t, result.PasswordList.Entries, 1)
				assert.Equal(t, "DatabaseProd", result.PasswordList.Entries[0].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sendStateMessage(t, sockPath, &Message{
				Type:  MessageTypeState,
				State: &StatePayload{Action: tt.action},
			})
			require.Equal(t, StatusOK, resp.Status, "error: %s", resp.Error)
			require.NotNil(t, resp.State)
			tt.verify(t, resp.State)
		})
	}
}

func TestServer_State_HandlerErrorIsReported(t *testing.T) {
	sockPath := startStateServer(t, &mockStateHandler{
		mockHandler: mockHandler{statusResp: OKResponse(ActionDaemonReady)},
		err:         errors.New("pin backend offline"),
	})

	resp := sendStateMessage(t, sockPath, &Message{
		Type:  MessageTypeState,
		State: &StatePayload{Action: ActionStatePIN},
	})

	assert.Equal(t, StatusError, resp.Status)
	assert.NotEqual(t, ActionUnsupported, resp.Action,
		"a real failure must not masquerade as an unsupported verb, which the client treats as a licence to fall back")
	assertNotEchoed(t, resp.Error, "pin backend offline")
}

func TestServer_State_HandlerWithoutStateSupportRepliesUnsupported(t *testing.T) {
	// A daemon that does not own live state (the FIDO2 foreground daemon,
	// the extension host) must say so structurally, so the client falls back
	// to disk and labels the fallback instead of failing.
	sockPath := startStateServer(t, &mockHandler{statusResp: OKResponse(ActionDaemonReady)})

	resp := sendStateMessage(t, sockPath, &Message{
		Type:  MessageTypeState,
		State: &StatePayload{Action: ActionStateBarrier},
	})

	assert.Equal(t, StatusError, resp.Status)
	assert.Equal(t, ActionUnsupported, resp.Action)
}

func TestServer_State_RejectsAnUnknownAction(t *testing.T) {
	sockPath := startStateServer(t, &mockStateHandler{
		mockHandler: mockHandler{statusResp: OKResponse(ActionDaemonReady)},
	})

	resp := sendStateMessage(t, sockPath, &Message{
		Type:  MessageTypeState,
		State: &StatePayload{Action: "read_pin_value"},
	})

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "unknown state action")
}

// --- client ---

func TestClient_StateMethodsUnpackEachResult(t *testing.T) {
	sockPath := startStateServer(t, &mockStateHandler{
		mockHandler:   mockHandler{statusResp: OKResponse(ActionDaemonReady)},
		pin:           &PINStateResult{SOPINSet: true, MaxAttempts: 8},
		barrier:       &BarrierStatusResult{Initialized: true, Sealed: true, Strategy: "software"},
		passwordStore: &PasswordStoreStateResult{Available: true, Locked: true, Backend: "barrier"},
		passwordList:  &PasswordListResult{Entries: []PasswordEntryInfo{{Name: "WiFi"}}},
	})

	client := NewClient(sockPath)
	defer func() { _ = client.Close() }()

	pin, err := client.StatePIN()
	require.NoError(t, err)
	assert.True(t, pin.SOPINSet)
	assert.Equal(t, 8, pin.MaxAttempts)

	barrier, err := client.StateBarrier()
	require.NoError(t, err)
	assert.True(t, barrier.Sealed)
	assert.Equal(t, "software", barrier.Strategy)

	store, err := client.StatePasswordStore()
	require.NoError(t, err)
	assert.True(t, store.Locked)

	list, err := client.StatePasswordList()
	require.NoError(t, err)
	require.Len(t, list.Entries, 1)
	assert.Equal(t, "WiFi", list.Entries[0].Name)
}

func TestClient_StateReportsUnsupportedDistinctlyFromNotRunning(t *testing.T) {
	// The two are different facts and drive different labels, so the client
	// must not collapse them into one error.
	sockPath := startStateServer(t, &mockHandler{statusResp: OKResponse(ActionDaemonReady)})

	client := NewClient(sockPath)
	defer func() { _ = client.Close() }()

	_, err := client.StateBarrier()
	require.ErrorIs(t, err, ErrStateUnsupported)
	assert.NotErrorIs(t, err, ErrDaemonNotRunning)

	absent := NewClient(filepath.Join(privateDir(t), "absent.sock"))
	defer func() { _ = absent.Close() }()

	_, err = absent.StateBarrier()
	require.ErrorIs(t, err, ErrDaemonNotRunning)
	assert.NotErrorIs(t, err, ErrStateUnsupported)
}

func TestClient_StateSurfacesHandlerFailures(t *testing.T) {
	sockPath := startStateServer(t, &mockStateHandler{
		mockHandler: mockHandler{statusResp: OKResponse(ActionDaemonReady)},
		err:         errors.New("barrier subsystem offline"),
	})

	client := NewClient(sockPath)
	defer func() { _ = client.Close() }()

	_, err := client.StateBarrier()
	require.ErrorIs(t, err, ErrStateOperation)
	assert.NotContains(t, err.Error(), "barrier subsystem offline")
	assert.ErrorContains(t, err, ErrHandlerFailed.Error())
}

func TestClient_StateRejectsAClosedClient(t *testing.T) {
	client := NewClient(filepath.Join(privateDir(t), "absent.sock"))
	require.NoError(t, client.Close())

	_, err := client.StatePIN()
	assert.ErrorIs(t, err, ErrClientClosed)
}

// sendStateMessage writes one message to the server and reads the response.
func sendStateMessage(t *testing.T, sockPath string, msg *Message) *Response {
	t.Helper()

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))
	return &resp
}

// TestClient_StateMethods_NilResultIsProtocolError covers the defensive
// check each State* accessor runs after a successful, error-free state
// query: a handler that reports success but leaves its own subject unset --
// a well-behaved daemon should never do this, but the wire format does not
// prevent it -- must surface as ErrProtocolError, not a nil-pointer panic on
// the field the caller then dereferences.
func TestClient_StateMethods_NilResultIsProtocolError(t *testing.T) {
	t.Run("pin", func(t *testing.T) {
		sockPath := startStateServer(t, &mockStateHandler{mockHandler: mockHandler{statusResp: OKResponse(ActionDaemonReady)}})
		client := NewClient(sockPath)
		defer func() { _ = client.Close() }()

		_, err := client.StatePIN()
		require.ErrorIs(t, err, ErrProtocolError)
		assert.Contains(t, err.Error(), "no pin result")
	})

	t.Run("barrier", func(t *testing.T) {
		sockPath := startStateServer(t, &mockStateHandler{mockHandler: mockHandler{statusResp: OKResponse(ActionDaemonReady)}})
		client := NewClient(sockPath)
		defer func() { _ = client.Close() }()

		_, err := client.StateBarrier()
		require.ErrorIs(t, err, ErrProtocolError)
		assert.Contains(t, err.Error(), "no barrier result")
	})

	t.Run("password store", func(t *testing.T) {
		sockPath := startStateServer(t, &mockStateHandler{mockHandler: mockHandler{statusResp: OKResponse(ActionDaemonReady)}})
		client := NewClient(sockPath)
		defer func() { _ = client.Close() }()

		_, err := client.StatePasswordStore()
		require.ErrorIs(t, err, ErrProtocolError)
		assert.Contains(t, err.Error(), "no password_store result")
	})

	t.Run("password list", func(t *testing.T) {
		sockPath := startStateServer(t, &mockStateHandler{mockHandler: mockHandler{statusResp: OKResponse(ActionDaemonReady)}})
		client := NewClient(sockPath)
		defer func() { _ = client.Close() }()

		_, err := client.StatePasswordList()
		require.ErrorIs(t, err, ErrProtocolError)
		assert.Contains(t, err.Error(), "no password_list result")
	})
}

func TestStateResult_OmitsUnsetSubjectsOnTheWire(t *testing.T) {
	encoded, err := json.Marshal(&StateResult{Barrier: &BarrierStatusResult{Sealed: true}})
	require.NoError(t, err)

	body := string(encoded)
	assert.Contains(t, body, `"barrier"`)
	assert.False(t, strings.Contains(body, `"pin"`))
	assert.False(t, strings.Contains(body, `"password_list"`))
}

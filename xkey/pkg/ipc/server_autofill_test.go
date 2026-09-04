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
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFullHandler is the failure injected into the full handler.
var errFullHandler = errors.New("handler unavailable")

// autofillCall records one dispatched autofill invocation and its arguments.
type autofillCall struct {
	action string
	args   []string
}

// fullHandler implements every optional IPC handler interface so the complete
// dispatch surface (autofill, pairing, unlock) can be driven over a real
// socket. It records the arguments each handler received, which is what proves
// the dispatch table wires payload fields to the right parameters.
type fullHandler struct {
	mu    sync.Mutex
	calls []autofillCall

	// failAction, when it matches the dispatched action, makes the handler
	// return errFullHandler.
	failAction string

	pairingCode   string
	pairingKey    string
	pairingOrigin string
	completed     string
	unlockPIN     string
}

func (h *fullHandler) record(action string, args ...string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, autofillCall{action: action, args: args})
	if h.failAction == action {
		return errFullHandler
	}
	return nil
}

func (h *fullHandler) recorded() []autofillCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]autofillCall(nil), h.calls...)
}

func (h *fullHandler) HandleTouch() (*Response, error)  { return OKResponse(ActionApprovedUP), nil }
func (h *fullHandler) HandleStatus() (*Response, error) { return OKResponse(ActionDaemonReady), nil }

func (h *fullHandler) HandleTypePassword(name string) (*Response, error) {
	if err := h.record("type_password", name); err != nil {
		return nil, err
	}
	return OKResponse(ActionTypedPassword), nil
}

func (h *fullHandler) autofill(action string, args ...string) (*AutofillResult, error) {
	if err := h.record(action, args...); err != nil {
		return nil, err
	}
	return &AutofillResult{Credentials: []AutofillCredential{{ID: action}}}, nil
}

func (h *fullHandler) HandleAutofillSearch(domain string) (*AutofillResult, error) {
	return h.autofill(ActionAutofillSearch, domain)
}

func (h *fullHandler) HandleAutofillGet(id, challenge string) (*AutofillResult, error) {
	return h.autofill(ActionAutofillGet, id, challenge)
}

func (h *fullHandler) HandleAutofillTOTP(domain string) (*AutofillResult, error) {
	return h.autofill(ActionAutofillTOTP, domain)
}

func (h *fullHandler) HandleAutofillTOTPByID(id string) (*AutofillResult, error) {
	return h.autofill(ActionAutofillTOTPByID, id)
}

func (h *fullHandler) HandleAutofillStatus() (*AutofillResult, error) {
	return h.autofill(ActionAutofillStatus)
}

func (h *fullHandler) HandleAutofillPolicy() (*AutofillResult, error) {
	return h.autofill(ActionAutofillPolicy)
}

func (h *fullHandler) HandleAutofillSave(domain, username, password, title string) (*AutofillResult, error) {
	return h.autofill(ActionAutofillSave, domain, username, password, title)
}

func (h *fullHandler) HandleAutofillIgnoreDomain(domain string) (*AutofillResult, error) {
	return h.autofill(ActionAutofillIgnoreDomain, domain)
}

func (h *fullHandler) HandleAutofillFocus() (*AutofillResult, error) {
	return h.autofill(ActionAutofillFocus)
}

func (h *fullHandler) HandlePairingNotifyCode(code, identityKey, origin string) error {
	h.mu.Lock()
	h.pairingCode, h.pairingKey, h.pairingOrigin = code, identityKey, origin
	h.mu.Unlock()
	return h.record(ActionPairingNotifyCode, code, identityKey, origin)
}

func (h *fullHandler) HandlePairingCompleted(origin string) error {
	h.mu.Lock()
	h.completed = origin
	h.mu.Unlock()
	return h.record(ActionPairingCompleted, origin)
}

func (h *fullHandler) HandleUnlock(pin string) (*UnlockResult, error) {
	h.mu.Lock()
	h.unlockPIN = pin
	h.mu.Unlock()
	if err := h.record("unlock", pin); err != nil {
		return nil, err
	}
	return &UnlockResult{Success: pin == "123456"}, nil
}

// startTestServer starts an IPC server on a socket inside a temp directory and
// returns the server plus its socket path.
func startFullTestServer(t *testing.T, handler Handler) (*Server, string) {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "xkey.sock")
	srv, err := NewServer(socketPath, handler, slog.New(slog.DiscardHandler))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()

	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-done
	})

	// NewServer already bound the listener, so connections queue in the
	// accept backlog even before Serve picks them up: no readiness probe is
	// needed (and a probe would pollute the audit log under test).
	return srv, socketPath
}

// roundTrip sends one raw message over the socket and returns the response.
func roundTrip(t *testing.T, socketPath string, msg *Message) *Response {
	t.Helper()

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))
	return &resp
}

// TestServer_AutofillDispatch drives every autofill action through the real
// client and socket, asserting each one reaches its handler with the right
// arguments. A mis-wired dispatch entry (a common copy/paste hazard in the
// action table) fails here.
func TestServer_AutofillDispatch(t *testing.T) {
	handler := &fullHandler{}
	_, socketPath := startFullTestServer(t, handler)
	client := NewClient(socketPath)

	tests := []struct {
		name     string
		call     func() (*Response, error)
		wantCall autofillCall
	}{
		{"search", func() (*Response, error) { return client.AutofillSearch("example.com") },
			autofillCall{ActionAutofillSearch, []string{"example.com"}}},
		{"get", func() (*Response, error) { return client.AutofillGet("cred-1", "challenge-1") },
			autofillCall{ActionAutofillGet, []string{"cred-1", "challenge-1"}}},
		{"totp", func() (*Response, error) { return client.AutofillTOTP("example.com") },
			autofillCall{ActionAutofillTOTP, []string{"example.com"}}},
		{"totp_by_id", func() (*Response, error) { return client.AutofillTOTPByID("oath-1") },
			autofillCall{ActionAutofillTOTPByID, []string{"oath-1"}}},
		{"status", func() (*Response, error) { return client.AutofillStatus() },
			autofillCall{ActionAutofillStatus, nil}},
		{"policy", func() (*Response, error) { return client.AutofillPolicy() },
			autofillCall{ActionAutofillPolicy, nil}},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.call()
			require.NoError(t, err)
			require.Equal(t, StatusOK, resp.Status, resp.Error)
			require.NotNil(t, resp.Autofill)
			require.Len(t, resp.Autofill.Credentials, 1)
			assert.Equal(t, tt.wantCall.action, resp.Autofill.Credentials[0].ID,
				"the response must come from the handler for the requested action")

			calls := handler.recorded()
			require.Len(t, calls, i+1)
			assert.Equal(t, tt.wantCall, calls[i])
		})
	}
}

// TestServer_AutofillSaveAndIgnoreAndFocus covers the actions that have no
// client convenience method and are only reachable as raw messages from the
// browser extension's native host.
func TestServer_AutofillSaveAndIgnoreAndFocus(t *testing.T) {
	handler := &fullHandler{}
	_, socketPath := startFullTestServer(t, handler)

	resp := roundTrip(t, socketPath, &Message{
		Type: MessageTypeAutofill,
		Autofill: &AutofillPayload{
			Action:   ActionAutofillSave,
			Domain:   "example.com",
			Username: "alice",
			Password: "s3cret",
			Title:    "Example",
		},
	})
	require.Equal(t, StatusOK, resp.Status, resp.Error)

	resp = roundTrip(t, socketPath, &Message{
		Type:     MessageTypeAutofill,
		Autofill: &AutofillPayload{Action: ActionAutofillIgnoreDomain, Domain: "ignored.example"},
	})
	require.Equal(t, StatusOK, resp.Status, resp.Error)

	resp = roundTrip(t, socketPath, &Message{
		Type:     MessageTypeAutofill,
		Autofill: &AutofillPayload{Action: ActionAutofillFocus},
	})
	require.Equal(t, StatusOK, resp.Status, resp.Error)

	assert.Equal(t, []autofillCall{
		{ActionAutofillSave, []string{"example.com", "alice", "s3cret", "Example"}},
		{ActionAutofillIgnoreDomain, []string{"ignored.example"}},
		{ActionAutofillFocus, nil},
	}, handler.recorded())
}

func TestServer_AutofillHandlerFailure(t *testing.T) {
	handler := &fullHandler{failAction: ActionAutofillSearch}
	_, socketPath := startFullTestServer(t, handler)

	resp := roundTrip(t, socketPath, &Message{
		Type:     MessageTypeAutofill,
		Autofill: &AutofillPayload{Action: ActionAutofillSearch, Domain: "example.com"},
	})

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, errFullHandler.Error())
	assert.Nil(t, resp.Autofill, "a failed handler must not return a partial result")
}

func TestServer_AutofillRejectedPayloads(t *testing.T) {
	handler := &fullHandler{}
	_, socketPath := startFullTestServer(t, handler)

	tests := []struct {
		name string
		msg  *Message
		want string
	}{
		{
			name: "missing payload",
			msg:  &Message{Type: MessageTypeAutofill},
			want: "autofill payload is required",
		},
		{
			name: "unknown action",
			msg:  &Message{Type: MessageTypeAutofill, Autofill: &AutofillPayload{Action: "exfiltrate"}},
			want: "unknown autofill action",
		},
		{
			name: "empty action",
			msg:  &Message{Type: MessageTypeAutofill, Autofill: &AutofillPayload{}},
			want: "action is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := roundTrip(t, socketPath, tt.msg)
			assert.Equal(t, StatusError, resp.Status)
			assert.Contains(t, resp.Error, tt.want)
		})
	}

	assert.Empty(t, handler.recorded(), "invalid payloads must never reach the handler")
}

func TestServer_PairingDispatch(t *testing.T) {
	handler := &fullHandler{}
	_, socketPath := startFullTestServer(t, handler)

	resp := roundTrip(t, socketPath, &Message{
		Type: MessageTypePairing,
		Pairing: &PairingPayload{
			Action:      ActionPairingNotifyCode,
			Code:        "123456",
			IdentityKey: "base64key",
			Origin:      "chrome-extension://abc/",
		},
	})
	require.Equal(t, StatusOK, resp.Status, resp.Error)
	require.NotNil(t, resp.Pairing)
	assert.True(t, resp.Pairing.Acknowledged)

	resp = roundTrip(t, socketPath, &Message{
		Type:    MessageTypePairing,
		Pairing: &PairingPayload{Action: ActionPairingCompleted, Origin: "chrome-extension://abc/"},
	})
	require.Equal(t, StatusOK, resp.Status, resp.Error)
	require.NotNil(t, resp.Pairing)
	assert.True(t, resp.Pairing.Acknowledged)

	handler.mu.Lock()
	defer handler.mu.Unlock()
	assert.Equal(t, "123456", handler.pairingCode)
	assert.Equal(t, "base64key", handler.pairingKey)
	assert.Equal(t, "chrome-extension://abc/", handler.pairingOrigin)
	assert.Equal(t, "chrome-extension://abc/", handler.completed)
}

func TestServer_PairingRejectedPayloads(t *testing.T) {
	handler := &fullHandler{}
	_, socketPath := startFullTestServer(t, handler)

	tests := []struct {
		name string
		msg  *Message
		want string
	}{
		{
			name: "missing payload",
			msg:  &Message{Type: MessageTypePairing},
			want: "pairing payload is required",
		},
		{
			name: "empty action",
			msg:  &Message{Type: MessageTypePairing, Pairing: &PairingPayload{}},
			want: "pairing action is required",
		},
		{
			name: "unknown action",
			msg:  &Message{Type: MessageTypePairing, Pairing: &PairingPayload{Action: "hijack"}},
			want: "unknown pairing action",
		},
		{
			name: "notify_code without code",
			msg:  &Message{Type: MessageTypePairing, Pairing: &PairingPayload{Action: ActionPairingNotifyCode}},
			want: "code is required",
		},
		{
			name: "completed without origin",
			msg:  &Message{Type: MessageTypePairing, Pairing: &PairingPayload{Action: ActionPairingCompleted}},
			want: "origin is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := roundTrip(t, socketPath, tt.msg)
			assert.Equal(t, StatusError, resp.Status)
			assert.Contains(t, resp.Error, tt.want)
		})
	}

	assert.Empty(t, handler.recorded(), "invalid pairing payloads must never reach the handler")
}

func TestServer_PairingHandlerFailure(t *testing.T) {
	handler := &fullHandler{failAction: ActionPairingCompleted}
	_, socketPath := startFullTestServer(t, handler)

	resp := roundTrip(t, socketPath, &Message{
		Type:    MessageTypePairing,
		Pairing: &PairingPayload{Action: ActionPairingCompleted, Origin: "chrome-extension://abc/"},
	})

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, errFullHandler.Error())
}

func TestServer_UnlockDispatch(t *testing.T) {
	handler := &fullHandler{}
	_, socketPath := startFullTestServer(t, handler)
	client := NewClient(socketPath)

	resp, err := client.Unlock("123456")
	require.NoError(t, err)
	require.Equal(t, StatusOK, resp.Status, resp.Error)
	require.NotNil(t, resp.Unlock)
	assert.True(t, resp.Unlock.Success)

	handler.mu.Lock()
	assert.Equal(t, "123456", handler.unlockPIN)
	handler.mu.Unlock()

	// A wrong PIN is a handler-level refusal, not a transport error: the
	// response must still be well-formed with Success=false, and the status
	// must follow the result. Reporting StatusOK here let the CLI read a
	// refused unlock as a granted one (#250).
	resp, err = client.Unlock("000000")
	require.NoError(t, err)
	require.Equal(t, StatusError, resp.Status)
	require.NotNil(t, resp.Unlock)
	assert.False(t, resp.Unlock.Success)
}

func TestServer_UnlockRejectedPayloads(t *testing.T) {
	handler := &fullHandler{}
	_, socketPath := startFullTestServer(t, handler)

	resp := roundTrip(t, socketPath, &Message{Type: MessageTypeUnlock})
	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "unlock payload is required")

	resp = roundTrip(t, socketPath, &Message{Type: MessageTypeUnlock, Unlock: &UnlockPayload{}})
	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "pin is required")

	assert.Empty(t, handler.recorded(), "an empty PIN must never reach the unlock handler")
}

func TestServer_UnlockHandlerFailure(t *testing.T) {
	handler := &fullHandler{failAction: "unlock"}
	_, socketPath := startFullTestServer(t, handler)

	resp := roundTrip(t, socketPath, &Message{
		Type:   MessageTypeUnlock,
		Unlock: &UnlockPayload{PIN: "123456"},
	})

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, errFullHandler.Error())
	assert.Nil(t, resp.Unlock)
}

// TestServer_OptionalHandlersNotImplemented verifies a base handler that does
// not implement the optional interfaces is rejected cleanly rather than
// panicking on the type assertion.
func TestServer_OptionalHandlersNotImplemented(t *testing.T) {
	_, socketPath := startFullTestServer(t, &mockHandler{
		touchResp:  OKResponse(ActionApprovedUP),
		statusResp: OKResponse(ActionDaemonReady),
	})

	tests := []struct {
		name string
		msg  *Message
		want string
	}{
		{
			name: "autofill",
			msg: &Message{Type: MessageTypeAutofill,
				Autofill: &AutofillPayload{Action: ActionAutofillStatus}},
			want: "does not implement AutofillHandler",
		},
		{
			name: "pairing",
			msg: &Message{Type: MessageTypePairing,
				Pairing: &PairingPayload{Action: ActionPairingCompleted, Origin: "chrome-extension://abc/"}},
			want: "does not implement PairingHandler",
		},
		{
			name: "unlock",
			msg:  &Message{Type: MessageTypeUnlock, Unlock: &UnlockPayload{PIN: "123456"}},
			want: "does not implement UnlockHandler",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := roundTrip(t, socketPath, tt.msg)
			assert.Equal(t, StatusError, resp.Status)
			assert.Contains(t, resp.Error, tt.want)
		})
	}
}

// TestServer_IsRunning verifies the lifecycle flag used by the GUI to decide
// whether the IPC endpoint is live.
func TestServer_IsRunning(t *testing.T) {
	srv, _ := startFullTestServer(t, &fullHandler{})

	assert.True(t, srv.IsRunning())
	require.NoError(t, srv.Close())
	assert.False(t, srv.IsRunning())
}

// recordingAudit captures audit entries emitted by the IPC server.
type recordingAudit struct {
	audit.Logger

	mu      sync.Mutex
	entries []audit.Entry
}

func (l *recordingAudit) Log(e audit.Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
}

func (l *recordingAudit) recorded() []audit.Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]audit.Entry(nil), l.entries...)
}

// TestServer_AuditLogging verifies dispatched and failed messages are audited
// with the message type, which is the record security review relies on.
func TestServer_AuditLogging(t *testing.T) {
	handler := &fullHandler{}
	srv, socketPath := startFullTestServer(t, handler)

	auditLog := &recordingAudit{}
	srv.SetAuditLogger(auditLog)

	resp := roundTrip(t, socketPath, &Message{Type: MessageTypeStatus})
	require.Equal(t, StatusOK, resp.Status)

	resp = roundTrip(t, socketPath, &Message{Type: "not-a-type"})
	require.Equal(t, StatusError, resp.Status)

	resp = roundTrip(t, socketPath, &Message{Type: MessageTypeTypePassword})
	require.Equal(t, StatusError, resp.Status)

	entries := auditLog.recorded()
	require.Len(t, entries, 3)

	assert.Equal(t, audit.OpIPCMessageDispatched, entries[0].Operation)
	assert.True(t, entries[0].Success)
	assert.Equal(t, MessageTypeStatus, entries[0].Details["message_type"])

	assert.Equal(t, audit.OpIPCMessageFailed, entries[1].Operation)
	assert.False(t, entries[1].Success)
	assert.NotEmpty(t, entries[1].Error)

	assert.Equal(t, audit.OpIPCMessageFailed, entries[2].Operation)
	assert.Equal(t, MessageTypeTypePassword, entries[2].Details["message_type"])
}

// TestServer_AuditLoggingOnDecodeFailure covers the audit record emitted when
// the client sends bytes that are not valid JSON.
func TestServer_AuditLoggingOnDecodeFailure(t *testing.T) {
	srv, socketPath := startFullTestServer(t, &fullHandler{})

	auditLog := &recordingAudit{}
	srv.SetAuditLogger(auditLog)

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	require.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = conn.Write([]byte("this is not json\n"))
	require.NoError(t, err)

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))
	assert.Equal(t, StatusError, resp.Status)

	entries := auditLog.recorded()
	require.Len(t, entries, 1)
	assert.Equal(t, audit.OpIPCMessageFailed, entries[0].Operation)
	assert.False(t, entries[0].Success)
}

func TestClient_ClosedRejectsAllCalls(t *testing.T) {
	handler := &fullHandler{}
	_, socketPath := startFullTestServer(t, handler)

	client := NewClient(socketPath)
	require.NoError(t, client.Close())

	calls := map[string]func() (*Response, error){
		"AutofillSearch":   func() (*Response, error) { return client.AutofillSearch("example.com") },
		"AutofillGet":      func() (*Response, error) { return client.AutofillGet("id", "challenge") },
		"AutofillTOTP":     func() (*Response, error) { return client.AutofillTOTP("example.com") },
		"AutofillTOTPByID": func() (*Response, error) { return client.AutofillTOTPByID("id") },
		"AutofillStatus":   func() (*Response, error) { return client.AutofillStatus() },
		"AutofillPolicy":   func() (*Response, error) { return client.AutofillPolicy() },
		"Unlock":           func() (*Response, error) { return client.Unlock("123456") },
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			resp, err := call()
			assert.ErrorIs(t, err, ErrClientClosed)
			assert.Nil(t, resp)
		})
	}

	assert.Empty(t, handler.recorded(), "a closed client must not reach the server")
}

func TestEffectiveUIDAndDefaultSocketPath(t *testing.T) {
	t.Run("uses XDG_RUNTIME_DIR when set", func(t *testing.T) {
		t.Setenv("XDG_RUNTIME_DIR", "/run/user/4242")
		assert.Equal(t, "/run/user/4242/xkey/xkey.sock", DefaultSocketPath())
	})

	t.Run("falls back to a uid-scoped tmp directory", func(t *testing.T) {
		t.Setenv("XDG_RUNTIME_DIR", "")
		path := DefaultSocketPath()
		assert.Equal(t, filepath.Join("/tmp", "xkey-"+strconv.Itoa(effectiveUID()), "xkey.sock"), path)
	})

	t.Run("sudo uid is honoured only when running as root", func(t *testing.T) {
		t.Setenv("SUDO_UID", "4242")
		// effectiveUID only trusts SUDO_UID when the process is root; the
		// result must always be a real uid on this system.
		uid := effectiveUID()
		assert.True(t, uid >= 0)
	})
}

// TestDispatchAutofill_UnknownAction covers the dispatch table's defensive
// fallback. Message validation normally rejects unknown actions first, so this
// branch guards against a validator/dispatcher mismatch (an action accepted by
// Validate but absent from the dispatch map).
func TestDispatchAutofill_UnknownAction(t *testing.T) {
	t.Parallel()

	resp, err := dispatchAutofill(&fullHandler{}, &AutofillPayload{Action: "not-registered"})
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidMessage)
	assert.Contains(t, err.Error(), "unknown autofill action")
}

func TestDispatchPairing_UnknownAction(t *testing.T) {
	t.Parallel()

	resp, err := dispatchPairing(&fullHandler{}, &PairingPayload{Action: "not-registered"})
	require.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidMessage)
	assert.Contains(t, err.Error(), "unknown pairing action")
}

func TestAutofillAndPairingOKResponses(t *testing.T) {
	t.Parallel()

	af := autofillOKResponse(&AutofillResult{Saved: true})
	assert.Equal(t, StatusOK, af.Status)
	require.NotNil(t, af.Autofill)
	assert.True(t, af.Autofill.Saved)
	assert.Empty(t, af.Error)

	pr := pairingOKResponse(&PairingResult{Acknowledged: true})
	assert.Equal(t, StatusOK, pr.Status)
	require.NotNil(t, pr.Pairing)
	assert.True(t, pr.Pairing.Acknowledged)
}

func TestSentinelCauseError_ErrorAndMatching(t *testing.T) {
	t.Parallel()

	cause := errors.New("bind: address already in use")
	err := &SentinelCauseError{Sentinel: ErrSocketCreateFailed, Cause: cause}

	assert.Equal(t, ErrSocketCreateFailed.Error()+": "+cause.Error(), err.Error())
	assert.ErrorIs(t, err, ErrSocketCreateFailed)
	assert.ErrorIs(t, err, cause)
	assert.NotErrorIs(t, err, ErrSocketPermission)
}

func TestWrappedError_ErrorAndMatching(t *testing.T) {
	t.Parallel()

	cause := errors.New("connection reset")
	err := &WrappedError{Msg: "read response", Err: cause}

	assert.Equal(t, "read response: connection reset", err.Error())
	assert.ErrorIs(t, err, cause)
	assert.NotErrorIs(t, err, ErrConnectionFailed)
}

// TestServer_HandlerErrorsPropagatePerAction verifies every action in the
// autofill and pairing dispatch tables surfaces a handler failure as an error
// response instead of an empty success.
func TestServer_HandlerErrorsPropagatePerAction(t *testing.T) {
	autofillActions := []*AutofillPayload{
		{Action: ActionAutofillSearch, Domain: "example.com"},
		{Action: ActionAutofillGet, ID: "cred-1"},
		{Action: ActionAutofillTOTP, Domain: "example.com"},
		{Action: ActionAutofillTOTPByID, ID: "oath-1"},
		{Action: ActionAutofillStatus},
		{Action: ActionAutofillPolicy},
		{Action: ActionAutofillSave, Domain: "example.com", Username: "alice", Password: "s3cret"},
		{Action: ActionAutofillIgnoreDomain, Domain: "example.com"},
		{Action: ActionAutofillFocus},
	}

	for _, payload := range autofillActions {
		t.Run("autofill/"+payload.Action, func(t *testing.T) {
			handler := &fullHandler{failAction: payload.Action}
			_, socketPath := startFullTestServer(t, handler)

			resp := roundTrip(t, socketPath, &Message{Type: MessageTypeAutofill, Autofill: payload})
			assert.Equal(t, StatusError, resp.Status)
			assert.Contains(t, resp.Error, errFullHandler.Error())
			assert.Nil(t, resp.Autofill)
		})
	}

	pairingActions := []*PairingPayload{
		{Action: ActionPairingNotifyCode, Code: "123456"},
		{Action: ActionPairingCompleted, Origin: "chrome-extension://abc/"},
	}

	for _, payload := range pairingActions {
		t.Run("pairing/"+payload.Action, func(t *testing.T) {
			handler := &fullHandler{failAction: payload.Action}
			_, socketPath := startFullTestServer(t, handler)

			resp := roundTrip(t, socketPath, &Message{Type: MessageTypePairing, Pairing: payload})
			assert.Equal(t, StatusError, resp.Status)
			assert.Contains(t, resp.Error, errFullHandler.Error())
			assert.Nil(t, resp.Pairing)
		})
	}
}

// TestDispatchTable_ValidatesPayloadIndependently verifies each entry of the
// top-level dispatch table re-checks its payload. Message.Validate normally
// runs first, so these checks are the second line of defence for any caller
// that dispatches a message without validating it.
func TestDispatchTable_ValidatesPayloadIndependently(t *testing.T) {
	t.Parallel()

	handler := &fullHandler{}

	tests := []struct {
		name string
		msg  *Message
		want string
	}{
		{"autofill nil payload", &Message{Type: MessageTypeAutofill}, "autofill payload is required"},
		{"autofill invalid payload", &Message{Type: MessageTypeAutofill, Autofill: &AutofillPayload{}}, "action is required"},
		{"pairing nil payload", &Message{Type: MessageTypePairing}, "pairing payload is required"},
		{"pairing invalid payload", &Message{Type: MessageTypePairing, Pairing: &PairingPayload{}}, "pairing action is required"},
		{"unlock nil payload", &Message{Type: MessageTypeUnlock}, "unlock payload is required"},
		{"unlock invalid payload", &Message{Type: MessageTypeUnlock, Unlock: &UnlockPayload{}}, "pin is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, ok := handlers[tt.msg.Type]
			require.True(t, ok)

			resp, err := fn(handler, tt.msg)
			require.Error(t, err)
			assert.Nil(t, resp)
			assert.ErrorIs(t, err, ErrInvalidMessage)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	assert.Empty(t, handler.recorded(), "no invalid payload may reach a handler")
}

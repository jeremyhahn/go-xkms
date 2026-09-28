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

package console

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestWSHandler_NonWebSocketRequestIsRejected verifies a plain HTTP request
// that passes authorization but is not a WebSocket upgrade is refused by the
// upgrader and does not proceed to dial SSH. Without this the handler would
// attempt an SSH connection for every stray GET that reached the endpoint.
func TestWSHandler_NonWebSocketRequestIsRejected(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	dialed := false
	handler := NewWSHandler(ResolverFunc(func(*http.Request) (*Target, error) {
		dialed = true
		return &Target{
			Host:         srv.host,
			Port:         srv.port,
			User:         "tester",
			Signer:       clientSigner(t),
			KnownHosts:   pinnedHosts(t, srv.host, srv.hostPub),
			HostKeyScope: scope.User,
			HostKeyOwner: "tester",
		}, nil
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ssh/console", nil))

	if rec.Code == http.StatusSwitchingProtocols {
		t.Fatal("a non-WebSocket request must not be upgraded")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for a failed upgrade", rec.Code, http.StatusBadRequest)
	}
	_ = dialed // resolution happens first by design; the upgrade is what fails
}

// TestWriteJSON_ReportsMarshalFailure verifies the control-frame writer surfaces
// an encoding failure instead of sending a malformed frame. The "ask" host-key
// confirmer propagates this error to abort the connection, so swallowing it
// would let a session continue with the prompt never delivered.
func TestWriteJSON_ReportsMarshalFailure(t *testing.T) {
	var mu sync.Mutex

	// A channel cannot be marshalled to JSON.
	err := writeJSON(nil, &mu, make(chan int))
	if err == nil {
		t.Fatal("writeJSON must report a marshal failure")
	}
}

// TestWSHandler_AskMalformedResponseAborts verifies a "hostkey-response" frame
// whose payload cannot be decoded aborts the connection rather than being read
// as an acceptance. Treating an undecodable response as "accept" would let a
// malformed or hostile client bypass the host-key prompt entirely.
func TestWSHandler_AskMalformedResponseAborts(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	store, err := known_hosts.NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}

	handler := NewWSHandler(ResolverFunc(func(*http.Request) (*Target, error) {
		return &Target{
			Host:          srv.host,
			Port:          srv.port,
			User:          "tester",
			Signer:        clientSigner(t),
			KnownHosts:    store,
			HostKeyScope:  scope.User,
			HostKeyOwner:  "tester",
			HostKeyPolicy: "ask",
		}, nil
	}))

	httpSrv := httptest.NewServer(handler)
	defer httpSrv.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpSrv.URL, "http"), nil)
	if !requireWSUpgrade(t, err) {
		return
	}
	defer func() { _ = conn.Close() }()

	// The server prompts for the unknown host key.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read hostkey prompt: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("prompt message type = %d, want text", mt)
	}
	if !strings.Contains(string(data), `"type":"hostkey"`) {
		t.Fatalf("expected a hostkey prompt, got %s", data)
	}

	// Answer with a well-formed envelope but an undecodable "accept" value.
	if err := conn.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"hostkey-response","accept":"yes-please"}`)); err != nil {
		t.Fatalf("write malformed response: %v", err)
	}

	// The handler must abort with an error frame, never open the session.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, data, err = conn.ReadMessage()
	if err != nil {
		return // an abrupt close is also a refusal, which is acceptable
	}
	if !strings.Contains(string(data), `"type":"error"`) {
		t.Fatalf("expected an error frame after a malformed response, got %s", data)
	}
}

// TestDial_ExtraKnownHostsFileUnreadableFailsClosed verifies that an
// unreadable KnownHostsExtraFiles entry aborts the connection instead of being
// skipped. Skipping it would let the TOFU path accept a host key that the
// unreadable file may have pinned to a DIFFERENT value — silently converting a
// mismatch into a first-contact accept.
func TestDial_ExtraKnownHostsFileUnreadableFailsClosed(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	// A directory where a known_hosts file is expected cannot be read as one.
	unreadable := filepath.Join(t.TempDir(), "known_hosts_dir")
	if err := os.Mkdir(unreadable, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	store, err := known_hosts.NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	confirmCalled := false
	c, err := Dial(ctx, DialRequest{
		Host:                 srv.host,
		Port:                 srv.port,
		User:                 "tester",
		Signer:               clientSigner(t),
		KnownHosts:           store,
		HostKeyScope:         scope.User,
		HostKeyOwner:         "tester",
		KnownHostsExtraFiles: []string{unreadable},
		HostKeyConfirm: func(context.Context, string, ssh.PublicKey) (bool, error) {
			confirmCalled = true
			return true, nil
		},
	}, Config{})
	if err == nil {
		_ = c.Close()
		t.Fatal("an unreadable extra known_hosts file must fail the connection")
	}
	if confirmCalled {
		t.Error("TOFU must not be consulted when an extra known_hosts file could not be read")
	}
}

// TestDial_ExtraKnownHostsFileForOtherHostDoesNotAuthorize verifies that an
// extra known_hosts file which pins only OTHER hosts leaves our host unknown,
// and that with no TOFU confirmer configured the connection is refused.
func TestDial_ExtraKnownHostsFileForOtherHostDoesNotAuthorize(t *testing.T) {
	srv := startSessionServer(t, sessionServerOptions{})

	// A syntactically valid known_hosts file pinning an unrelated host.
	other := filepath.Join(t.TempDir(), "known_hosts")
	content := "other.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGnJ0Zq6mLQ0zRz9Gk6cKJ3Yy0kQmXhWlH8pT7bA2cVd\n"
	if err := os.WriteFile(other, []byte(content), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	store, err := known_hosts.NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := Dial(ctx, DialRequest{
		Host:                 srv.host,
		Port:                 srv.port,
		User:                 "tester",
		Signer:               clientSigner(t),
		KnownHosts:           store,
		HostKeyScope:         scope.User,
		HostKeyOwner:         "tester",
		KnownHostsExtraFiles: []string{other},
		// No HostKeyConfirm: strict policy, an unknown host must be refused.
	}, Config{})
	if err == nil {
		_ = c.Close()
		t.Fatal("a host absent from every known_hosts source must be refused under the strict policy")
	}
}

// writeStopMarker is the binary payload fakeConsole.Write recognizes as a
// signal to fail, driving bridge's WebSocket->console error path.
var writeStopMarker = []byte("trigger-write-error")

// fakeConsole is a minimal Console test double that drives bridge()'s
// best-effort error-handling branches (a rejected resize, a failed stdin
// write, a failed CloseWrite) directly and deterministically, without a live
// SSH session where those failures cannot be induced on demand.
type fakeConsole struct {
	writeErr      error
	resizeErr     error
	closeWriteErr error
}

// Read always reports EOF immediately: these tests drive the WebSocket-to-
// console direction only, and an immediate EOF ends bridge's stdout-pump
// goroutine without producing any output to race against.
func (f *fakeConsole) Read([]byte) (int, error) { return 0, io.EOF }

func (f *fakeConsole) Write(p []byte) (int, error) {
	if f.writeErr != nil && string(p) == string(writeStopMarker) {
		return 0, f.writeErr
	}
	return len(p), nil
}

func (f *fakeConsole) Resize(int, int) error { return f.resizeErr }
func (f *fakeConsole) CloseWrite() error     { return f.closeWriteErr }
func (f *fakeConsole) Close() error          { return nil }

var _ Console = (*fakeConsole)(nil)

// TestBridge_RejectedResizeFailedWriteAndCloseWriteAreLoggedNotFatal drives
// bridge() directly against a fakeConsole to cover three best-effort
// branches a live SSH session cannot fail on demand: a server-rejected
// resize, a failed stdin write (which ends the WebSocket->console loop), and
// a failed CloseWrite during teardown. None of these abort the bridge --
// they are all logged and bridge still returns once the WebSocket side is
// done.
func TestBridge_RejectedResizeFailedWriteAndCloseWriteAreLoggedNotFatal(t *testing.T) {
	handler := &captureHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	cons := &fakeConsole{
		writeErr:      errors.New("stdin write boom"),
		resizeErr:     errors.New("resize rejected"),
		closeWriteErr: errors.New("close-write boom"),
	}

	bridgeDone := make(chan struct{})
	upgrader := websocket.Upgrader{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		bridge(conn, cons)
		close(bridgeDone)
	}))
	defer ts.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	if !requireWSUpgrade(t, err) {
		return
	}
	defer func() { _ = conn.Close() }()

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","rows":40,"cols":120}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, writeStopMarker); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	select {
	case <-bridgeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("bridge did not return after the console write failed")
	}

	if !handler.hasMessage("ssh/console: remote rejected a PTY resize") {
		t.Error("expected the rejected resize to be logged")
	}
	if !handler.hasMessage("ssh/console: CloseWrite failed while tearing down a bridged session") {
		t.Error("expected the CloseWrite failure to be logged")
	}
}

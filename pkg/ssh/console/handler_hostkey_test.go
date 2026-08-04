// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/known_hosts"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// freshHostStore returns a Store with NO pin for any host — used to exercise
// the WebSocket hostkey confirmation flow (Callback would otherwise reject
// the connection outright, per known_hosts.CallbackWithConfirm semantics).
func freshHostStore(t *testing.T) known_hosts.Store {
	t.Helper()
	store, err := known_hosts.NewBackendStore(storage.New())
	if err != nil {
		t.Fatalf("known_hosts store: %v", err)
	}
	return store
}

// dialWS dials the WebSocket endpoint under test.
func dialWS(t *testing.T, ts *httptest.Server) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	return conn
}

// readEcho drains BinaryMessage frames until want appears (or the deadline
// set on conn expires), returning everything read so far.
func readEcho(t *testing.T, conn *websocket.Conn, want string) string {
	t.Helper()
	var got strings.Builder
	for i := 0; i < 20; i++ {
		mt, data, rerr := conn.ReadMessage()
		if rerr != nil {
			t.Fatalf("read: %v (so far %q)", rerr, got.String())
		}
		if mt == websocket.BinaryMessage {
			got.Write(data)
			if strings.Contains(got.String(), want) {
				break
			}
		}
	}
	return got.String()
}

// TestWSHandler_AskAccept covers the "ask" policy's happy path: the client
// receives a well-formed "hostkey" confirm frame, replies accept:true, the
// session proceeds normally, and the pin ends up in the store.
func TestWSHandler_AskAccept(t *testing.T) {
	srv := startEchoSSHServer(t)
	store := freshHostStore(t)
	signer := clientSigner(t)

	resolver := ResolverFunc(func(_ *http.Request) (*Target, error) {
		return &Target{
			Host:          srv.host,
			Port:          srv.port,
			User:          "tester",
			Signer:        signer,
			KnownHosts:    store,
			HostKeyScope:  scope.User,
			HostKeyOwner:  "tester",
			HostKeyPolicy: "ask",
			Config:        Config{Rows: 24, Cols: 80},
		}, nil
	})
	ts := httptest.NewServer(NewWSHandler(resolver, WithCheckOrigin(func(*http.Request) bool { return true })))
	defer ts.Close()

	conn := dialWS(t, ts)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read hostkey frame: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("expected TEXT hostkey frame, got message type %d", mt)
	}
	raw := string(data)
	if !strings.Contains(raw, `"key_type"`) {
		t.Fatalf("wire frame must use snake_case key_type, got %s", raw)
	}
	if !strings.Contains(raw, `"known":false`) {
		t.Fatalf("wire frame must always carry known (no omitempty), got %s", raw)
	}
	var msg hostKeyMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal hostkey frame: %v", err)
	}
	if msg.Type != "hostkey" || msg.Mode != "confirm" || msg.Known {
		t.Fatalf("unexpected hostkey frame: %+v", msg)
	}
	if msg.Host != srv.host {
		t.Fatalf("hostkey frame host mismatch: got %q want %q", msg.Host, srv.host)
	}
	if msg.KeyType != "ssh-ed25519" {
		t.Fatalf("unexpected key_type: %q", msg.KeyType)
	}
	if msg.Fingerprint == "" {
		t.Fatal("hostkey frame missing fingerprint")
	}

	resp, _ := json.Marshal(hostKeyResponse{Type: "hostkey-response", Accept: true})
	if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
		t.Fatalf("write hostkey-response: %v", err)
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("ping123\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if got := readEcho(t, conn, "ping123"); !strings.Contains(got, "ping123") {
		t.Fatalf("did not receive echo, got %q", got)
	}

	if _, gerr := store.Get(context.Background(), scope.User, "tester", srv.host); gerr != nil {
		t.Fatalf("expected pin to exist after accept: %v", gerr)
	}
}

// TestWSHandler_AskAccept_IgnoresUnrelatedFramesWhileWaiting covers
// awaitHostKeyResponse's "ignore anything that isn't a hostkey-response text
// frame" branches: a stray binary frame and an unrelated text control frame
// arrive before the real reply, and must not derail the wait.
func TestWSHandler_AskAccept_IgnoresUnrelatedFramesWhileWaiting(t *testing.T) {
	srv := startEchoSSHServer(t)
	store := freshHostStore(t)
	signer := clientSigner(t)

	resolver := ResolverFunc(func(_ *http.Request) (*Target, error) {
		return &Target{
			Host:          srv.host,
			Port:          srv.port,
			User:          "tester",
			Signer:        signer,
			KnownHosts:    store,
			HostKeyScope:  scope.User,
			HostKeyOwner:  "tester",
			HostKeyPolicy: "ask",
			Config:        Config{Rows: 24, Cols: 80},
		}, nil
	})
	ts := httptest.NewServer(NewWSHandler(resolver, WithCheckOrigin(func(*http.Request) bool { return true })))
	defer ts.Close()

	conn := dialWS(t, ts)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read hostkey frame: %v", err)
	}

	// A stray binary frame (would be terminal input on a live session, but
	// bridge() has not started yet — Dial owns the only reader) and an
	// unrelated text control frame must both be ignored while waiting.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("premature input")); err != nil {
		t.Fatalf("write stray binary frame: %v", err)
	}
	stray, _ := json.Marshal(controlMessage{Type: "resize", Rows: 10, Cols: 10})
	if err := conn.WriteMessage(websocket.TextMessage, stray); err != nil {
		t.Fatalf("write stray text frame: %v", err)
	}

	resp, _ := json.Marshal(hostKeyResponse{Type: "hostkey-response", Accept: true})
	if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
		t.Fatalf("write hostkey-response: %v", err)
	}

	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("ping123\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if got := readEcho(t, conn, "ping123"); !strings.Contains(got, "ping123") {
		t.Fatalf("did not receive echo, got %q", got)
	}
}

// TestWSHandler_AskReject covers the "ask" policy's decline path: replying
// accept:false surfaces the existing error-frame + close path, and no pin
// is written.
func TestWSHandler_AskReject(t *testing.T) {
	srv := startEchoSSHServer(t)
	store := freshHostStore(t)
	signer := clientSigner(t)

	resolver := ResolverFunc(func(_ *http.Request) (*Target, error) {
		return &Target{
			Host:          srv.host,
			Port:          srv.port,
			User:          "tester",
			Signer:        signer,
			KnownHosts:    store,
			HostKeyScope:  scope.User,
			HostKeyOwner:  "tester",
			HostKeyPolicy: "ask",
		}, nil
	})
	ts := httptest.NewServer(NewWSHandler(resolver, WithCheckOrigin(func(*http.Request) bool { return true })))
	defer ts.Close()

	conn := dialWS(t, ts)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read hostkey frame: %v", err)
	}

	resp, _ := json.Marshal(hostKeyResponse{Type: "hostkey-response", Accept: false})
	if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
		t.Fatalf("write hostkey-response: %v", err)
	}

	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("expected TEXT error frame, got message type %d", mt)
	}
	var ctrl controlMessage
	if err := json.Unmarshal(data, &ctrl); err != nil {
		t.Fatalf("unmarshal error frame: %v", err)
	}
	if ctrl.Type != "error" {
		t.Fatalf("expected error control frame, got %+v", ctrl)
	}
	if !strings.Contains(ctrl.Message, "rejected") {
		t.Fatalf("expected a rejection error message, got %q", ctrl.Message)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected the connection to close after rejection")
	}

	if _, gerr := store.Get(context.Background(), scope.User, "tester", srv.host); gerr == nil {
		t.Fatal("no pin must be written on rejection")
	}
}

// TestWSHandler_AskTimeout covers the bounded-wait branch: with a short
// WithHostKeyConfirmTimeout and no client reply, the connection closes
// within the configured bound and no pin is written.
func TestWSHandler_AskTimeout(t *testing.T) {
	srv := startEchoSSHServer(t)
	store := freshHostStore(t)
	signer := clientSigner(t)

	resolver := ResolverFunc(func(_ *http.Request) (*Target, error) {
		return &Target{
			Host:          srv.host,
			Port:          srv.port,
			User:          "tester",
			Signer:        signer,
			KnownHosts:    store,
			HostKeyScope:  scope.User,
			HostKeyOwner:  "tester",
			HostKeyPolicy: "ask",
		}, nil
	})
	const timeout = 300 * time.Millisecond
	ts := httptest.NewServer(NewWSHandler(resolver,
		WithCheckOrigin(func(*http.Request) bool { return true }),
		WithHostKeyConfirmTimeout(timeout),
	))
	defer ts.Close()

	conn := dialWS(t, ts)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read hostkey frame: %v", err)
	}

	start := time.Now()
	// Never reply. Bound the assertion comfortably above the configured
	// timeout so the test itself cannot flake on a slow CI runner, while
	// still proving the wait does not hang indefinitely.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	closed := false
	for i := 0; i < 5; i++ {
		if _, _, err := conn.ReadMessage(); err != nil {
			closed = true
			break
		}
	}
	if !closed {
		t.Fatal("expected the connection to error/close after the confirm timeout elapsed")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout bound not honored: took %v", elapsed)
	}

	if _, gerr := store.Get(context.Background(), scope.User, "tester", srv.host); gerr == nil {
		t.Fatal("no pin must be written on a confirm timeout")
	}
}

// TestWSHandler_AcceptNew covers the "accept-new" policy: the client
// receives a "notify" mode frame (no reply expected), the session proceeds
// immediately, and the pin is written.
func TestWSHandler_AcceptNew(t *testing.T) {
	srv := startEchoSSHServer(t)
	store := freshHostStore(t)
	signer := clientSigner(t)

	resolver := ResolverFunc(func(_ *http.Request) (*Target, error) {
		return &Target{
			Host:          srv.host,
			Port:          srv.port,
			User:          "tester",
			Signer:        signer,
			KnownHosts:    store,
			HostKeyScope:  scope.User,
			HostKeyOwner:  "tester",
			HostKeyPolicy: "accept-new",
			Config:        Config{Rows: 24, Cols: 80},
		}, nil
	})
	ts := httptest.NewServer(NewWSHandler(resolver, WithCheckOrigin(func(*http.Request) bool { return true })))
	defer ts.Close()

	conn := dialWS(t, ts)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read notify frame: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("expected TEXT notify frame, got message type %d", mt)
	}
	var msg hostKeyMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal notify frame: %v", err)
	}
	if msg.Mode != "notify" {
		t.Fatalf("expected mode=notify, got %+v", msg)
	}
	if msg.Known {
		t.Fatalf("expected known=false, got %+v", msg)
	}

	// No reply sent — the session must proceed regardless.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("ping123\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if got := readEcho(t, conn, "ping123"); !strings.Contains(got, "ping123") {
		t.Fatalf("did not receive echo, got %q", got)
	}

	if _, gerr := store.Get(context.Background(), scope.User, "tester", srv.host); gerr != nil {
		t.Fatalf("expected pin written under accept-new: %v", gerr)
	}
}

// TestWSHandler_StrictDefaultRegression proves the zero-value Target
// (HostKeyPolicy unset) reproduces today's behavior exactly: an unpinned
// host fails immediately with no hostkey prompt of any kind, and no pin is
// written.
func TestWSHandler_StrictDefaultRegression(t *testing.T) {
	srv := startEchoSSHServer(t)
	store := freshHostStore(t)
	signer := clientSigner(t)

	resolver := ResolverFunc(func(_ *http.Request) (*Target, error) {
		return &Target{
			Host:         srv.host,
			Port:         srv.port,
			User:         "tester",
			Signer:       signer,
			KnownHosts:   store,
			HostKeyScope: scope.User,
			HostKeyOwner: "tester",
			// HostKeyPolicy intentionally left at its zero value.
		}, nil
	})
	ts := httptest.NewServer(NewWSHandler(resolver, WithCheckOrigin(func(*http.Request) bool { return true })))
	defer ts.Close()

	conn := dialWS(t, ts)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read error frame: %v", err)
	}
	if mt != websocket.TextMessage {
		t.Fatalf("expected TEXT error frame, got message type %d", mt)
	}
	var ctrl controlMessage
	if err := json.Unmarshal(data, &ctrl); err != nil {
		t.Fatalf("unmarshal error frame: %v", err)
	}
	if ctrl.Type != "error" {
		t.Fatalf("expected error control frame for an unpinned strict host, got %+v", ctrl)
	}

	if _, gerr := store.Get(context.Background(), scope.User, "tester", srv.host); gerr == nil {
		t.Fatal("no pin must be written for a strict-policy failure")
	}
}

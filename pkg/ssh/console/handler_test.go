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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

func TestWSHandler_BridgeEchoAndResize(t *testing.T) {
	srv := startEchoSSHServer(t)
	store := pinnedHosts(t, srv.host, srv.hostPub)
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
			Config:       Config{Rows: 24, Cols: 80},
		}, nil
	})

	ts := httptest.NewServer(NewWSHandler(resolver, WithCheckOrigin(func(*http.Request) bool { return true })))
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer conn.Close()

	// Type via a binary frame; expect the echo back as binary.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("ping123\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got strings.Builder
	for i := 0; i < 20; i++ {
		mt, data, rerr := conn.ReadMessage()
		if rerr != nil {
			t.Fatalf("read: %v (so far: %q)", rerr, got.String())
		}
		if mt == websocket.BinaryMessage {
			got.Write(data)
			if strings.Contains(got.String(), "ping123") {
				break
			}
		}
	}
	if !strings.Contains(got.String(), "ping123") {
		t.Fatalf("did not receive echo, got %q", got.String())
	}

	// Resize control frame must be accepted without error.
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","rows":40,"cols":120}`)); err != nil {
		t.Fatalf("write resize: %v", err)
	}
	// Round-trip another echo to confirm the session is still live post-resize.
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("after-resize\n")); err != nil {
		t.Fatalf("write after resize: %v", err)
	}
	got.Reset()
	for i := 0; i < 20; i++ {
		mt, data, rerr := conn.ReadMessage()
		if rerr != nil {
			t.Fatalf("read after resize: %v", rerr)
		}
		if mt == websocket.BinaryMessage {
			got.Write(data)
			if strings.Contains(got.String(), "after-resize") {
				break
			}
		}
	}
	if !strings.Contains(got.String(), "after-resize") {
		t.Fatalf("session dead after resize, got %q", got.String())
	}
}

func TestWSHandler_ResolverRejectBeforeUpgrade(t *testing.T) {
	resolver := ResolverFunc(func(_ *http.Request) (*Target, error) {
		return nil, &InputError{Field: "unauthorized"}
	})
	ts := httptest.NewServer(NewWSHandler(resolver, WithCheckOrigin(func(*http.Request) bool { return true })))
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected dial failure when resolver rejects")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %v", resp)
	}
}

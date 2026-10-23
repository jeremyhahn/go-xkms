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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
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
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if !requireWSUpgrade(t, resp, err) {
		return
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

// TestUpgradeWS_RefusesSHA1UnderFIPSOtherwiseUpgrades checks that upgradeWS
// returns the typed refusal and answers 501 when the standard library refuses
// the SHA-1 RFC 6455 §4.2.2 requires (GODEBUG=fips140=only), and completes the
// upgrade outside it.
func TestUpgradeWS_RefusesSHA1UnderFIPSOtherwiseUpgrades(t *testing.T) {
	serverErr := make(chan error, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgradeWS(&websocket.Upgrader{}, w, r)
		serverErr <- err
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer ts.Close()

	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	if !fipstest.OutsideFIPSAfterRefusal(t, <-serverErr, &UpgradeRefusedError{}) {
		if resp == nil || resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("refused upgrade: dial err = %v, want a %d response", err, http.StatusNotImplemented)
		}
		return
	}
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	_ = conn.Close()
}

// TestUpgradeWS_NonWebSocketRequestKeepsBadRequest checks that a request that
// is not a WebSocket handshake gets gorilla's 400 in every FIPS mode, since it
// never reaches SHA-1.
func TestUpgradeWS_NonWebSocketRequestKeepsBadRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	conn, err := upgradeWS(&websocket.Upgrader{}, rec, httptest.NewRequest(http.MethodGet, "/ssh/console", nil))
	if err == nil {
		_ = conn.Close()
		t.Fatal("a non-WebSocket request must not be upgraded")
	}
	if errors.Is(err, &UpgradeRefusedError{}) {
		t.Fatalf("err = %v, want gorilla's handshake error, not a SHA-1 refusal", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestUpgradeRefusedError_MatchesAnyRefusalAndUnwraps checks errors.Is and
// errors.Unwrap on the typed refusal.
func TestUpgradeRefusedError_MatchesAnyRefusalAndUnwraps(t *testing.T) {
	cause := errors.New("crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode")
	err := error(&UpgradeRefusedError{Err: cause})

	if !errors.Is(err, &UpgradeRefusedError{}) {
		t.Error("errors.Is must match any *UpgradeRefusedError")
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is must reach the standard library's refusal")
	}
	if errors.Is(err, &ClosedError{}) {
		t.Error("errors.Is must not match an unrelated typed error")
	}
	if want := "ssh/console: websocket upgrade refused: " + cause.Error(); err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}

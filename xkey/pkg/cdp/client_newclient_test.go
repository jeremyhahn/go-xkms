// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostPort splits an httptest server's URL into the host and port NewClient
// and discoverWebSocketURL expect as separate arguments.
func hostPort(t *testing.T, serverURL string) (string, int) {
	t.Helper()
	addr := strings.TrimPrefix(serverURL, "http://")
	parts := strings.SplitN(addr, ":", 2)
	port, err := strconv.Atoi(parts[1])
	require.NoError(t, err)
	return parts[0], port
}

// --- findPageTarget ---

// TestFindPageTarget_ReturnsFirstPageTarget pins the success path: given a
// /json listing with a non-page target ahead of a page target, the page
// target's WebSocket URL is what gets returned.
func TestFindPageTarget_ReturnsFirstPageTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[
			{"id":"1","type":"browser","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/x"},
			{"id":"2","type":"page","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/2"}
		]`)
	}))
	defer srv.Close()

	url, err := findPageTarget(srv.URL)

	require.NoError(t, err)
	assert.Equal(t, "ws://127.0.0.1:9222/devtools/page/2", url)
}

// TestFindPageTarget_NoPageTargets pins the empty-list refusal: page targets
// exist in neither shape nor number, so the caller must fall back to
// creating one.
func TestFindPageTarget_NoPageTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"id":"1","type":"browser","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/x"}]`)
	}))
	defer srv.Close()

	_, err := findPageTarget(srv.URL)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPWebSocketURLNotFound))
}

// --- createBlankTarget ---

// TestCreateBlankTarget_MissingWebSocketURL pins the refusal when Chrome's
// /json/new response carries no usable WebSocket URL.
func TestCreateBlankTarget_MissingWebSocketURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"3","type":"page"}`)
	}))
	defer srv.Close()

	_, err := createBlankTarget(srv.URL)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPWebSocketURLNotFound))
}

// --- NewClient ---

// TestNewClient_Success drives the whole constructor: discover the
// WebSocket URL from /json, dial it, and start the read loop.
func TestNewClient_Success(t *testing.T) {
	mux := http.NewServeMux()
	var wsURL string

	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[{"id":"1","type":"page","webSocketDebuggerUrl":%q}]`, wsURL)
	})

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	mux.HandleFunc("/devtools/page/1", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	wsURL = "ws" + strings.TrimPrefix(srv.URL, "http") + "/devtools/page/1"

	host, port := hostPort(t, srv.URL)

	client, err := NewClient(host, port, testLogger())
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()
}

// TestNewClient_DiscoveryFailure pins that a discovery failure (no server
// listening at all) is returned as-is, before any dial is attempted.
func TestNewClient_DiscoveryFailure(t *testing.T) {
	client, err := NewClient("127.0.0.1", 1, testLogger())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPVersionFetchFailed))
	assert.Nil(t, client)
}

// TestNewClient_DialFailure pins the connection-failed wrap: discovery
// succeeds (a page target is found) but the returned URL cannot be dialed.
func TestNewClient_DialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[{"id":"1","type":"page","webSocketDebuggerUrl":"ws://127.0.0.1:1/nothing-here"}]`)
	}))
	defer srv.Close()

	host, port := hostPort(t, srv.URL)

	client, err := NewClient(host, port, testLogger())

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCDPConnectionFailed))
	assert.Nil(t, client)
}

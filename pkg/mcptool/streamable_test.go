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

package mcptool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	mcptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initRequest() mcptransport.JSONRPCRequest {
	return mcptransport.JSONRPCRequest{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      mcp.NewRequestId(int64(1)),
		Method:  string(mcp.MethodInitialize),
	}
}

func TestStreamableHTTP_EventStreamSessionAndClose(t *testing.T) {
	var mu sync.Mutex
	var deleted, sessionOnPing, versionOnPing, custom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodDelete:
			deleted = r.Header.Get(headerSessionID)
			w.WriteHeader(http.StatusOK)
		case http.MethodPost:
			if r.Header.Get(headerSessionID) == "" {
				custom = r.Header.Get("X-Custom")
				w.Header().Set(headerSessionID, "sess-1")
				w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
				_, _ = w.Write([]byte(": comment\nevent: message\n" +
					"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\"}}\n\n" +
					"data: not json\n\n" +
					"data: {\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"sampling/createMessage\"}\n\n" +
					"data: {\"jsonrpc\":\"2.0\",\"id\":1,\n" +
					"data: \"result\":{\"ok\":true}}\n\n"))
				return
			}
			sessionOnPing = r.Header.Get(headerSessionID)
			versionOnPing = r.Header.Get(headerProtocolVersion)
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	defer srv.Close()

	tr := newStreamableHTTP(srv.URL, http.DefaultTransport, map[string]string{"X-Custom": "v"})
	var notes []string
	tr.SetNotificationHandler(func(n mcp.JSONRPCNotification) { notes = append(notes, n.Method) })
	require.NoError(t, tr.Start(context.Background()))

	resp, err := tr.SendRequest(context.Background(), initRequest())
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true}`, string(resp.Result))
	assert.Equal(t, []string{"notifications/message"}, notes)
	assert.Equal(t, "sess-1", tr.GetSessionId())

	tr.SetProtocolVersion("2025-06-18")
	require.NoError(t, tr.SendNotification(context.Background(), mcp.JSONRPCNotification{
		JSONRPC:      mcp.JSONRPC_VERSION,
		Notification: mcp.Notification{Method: "notifications/initialized"},
	}))
	require.NoError(t, tr.Close())
	require.NoError(t, tr.Close(), "Close is idempotent")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "v", custom)
	assert.Equal(t, "sess-1", sessionOnPing)
	assert.Equal(t, "2025-06-18", versionOnPing)
	assert.Equal(t, "sess-1", deleted)

	_, err = tr.SendRequest(context.Background(), initRequest())
	assert.ErrorIs(t, err, errTransportClosed)
}

func TestStreamableHTTP_RejectsBadResponses(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"status": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"content type": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("hello"))
		},
		"bad json": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{"))
		},
		"not a response": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","method":"ping"}`))
		},
		"stream without response": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n"))
		},
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			tr := newStreamableHTTP(srv.URL, http.DefaultTransport, nil)
			_, err := tr.SendRequest(context.Background(), initRequest())
			assert.Error(t, err)
		})
	}
}

func TestStreamableHTTP_NotificationErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	note := mcp.JSONRPCNotification{JSONRPC: mcp.JSONRPC_VERSION, Notification: mcp.Notification{Method: "x"}}

	tr := newStreamableHTTP(srv.URL, http.DefaultTransport, nil)
	assert.Error(t, tr.SendNotification(context.Background(), note), "a 400 is refused")

	bad := newStreamableHTTP("http://[::1", http.DefaultTransport, nil)
	assert.Error(t, bad.SendNotification(context.Background(), note), "an invalid URL fails before dialing")
	_, err := bad.SendRequest(context.Background(), mcptransport.JSONRPCRequest{Params: func() {}})
	assert.Error(t, err, "an unencodable message fails before dialing")
}

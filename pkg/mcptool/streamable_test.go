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
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

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

// TestStreamableHTTP_CloseCancelsBlockedRequests: Close ends a request whose
// response is blocked, both before the headers arrive and in the middle of an
// event stream. The call returns promptly with errTransportClosed, and the
// connection is torn down, so the server handler sees its request end too:
// nothing is left waiting on the server.
func TestStreamableHTTP_CloseCancelsBlockedRequests(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stream bool
	}{
		{name: "before headers"},
		{name: "mid event stream", stream: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{})
			released := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					w.WriteHeader(http.StatusOK)
					return
				}
				// A drained body lets the server watch the connection, so
				// r.Context ends when the client drops it.
				_, _ = io.Copy(io.Discard, r.Body)
				if tc.stream {
					w.Header().Set("Content-Type", contentTypeEventFeed)
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(": waiting\n\n"))
					w.(http.Flusher).Flush()
				}
				close(entered)
				<-r.Context().Done()
				close(released)
			}))
			// Dropping the connections first lets a failing run end instead of
			// waiting on the blocked handler.
			defer func() { srv.CloseClientConnections(); srv.Close() }()

			tr := newStreamableHTTP(srv.URL, http.DefaultTransport, nil)
			errc := make(chan error, 1)
			go func() {
				_, err := tr.SendRequest(context.Background(), initRequest())
				errc <- err
			}()

			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("the request never reached the server")
			}
			closed := make(chan error, 1)
			go func() { closed <- tr.Close() }()
			select {
			case err := <-closed:
				require.NoError(t, err)
			case <-time.After(2 * time.Second):
				t.Fatal("Close blocked behind the in-flight request")
			}

			select {
			case err := <-errc:
				require.Error(t, err)
				assert.ErrorIs(t, err, errTransportClosed)
			case <-time.After(2 * time.Second):
				t.Fatal("the blocked request outlived Close")
			}
			select {
			case <-released:
			case <-time.After(2 * time.Second):
				t.Fatal("the server handler still holds the request after Close")
			}
		})
	}
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

// TestStreamableHTTP_ResponsesCarryTheRequestID pins response correlation: a
// JSON-RPC response is the request's result only when its wire ID matches
// the request's ID. A JSON body with a mismatched, missing or null ID is an
// error; on an event stream an unrelated response is skipped, and a stream
// with no matching response is an error.
func TestStreamableHTTP_ResponsesCarryTheRequestID(t *testing.T) {
	jsonBody := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}
	}
	eventStream := func(bodies ...string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			for _, body := range bodies {
				_, _ = w.Write([]byte("data: " + body + "\n\n"))
			}
		}
	}
	send := func(t *testing.T, handler http.HandlerFunc, request mcptransport.JSONRPCRequest) (*mcptransport.JSONRPCResponse, error) {
		t.Helper()
		srv := httptest.NewServer(handler)
		defer srv.Close()
		return newStreamableHTTP(srv.URL, http.DefaultTransport, nil).SendRequest(context.Background(), request)
	}

	rejected := map[string]http.HandlerFunc{
		"json mismatched id":   jsonBody(`{"jsonrpc":"2.0","id":2,"result":{"which":"other"}}`),
		"json missing id":      jsonBody(`{"jsonrpc":"2.0","result":{"which":"other"}}`),
		"json null id":         jsonBody(`{"jsonrpc":"2.0","id":null,"result":{"which":"other"}}`),
		"json string for int":  jsonBody(`{"jsonrpc":"2.0","id":"1","result":{"which":"other"}}`),
		"stream mismatched id": eventStream(`{"jsonrpc":"2.0","id":2,"result":{"which":"other"}}`),
		"stream missing id":    eventStream(`{"jsonrpc":"2.0","result":{"which":"other"}}`),
		"stream null id":       eventStream(`{"jsonrpc":"2.0","id":null,"result":{"which":"other"}}`),
	}
	for name, handler := range rejected {
		t.Run(name, func(t *testing.T) {
			resp, err := send(t, handler, initRequest())
			assert.Error(t, err)
			assert.Nil(t, resp)
		})
	}

	accepted := map[string]http.HandlerFunc{
		"json matching id": jsonBody(`{"jsonrpc":"2.0","id":1,"result":{"which":"right"}}`),
		// JSON-RPC ids compare by value, not by spelling: 1, 1.0 and 1e0 are
		// the same number.
		"json id spelled 1.0":   jsonBody(`{"jsonrpc":"2.0","id":1.0,"result":{"which":"right"}}`),
		"json id spelled 1e0":   jsonBody(`{"jsonrpc":"2.0","id":1e0,"result":{"which":"right"}}`),
		"stream id spelled 1.0": eventStream(`{"jsonrpc":"2.0","id":2,"result":{"which":"other"}}`, `{"jsonrpc":"2.0","id":1.0,"result":{"which":"right"}}`),
		"stream skips unrelated responses": eventStream(
			`{"jsonrpc":"2.0","id":2,"result":{"which":"other"}}`,
			`{"jsonrpc":"2.0","result":{"which":"other"}}`,
			`{"jsonrpc":"2.0","id":null,"result":{"which":"other"}}`,
			`{"jsonrpc":"2.0","id":1,"result":{"which":"right"}}`,
		),
	}
	for name, handler := range accepted {
		t.Run(name, func(t *testing.T) {
			resp, err := send(t, handler, initRequest())
			require.NoError(t, err)
			assert.JSONEq(t, `{"which":"right"}`, string(resp.Result))
			id, err := resp.ID.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, "1", string(id))
		})
	}

	t.Run("string id matches", func(t *testing.T) {
		request := initRequest()
		request.ID = mcp.NewRequestId("req-7")
		resp, err := send(t, jsonBody(`{"jsonrpc":"2.0","id":"req-7","result":{"which":"right"}}`), request)
		require.NoError(t, err)
		assert.JSONEq(t, `{"which":"right"}`, string(resp.Result))
	})
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

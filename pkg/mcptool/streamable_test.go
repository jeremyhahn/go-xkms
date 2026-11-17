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
	"encoding/json"
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

// TestStreamableHTTP_MediaTypeIsCaseInsensitive pins RFC 9110 media-type
// matching: type and subtype compare case-insensitively and parameters such
// as charset are ignored, so a server spelling Application/JSON or
// Text/Event-Stream is answered like one spelling them in lower case.
func TestStreamableHTTP_MediaTypeIsCaseInsensitive(t *testing.T) {
	const response = `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`
	for _, tc := range []struct {
		contentType string
		body        string
	}{
		{contentType: "Application/JSON", body: response},
		{contentType: "Application/JSON; charset=utf-8", body: response},
		{contentType: "APPLICATION/json;Charset=UTF-8", body: response},
		{contentType: "Text/Event-Stream", body: "data: " + response + "\n\n"},
		{contentType: "Text/Event-Stream; charset=utf-8", body: "data: " + response + "\n\n"},
	} {
		t.Run(tc.contentType, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			resp, err := newStreamableHTTP(srv.URL, http.DefaultTransport, nil).SendRequest(context.Background(), initRequest())
			require.NoError(t, err)
			assert.JSONEq(t, `{"ok":true}`, string(resp.Result))
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

// TestStreamableHTTP_AnswersServerRequestsOnTheEventStream pins the verify13
// P1 on streamable.go's dispatchEvent: a server may send its own request
// (method + id) on a POST's event stream. The client answers ping with an
// empty result and every other method with a JSON-RPC method-not-found
// error, both on the same session; this fixture server completes the tool
// call only once both answers have arrived.
func TestStreamableHTTP_AnswersServerRequestsOnTheEventStream(t *testing.T) {
	type reply struct {
		body    map[string]any
		session string
	}
	replies := make(chan reply, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, isRequest := msg["method"]; !isRequest {
			replies <- reply{body: msg, session: r.Header.Get(headerSessionID)}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(`data: {"jsonrpc":"2.0","id":"srv-ping","method":"ping"}` + "\n\n"))
		_, _ = w.Write([]byte(`data: {"jsonrpc":"2.0","id":9,"method":"sampling/createMessage","params":{}}` + "\n\n"))
		w.(http.Flusher).Flush()
		got := map[string]reply{}
		for len(got) < 2 {
			select {
			case rep := <-replies:
				id, _ := json.Marshal(rep.body["id"])
				got[string(id)] = rep
			case <-time.After(10 * time.Second):
				return // ends the stream without a response: the call fails
			case <-r.Context().Done():
				return
			}
		}
		pingReply, otherReply := got[`"srv-ping"`], got[`9`]
		if pingReply.body == nil || otherReply.body == nil {
			return
		}
		replies <- pingReply
		replies <- otherReply
		_, _ = w.Write([]byte(`data: {"jsonrpc":"2.0","id":1,"result":{"done":true}}` + "\n\n"))
	}))
	defer srv.Close()

	tr := newStreamableHTTP(srv.URL, http.DefaultTransport, nil)
	tr.sessionID = "session-1"
	resp, err := tr.SendRequest(context.Background(), mcptransport.JSONRPCRequest{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      mcp.NewRequestId(int64(1)),
		Method:  string(mcp.MethodToolsCall),
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"done":true}`, string(resp.Result))

	pingReply, otherReply := <-replies, <-replies
	assert.Equal(t, "session-1", pingReply.session)
	assert.Equal(t, "session-1", otherReply.session)
	pingJSON, err := json.Marshal(pingReply.body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":"srv-ping","result":{}}`, string(pingJSON))
	assert.Equal(t, float64(9), otherReply.body["id"])
	assert.NotContains(t, otherReply.body, "result")
	errObj, ok := otherReply.body["error"].(map[string]any)
	require.True(t, ok, "a request for another method gets a JSON-RPC error: %v", otherReply.body)
	assert.Equal(t, float64(mcp.METHOD_NOT_FOUND), errObj["code"])
}

// TestStreamableHTTP_ValidatesResponseID proves a JSON or event-stream
// response is accepted only when its JSON-RPC version is 2.0 and its id is the
// outstanding request's id (1); a different, missing or null id, or another
// version, fails the call instead of answering it.
func TestStreamableHTTP_ValidatesResponseID(t *testing.T) {
	// An event stream may carry responses to other requests, which the
	// transport skips (TestStreamableHTTP_ResponsesCarryTheRequestID), so a
	// stream with no response for this id ends without one.
	const noneOnStream = "event stream ended without a response"
	bodies := map[string]struct {
		body     string
		wantJSON string
		wantSSE  string
	}{
		"matching id":   {body: `{"jsonrpc":"2.0","id":1,"result":{}}`},
		"different id":  {body: `{"jsonrpc":"2.0","id":2,"result":{}}`, wantJSON: "does not match", wantSSE: noneOnStream},
		"string id":     {body: `{"jsonrpc":"2.0","id":"1","result":{}}`, wantJSON: "does not match", wantSSE: noneOnStream},
		"missing id":    {body: `{"jsonrpc":"2.0","result":{}}`, wantJSON: "not a JSON-RPC response", wantSSE: noneOnStream},
		"null id":       {body: `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse"}}`, wantJSON: "not a JSON-RPC response", wantSSE: noneOnStream},
		"wrong version": {body: `{"jsonrpc":"1.0","id":1,"result":{}}`, wantJSON: "version", wantSSE: "version"},
		"no version":    {body: `{"id":1,"result":{}}`, wantJSON: "version", wantSSE: "version"},
	}
	encodings := map[string]func(string) (string, string){
		"json": func(b string) (string, string) { return "application/json", b },
		"sse":  func(b string) (string, string) { return "text/event-stream", "data: " + b + "\n\n" },
	}
	for enc, encode := range encodings {
		for name, tc := range bodies {
			t.Run(enc+"/"+name, func(t *testing.T) {
				contentType, payload := encode(tc.body)
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", contentType)
					_, _ = w.Write([]byte(payload))
				}))
				defer srv.Close()
				tr := newStreamableHTTP(srv.URL, http.DefaultTransport, nil)
				resp, err := tr.SendRequest(context.Background(), initRequest())
				want := tc.wantJSON
				if enc == "sse" {
					want = tc.wantSSE
				}
				if want == "" {
					require.NoError(t, err)
					assert.Equal(t, mcp.NewRequestId(int64(1)), resp.ID)
					return
				}
				require.Error(t, err)
				assert.Nil(t, resp)
				assert.Contains(t, err.Error(), want)
			})
		}
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

// TestStreamableHTTP_CloseInterruptsActiveRequests proves Close cancels a
// request whose response the server holds open, with a background context:
// a stalled response (no headers yet) and an unfinished event stream both
// return an error once the transport is closed (every request derives from
// the transport's lifetime context, which Close cancels).
func TestStreamableHTTP_CloseInterruptsActiveRequests(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter){
		"stalled response": func(http.ResponseWriter) {},
		"open event stream": func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n"))
			w.(http.Flusher).Flush()
		},
	}
	for name, start := range cases {
		t.Run(name, func(t *testing.T) {
			arrived := make(chan struct{})
			hold := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					return
				}
				start(w)
				close(arrived)
				select {
				case <-r.Context().Done():
				case <-hold:
				}
			}))
			defer srv.Close()
			defer close(hold)

			tr := newStreamableHTTP(srv.URL, http.DefaultTransport, nil)
			done := make(chan error, 1)
			go func() {
				_, err := tr.SendRequest(context.Background(), initRequest())
				done <- err
			}()
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("request never reached the server")
			}

			require.NoError(t, tr.Close())
			select {
			case err := <-done:
				assert.Error(t, err, "the held request fails once the transport is closed")
			case <-time.After(5 * time.Second):
				t.Fatal("Close left the active request running")
			}
		})
	}
}

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

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verbCase is one transport verb under test: the MCP method it must call,
// the request it sends, the answer the server gives, and the call itself.
type verbCase struct {
	method string
	req    any
	answer any
	call   func(context.Context, *Transport) (any, error)
}

// verb builds the verbCase of a request/response verb, with a request and an
// answer in which every field holds a value of its own.
func verb[Req, Resp any](method string, fn func(*Transport, context.Context, *Req) (*Resp, error)) verbCase {
	req, answer := filled[Req](), filled[Resp]()
	return verbCase{
		method: method,
		req:    req,
		answer: answer,
		call: func(ctx context.Context, tr *Transport) (any, error) {
			resp, err := fn(tr, ctx, req)
			if resp == nil {
				return nil, err
			}
			return resp, err
		},
	}
}

// filled returns a *T whose exported fields, nested ones included, each
// hold a distinct non-zero value, so a field dropped or swapped on the wire
// shows up as a difference.
func filled[T any]() *T {
	v := new(T)
	n := 0
	fill(reflect.ValueOf(v).Elem(), &n)
	return v
}

func fill(v reflect.Value, n *int) {
	*n++
	switch v.Kind() {
	case reflect.String:
		v.SetString(fmt.Sprintf("v%d", *n))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(*n))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(*n))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(*n) + 0.5)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem(), n)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fill(v.Index(0), n)
	case reflect.Map:
		key := reflect.New(v.Type().Key()).Elem()
		fill(key, n)
		val := reflect.New(v.Type().Elem()).Elem()
		fill(val, n)
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(key, val)
	case reflect.Struct:
		for i := range v.NumField() {
			field := v.Type().Field(i)
			if field.IsExported() && field.Tag.Get("json") != "-" {
				fill(v.Field(i), n)
			}
		}
	}
}

// verbRecorder keeps the params of the last call to each MCP method.
type verbRecorder struct {
	mu     sync.Mutex
	params map[string]json.RawMessage
}

func (r *verbRecorder) record(method string, params json.RawMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.params[method] = params
}

func (r *verbRecorder) paramsOf(method string) json.RawMessage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.params[method]
}

// connectToVerbServer connects a Transport to a mock MCP server whose tools
// answer through respond, once the health check of Connect has passed.
func connectToVerbServer(t *testing.T, respond func(req jsonrpcRequest) jsonrpcResponse) *Transport {
	t.Helper()
	addr, cleanup := startMockServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		if req.Method == "health" {
			return jsonrpcResponse{Result: []byte(`{"status":"ok"}`)}
		}
		return respond(req)
	})
	t.Cleanup(cleanup)
	tr := connectToMockServer(t, addr)
	t.Cleanup(func() { assert.NoError(t, tr.Close()) })
	return tr
}

// assertVerbsCallTheTool checks that each verb sends its request, field for
// field, as the params of its own MCP method, and decodes every field of the
// answer.
func assertVerbsCallTheTool(t *testing.T, cases map[string]verbCase) {
	t.Helper()
	answers := make(map[string]json.RawMessage, len(cases))
	for _, c := range cases {
		data, err := json.Marshal(c.answer)
		require.NoError(t, err)
		answers[c.method] = data
	}
	rec := &verbRecorder{params: map[string]json.RawMessage{}}
	tr := connectToVerbServer(t, func(req jsonrpcRequest) jsonrpcResponse {
		rec.record(req.Method, req.Params)
		return jsonrpcResponse{Result: answers[req.Method]}
	})
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := c.call(context.Background(), tr)
			require.NoError(t, err)
			assert.Equal(t, c.answer, got)
			want, err := json.Marshal(c.req)
			require.NoError(t, err)
			assert.JSONEq(t, string(want), string(rec.paramsOf(c.method)))
		})
	}
}

// assertVerbsServerRefusal checks that a tool refusal reaches the caller as
// an *RPCError carrying the translated code, with no result.
func assertVerbsServerRefusal(t *testing.T, cases map[string]verbCase) {
	t.Helper()
	tr := connectToVerbServer(t, func(jsonrpcRequest) jsonrpcResponse {
		return jsonrpcResponse{ErrorText: "key not found", Envelope: qrdbsdk.MCPCodeInvalidArgument}
	})
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := c.call(context.Background(), tr)
			var rpcErr *RPCError
			require.ErrorAs(t, err, &rpcErr)
			assert.Equal(t, xkmsmcp.ErrCodeInvalidParams, rpcErr.Code)
			assert.Equal(t, "key not found", rpcErr.Message)
			assert.Nil(t, got)
		})
	}
}

// assertVerbsRejectMalformedAnswer checks that an answer that is not JSON is
// an *UnmarshalError, never a zero-valued result.
func assertVerbsRejectMalformedAnswer(t *testing.T, cases map[string]verbCase) {
	t.Helper()
	tr := connectToVerbServer(t, func(jsonrpcRequest) jsonrpcResponse {
		return jsonrpcResponse{Result: []byte(`{"truncated":`)}
	})
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := c.call(context.Background(), tr)
			var unmarshalErr *UnmarshalError
			require.ErrorAs(t, err, &unmarshalErr)
			assert.Nil(t, got)
		})
	}
}

// assertVerbsNotConnected checks that each verb refuses to run before
// Connect, without a result.
func assertVerbsNotConnected(t *testing.T, cases map[string]verbCase) {
	t.Helper()
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := c.call(context.Background(), &Transport{})
			assert.ErrorIs(t, err, ErrNotConnected)
			assert.Nil(t, got)
		})
	}
}

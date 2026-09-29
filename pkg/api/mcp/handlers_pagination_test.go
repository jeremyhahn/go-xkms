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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListHandlers_MalformedPaginationParamsRejected proves that malformed
// JSON pagination params on the list* handlers are reported as Invalid
// params rather than being silently discarded and processed as an
// unpaginated "list everything" request (#701).
func TestListHandlers_MalformedPaginationParamsRejected(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	handlers := map[string]func(context.Context, *JSONRPCRequest) (interface{}, error){
		"xkms.listBackends": server.handleListBackends,
		"xkms.listKeys":     server.handleListKeys,
		"xkms.listCerts":    server.handleListCerts,
	}

	for method, handler := range handlers {
		t.Run(method, func(t *testing.T) {
			_, err := handler(context.Background(), &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  json.RawMessage(`{"page_size": "not-a-number"}`),
				ID:      1,
			})

			require.Error(t, err)
			var keyOp *KeyOpError
			require.True(t, errors.As(err, &keyOp), "%s: %T is not a KeyOpError", method, err)
			assert.Equal(t, ErrCodeInvalidParams, keyOp.Code)
		})
	}
}

// TestListHandlers_OmittedPaginationParamsStillWork proves the fix in
// TestListHandlers_MalformedPaginationParamsRejected did not regress the
// documented "no params" shape those same handlers must continue to accept.
func TestListHandlers_OmittedPaginationParamsStillWork(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	handlers := map[string]func(context.Context, *JSONRPCRequest) (interface{}, error){
		"xkms.listBackends": server.handleListBackends,
		"xkms.listKeys":     server.handleListKeys,
		"xkms.listCerts":    server.handleListCerts,
	}

	for method, handler := range handlers {
		t.Run(method, func(t *testing.T) {
			_, err := handler(context.Background(), &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				ID:      1,
			})
			require.NoError(t, err)
		})
	}
}

// TestListHandlers_NegativePaginationParamsRejected proves go-xkms#1262:
// unlike the REST and QUIC transports, these handlers decode a PageRequest
// directly from JSON-RPC params rather than through PageRequestFromQuery, so
// they used to hand a negative Page straight to ApplyPagination. ApplyPagination
// no longer panics on that input (see pagination_test.go), but a caller
// sending a negative page or page_size should still be told the request was
// invalid rather than have it silently reinterpreted, exactly like the REST
// transport's 400. transport.ValidatePageRequest is what gives all three
// handlers that same rejection.
func TestListHandlers_NegativePaginationParamsRejected(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	handlers := map[string]func(context.Context, *JSONRPCRequest) (interface{}, error){
		"xkms.listBackends": server.handleListBackends,
		"xkms.listKeys":     server.handleListKeys,
		"xkms.listCerts":    server.handleListCerts,
	}

	for _, tc := range []struct {
		name   string
		params string
	}{
		{"negative page", `{"page": -1}`},
		{"negative page_size", `{"page": 1, "page_size": -1}`},
	} {
		for method, handler := range handlers {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				_, err := handler(context.Background(), &JSONRPCRequest{
					JSONRPC: "2.0",
					Method:  method,
					Params:  json.RawMessage(tc.params),
					ID:      1,
				})

				require.Error(t, err)
				var keyOp *KeyOpError
				require.True(t, errors.As(err, &keyOp), "%s: %T is not a KeyOpError", method, err)
				assert.Equal(t, ErrCodeInvalidParams, keyOp.Code)
			})
		}
	}
}

// TestListHandlers_HugePaginationParamsDoNotPanic proves the overflow
// combination the issue reported does not reach a panic through this
// transport either: a huge page combined with a huge page_size is valid
// input (ValidatePageRequest only rejects negative values), so it must
// reach ApplyPagination's own overflow handling instead of a 500.
func TestListHandlers_HugePaginationParamsDoNotPanic(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	handlers := map[string]func(context.Context, *JSONRPCRequest) (interface{}, error){
		"xkms.listBackends": server.handleListBackends,
		"xkms.listKeys":     server.handleListKeys,
		"xkms.listCerts":    server.handleListCerts,
	}

	for method, handler := range handlers {
		t.Run(method, func(t *testing.T) {
			_, err := handler(context.Background(), &JSONRPCRequest{
				JSONRPC: "2.0",
				Method:  method,
				Params:  json.RawMessage(`{"page": 9223372036854775807, "page_size": 9223372036854775807}`),
				ID:      1,
			})
			require.NoError(t, err)
		})
	}
}

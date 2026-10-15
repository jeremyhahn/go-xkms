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

package pairingproto

import (
	"errors"
	"testing"
)

func TestDecodeResult_DecodesResult(t *testing.T) {
	resp := &Response{JSONRPC: JSONRPCVersion, ID: 1, Result: []byte(`{"pong":true}`)}

	result, err := DecodeResult[PingResult](resp)
	if err != nil {
		t.Fatalf("DecodeResult() returned unexpected error: %v", err)
	}
	if !result.Pong {
		t.Errorf("DecodeResult() Pong = false, want true")
	}
}

func TestDecodeResult_ReturnsRPCError(t *testing.T) {
	rpcErr := &RPCError{Code: ErrorCodeMethodNotFound, Message: "method not found"}
	resp := &Response{JSONRPC: JSONRPCVersion, ID: 1, Error: rpcErr}

	result, err := DecodeResult[PingResult](resp)
	if result != nil {
		t.Errorf("DecodeResult() result = %+v, want nil", result)
	}
	var got *RPCError
	if !errors.As(err, &got) || got != rpcErr {
		t.Errorf("DecodeResult() error = %v, want the response's RPCError", err)
	}
}

func TestDecodeResult_MalformedResult(t *testing.T) {
	resp := &Response{JSONRPC: JSONRPCVersion, ID: 1, Result: []byte(`{"pong":`)}

	if _, err := DecodeResult[PingResult](resp); err == nil {
		t.Fatal("DecodeResult() with malformed result expected error, got nil")
	}
}

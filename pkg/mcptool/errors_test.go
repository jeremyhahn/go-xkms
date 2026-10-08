// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.

package mcptool

import (
	"context"
	"errors"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

func TestRPCError_Error(t *testing.T) {
	e := &RPCError{Code: -32602, WireCode: qrdbsdk.MCPCodeInvalidArgument, Message: "invalid request"}
	got := e.Error()
	if !strings.Contains(got, "-32602") || !strings.Contains(got, "invalid request") || !strings.Contains(got, "INVALID_ARGUMENT") {
		t.Errorf("Error() = %q, want it to name the code, wire code, and message", got)
	}
}

func TestEnvelopeMissingError_Error(t *testing.T) {
	e := &EnvelopeMissingError{Tool: "xkms_ssh_keys_get", Message: "boom"}
	got := e.Error()
	if !strings.Contains(got, "xkms_ssh_keys_get") || !strings.Contains(got, "boom") {
		t.Errorf("Error() = %q, want it to name the tool and message", got)
	}
}

func TestMarshalError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("bad json")
	e := &MarshalError{Operation: "request", Err: cause}
	if !strings.Contains(e.Error(), "marshal request") || !strings.Contains(e.Error(), "bad json") {
		t.Errorf("Error() = %q", e.Error())
	}
	if e.Unwrap() != cause {
		t.Error("Unwrap() must return the wrapped cause")
	}
}

func TestUnmarshalError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("unexpected EOF")
	e := &UnmarshalError{Operation: "response", Err: cause}
	if !strings.Contains(e.Error(), "unmarshal response") || !strings.Contains(e.Error(), "unexpected EOF") {
		t.Errorf("Error() = %q", e.Error())
	}
	if e.Unwrap() != cause {
		t.Error("Unwrap() must return the wrapped cause")
	}
}

func TestReceiveError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("connection reset")
	e := &ReceiveError{Err: cause}
	if !strings.Contains(e.Error(), "receive response") || !strings.Contains(e.Error(), "connection reset") {
		t.Errorf("Error() = %q", e.Error())
	}
	if e.Unwrap() != cause {
		t.Error("Unwrap() must return the wrapped cause")
	}
}

func TestTLSSetupError_ErrorWithAndWithoutCause(t *testing.T) {
	withCause := &TLSSetupError{Detail: "bad CA", Err: errors.New("parse failed")}
	if !strings.Contains(withCause.Error(), "bad CA") || !strings.Contains(withCause.Error(), "parse failed") {
		t.Errorf("Error() = %q", withCause.Error())
	}
	if withCause.Unwrap() == nil {
		t.Error("Unwrap() must return the wrapped cause")
	}

	noCause := &TLSSetupError{Detail: "missing cert"}
	if got, want := noCause.Error(), "TLS setup: missing cert"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if noCause.Unwrap() != nil {
		t.Error("Unwrap() must be nil when there is no underlying cause")
	}
}

// ----------------------------------------------------------------------------
// nil-receiver safety: a zero-value Transport in pkg/api/transport/mcp
// embeds a nil *Client (see that package's not-connected coverage tests),
// so every read-only accessor must tolerate a nil receiver rather than
// panic.
// ----------------------------------------------------------------------------

func TestClient_NilReceiver_IsConnectedFalse(t *testing.T) {
	var c *Client
	if c.IsConnected() {
		t.Error("IsConnected() on a nil *Client must be false")
	}
}

func TestClient_NilReceiver_CloseIsNoOp(t *testing.T) {
	var c *Client
	if err := c.Close(); err != nil {
		t.Errorf("Close() on a nil *Client must be a no-op, got: %v", err)
	}
}

func TestClient_NilReceiver_ConnIsNil(t *testing.T) {
	var c *Client
	if c.Conn() != nil {
		t.Error("Conn() on a nil *Client must be nil")
	}
}

func TestClient_NilReceiver_ConfigIsNil(t *testing.T) {
	var c *Client
	if c.Config() != nil {
		t.Error("Config() on a nil *Client must be nil")
	}
}

func TestClient_NilReceiver_CallReturnsErrNotConnected(t *testing.T) {
	var c *Client
	err := c.Call(context.Background(), "health", nil, nil)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
}

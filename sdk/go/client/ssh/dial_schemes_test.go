// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ssh_test

import (
	"context"
	"errors"
	"testing"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestNewClientForServer_SchemeDispatch pins NewClientForServer's scheme
// dispatch table: every non-HTTP scheme it understands must construct the
// matching Client without blocking on connectivity (gRPC/QUIC clients dial
// lazily; only "mcp"/"mcps" perform an eager health-check dial and are
// covered separately against a live target), and an unrecognized scheme
// must fail with *ProtocolError.
func TestNewClientForServer_SchemeDispatch(t *testing.T) {
	cases := []struct {
		name   string
		server string
	}{
		{"grpc", "grpc://127.0.0.1:0"},
		{"grpcs", "grpcs://127.0.0.1:0"},
		{"unix", "unix:///tmp/xkms-test.sock"},
		{"quic", "quic://127.0.0.1:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := sdkssh.NewClientForServer(tc.server, "", "")
			if err != nil {
				t.Fatalf("NewClientForServer(%q): %v", tc.server, err)
			}
			defer func() { _ = client.Close() }()
			if client == nil {
				t.Fatal("expected a non-nil Client")
			}
		})
	}
}

// TestNewClientForServer_UnsupportedSchemeErrors pins the default branch:
// an unrecognized scheme fails construction with *ProtocolError rather than
// silently falling back to a transport.
func TestNewClientForServer_UnsupportedSchemeErrors(t *testing.T) {
	_, err := sdkssh.NewClientForServer("ftp://example.test", "", "")
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

// TestNewClientForServer_UnparsableURLErrors pins the url.Parse failure
// path: a server string that is not a valid URL fails with *ProtocolError
// before any scheme dispatch.
func TestNewClientForServer_UnparsableURLErrors(t *testing.T) {
	_, err := sdkssh.NewClientForServer("://not-a-url", "", "")
	var pe *sdkssh.ProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProtocolError, got %T: %v", err, err)
	}
}

// TestRESTClient_ConsoleUnsupported pins that the REST/QUIC transport
// rejects Console outright — the interactive console over HTTP is served by
// the WebSocket bridge, not this request/response client.
func TestRESTClient_ConsoleUnsupported(t *testing.T) {
	client, err := sdkssh.NewREST(sdkssh.RESTOptions{BaseURL: "https://xkms.example.test"})
	if err != nil {
		t.Fatalf("NewREST: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Console(context.Background(), sdkssh.ConsoleConnectRequest{}, sdkssh.ConsoleConfig{})
	var cue *sdkssh.ConsoleUnsupportedError
	if !errors.As(err, &cue) || cue.Transport != "rest" {
		t.Fatalf("expected ConsoleUnsupportedError{Transport: rest}, got %T: %v", err, err)
	}
}

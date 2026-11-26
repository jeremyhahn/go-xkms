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

package xkms

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// guardOn turns the mandatory-TLS guard back on for one test (TestMain opts
// the package out of it): with the variable empty, the config field decides.
func guardOn(t *testing.T) {
	t.Helper()
	t.Setenv(transport.EnvAllowInsecureTransport, "")
}

func TestNew_RefusesPlaintextTCPWithoutOptOut(t *testing.T) {
	guardOn(t)

	for name, cfg := range map[string]*BackendConfig{
		"grpc": {Protocol: ProtocolGRPC, Address: "10.0.0.1:9443"},
		"rest": {Protocol: ProtocolREST, Address: "http://10.0.0.1:8443"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); !errors.Is(err, transport.ErrInsecureTransport) {
				t.Fatalf("New(%s) error = %v, want ErrInsecureTransport", name, err)
			}
		})
	}

	if _, err := NewFromURL("grpc://10.0.0.1:9443"); !errors.Is(err, transport.ErrInsecureTransport) {
		t.Fatalf("NewFromURL(grpc://) error = %v, want ErrInsecureTransport", err)
	}
}

func TestNew_AllowInsecureTransportAdmitsLoopback(t *testing.T) {
	guardOn(t)

	for name, cfg := range map[string]*BackendConfig{
		"grpc": {Protocol: ProtocolGRPC, Address: "127.0.0.1:9443", AllowInsecureTransport: true},
		"rest": {Protocol: ProtocolREST, Address: "http://127.0.0.1:8443", AllowInsecureTransport: true},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := New(cfg)
			if err != nil {
				t.Fatalf("New(%s) with the opt-out returned error: %v", name, err)
			}
			if client == nil {
				t.Fatalf("New(%s) returned nil client", name)
			}
		})
	}
}

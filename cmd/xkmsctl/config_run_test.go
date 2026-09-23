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

// config_run_test.go closes remaining branches in config.go's client
// construction helpers: the default (no --server, no --transport) Unix
// socket path, NewFromURL parse failures, the embedded-protocol error
// propagation inside CreateClient, and the PKCS#11 TLS config error
// branches in createClientFromProtocol / createClientWithTLS.
package main

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func TestConfig_CreateClient_DefaultUnixSocket(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = ""
	cfg.Protocol = ""

	cl, err := cfg.CreateClient()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cl == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestConfig_CreateClient_InvalidServerURL(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "://not-a-valid-url"
	cfg.Protocol = ""

	_, err := cfg.CreateClient()
	if err == nil {
		t.Fatal("expected error for invalid server URL")
	}
}

func TestConfig_CreateClient_EmbeddedError(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "embedded"
	cfg.KeyDir = "/dev/null/invalid/keydir"
	cfg.Backend = "software"

	xkms.Reset()
	defer xkms.Reset()

	_, err := cfg.CreateClient()
	if err == nil {
		t.Fatal("expected error when the embedded xkms service fails to initialize")
	}
}

func TestConfig_CreateClientFromProtocol_PKCS11Error(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "unix"
	cfg.PKCS11Module = "/nonexistent/pkcs11.so"

	_, err := cfg.createClientFromProtocol()
	if err == nil {
		t.Fatal("expected error for nonexistent PKCS#11 module")
	}
}

func TestConfig_CreateClientWithTLS_PKCS11Error(t *testing.T) {
	cfg := NewConfig()
	cfg.Server = "unix:///tmp/xkms.sock"
	cfg.PKCS11Module = "/nonexistent/pkcs11.so"

	_, err := cfg.createClientWithTLS()
	if err == nil {
		t.Fatal("expected error for nonexistent PKCS#11 module")
	}
}

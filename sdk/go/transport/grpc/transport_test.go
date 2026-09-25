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

package grpc

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestNew_Success confirms New forwards valid options to the canonical
// implementation and returns a usable Transport.
func TestNew_Success(t *testing.T) {
	tr, err := New(transport.WithAddress("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("New() returned nil transport")
	}
}

// TestNew_OptionError confirms New propagates an error from a failing option
// rather than swallowing it, since New is a bare pass-through to the
// canonical constructor.
func TestNew_OptionError(t *testing.T) {
	_, err := New(transport.WithAddress(""))
	if err == nil {
		t.Fatal("expected error for empty address, got nil")
	}
}

// TestNewWithConfig_NilConfig confirms NewWithConfig accepts a nil config and
// forwards it to the canonical implementation without panicking.
func TestNewWithConfig_NilConfig(t *testing.T) {
	tr, err := NewWithConfig(nil)
	if err != nil {
		t.Fatalf("NewWithConfig(nil) returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("NewWithConfig(nil) returned nil transport")
	}
}

// TestNewWithConfig_ExplicitConfig confirms NewWithConfig forwards an
// explicit, non-nil config to the canonical implementation.
func TestNewWithConfig_ExplicitConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "127.0.0.1:0"

	tr, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig() returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("NewWithConfig() returned nil transport")
	}
}

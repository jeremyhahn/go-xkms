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

package unix

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestNew_Success confirms New forwards valid options to the canonical
// implementation and returns a usable Transport backed by a socket path.
func TestNew_Success(t *testing.T) {
	tr, err := New(transport.WithAddress("/tmp/xkms-test.sock"))
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("New() returned nil transport")
	}
}

// TestNew_NoSocketPath confirms New surfaces ErrSocketPathRequired when no
// address is configured, since a Unix transport is unusable without one.
func TestNew_NoSocketPath(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Fatal("expected error for missing socket path, got nil")
	}
}

// TestNewWithConfig_NilConfig confirms NewWithConfig rejects a nil config
// once it falls back to defaults, because the default config still has no
// socket path.
func TestNewWithConfig_NilConfig(t *testing.T) {
	_, err := NewWithConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil config with no socket path, got nil")
	}
}

// TestNewWithConfig_ExplicitConfig confirms NewWithConfig forwards an
// explicit, non-nil config carrying a socket path to the canonical
// implementation.
func TestNewWithConfig_ExplicitConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/xkms-test.sock"

	tr, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig() returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("NewWithConfig() returned nil transport")
	}
}

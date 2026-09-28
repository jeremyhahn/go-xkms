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

package usb

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TestNew_Defaults proves New builds a usable Transport from the zero set
// of options -- no real USB device is touched by construction, only by a
// later Connect, so this exercises the full constructor without hardware.
func TestNew_Defaults(t *testing.T) {
	tr, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if tr == nil {
		t.Fatal("New() returned a nil Transport with a nil error")
	}
}

// TestNew_OptionError proves an Option that rejects its arguments prevents
// construction. WithMTLS with an empty cert path is the option package's own
// documented error case, so New must surface it rather than build a
// half-configured Transport.
func TestNew_OptionError(t *testing.T) {
	tr, err := New(transport.WithMTLS("", "", ""))
	if err == nil {
		t.Fatal("New() error = nil, want the WithMTLS validation error")
	}
	if tr != nil {
		t.Errorf("New() Transport = %+v, want nil on error", tr)
	}
}

// TestNewWithConfig_NilUsesDefaults proves a nil *Config is not treated as a
// caller error: NewWithConfig substitutes transport.DefaultConfig() rather
// than panicking or constructing a zero-value Config.
func TestNewWithConfig_NilUsesDefaults(t *testing.T) {
	tr, err := NewWithConfig(nil)
	if err != nil {
		t.Fatalf("NewWithConfig(nil) error = %v", err)
	}
	if tr == nil {
		t.Fatal("NewWithConfig(nil) returned a nil Transport with a nil error")
	}
}

// TestNewWithConfig_Explicit proves an explicit Config is accepted and does
// not get silently replaced by defaults.
func TestNewWithConfig_Explicit(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "usb://pairing-fixture"

	tr, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig() error = %v", err)
	}
	if tr == nil {
		t.Fatal("NewWithConfig() returned a nil Transport with a nil error")
	}
}

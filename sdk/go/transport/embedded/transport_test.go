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

package embedded

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// stubServicer satisfies XKMSServicer by embedding the interface unset
// (nil). The New/NewWithConfig/NewWithService constructors under test only
// store the servicer, never call it, so a method call would panic but
// construction never triggers one; this keeps the fixture in-process and
// free of any real backend.
type stubServicer struct {
	XKMSServicer
}

// TestNew_Success confirms New stores a non-nil service and forwards options
// to the canonical implementation.
func TestNew_Success(t *testing.T) {
	tr, err := New(&stubServicer{}, transport.WithTimeout(5))
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("New() returned nil transport")
	}
}

// TestNew_NilService confirms New rejects a nil service before ever
// reaching the canonical constructor, since the embedded transport is
// useless without a backing service.
func TestNew_NilService(t *testing.T) {
	_, err := New(nil)
	if err == nil {
		t.Fatal("expected error for nil service, got nil")
	}
}

// TestNew_OptionError confirms New propagates an error from a failing
// option even when the service itself is valid.
func TestNew_OptionError(t *testing.T) {
	_, err := New(&stubServicer{}, transport.WithAddress(""))
	if err == nil {
		t.Fatal("expected error for empty address option, got nil")
	}
}

// TestNewWithConfig_NilConfig confirms NewWithConfig accepts a nil config,
// falling back to defaults, and returns a disconnected transport pending a
// later SetService call.
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

	tr, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig() returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("NewWithConfig() returned nil transport")
	}
}

// TestNewWithService_Success confirms NewWithService is equivalent to
// New(service) with default options.
func TestNewWithService_Success(t *testing.T) {
	tr, err := NewWithService(&stubServicer{})
	if err != nil {
		t.Fatalf("NewWithService() returned error: %v", err)
	}
	if tr == nil {
		t.Fatal("NewWithService() returned nil transport")
	}
}

// TestNewWithService_NilService confirms NewWithService rejects a nil
// service, matching New's own validation.
func TestNewWithService_NilService(t *testing.T) {
	_, err := NewWithService(nil)
	if err == nil {
		t.Fatal("expected error for nil service, got nil")
	}
}

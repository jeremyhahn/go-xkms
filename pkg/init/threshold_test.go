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

package initialize

import (
	"context"
	"errors"
	"testing"
)

// Compile-time interface satisfaction check.
var _ ThresholdInitializer = (*NoopThresholdInitializer)(nil)

func TestNoopThresholdInitializer_VendorName(t *testing.T) {
	noop := NewNoopThresholdInitializer()
	if got := noop.VendorName(); got != "noop" {
		t.Errorf("VendorName() = %q, want %q", got, "noop")
	}
}

func TestNoopThresholdInitializer_Available(t *testing.T) {
	noop := NewNoopThresholdInitializer()
	if noop.Available() {
		t.Error("Available() = true, want false")
	}
}

func TestNoopThresholdInitializer_InitializeThreshold(t *testing.T) {
	noop := NewNoopThresholdInitializer()
	err := noop.InitializeThreshold(context.Background(), &ThresholdOptions{
		Threshold: 2,
		Total:     3,
		SOPIN:     "123456",
	})
	if !errors.Is(err, ErrThresholdNotSupported) {
		t.Errorf("InitializeThreshold() error = %v, want %v", err, ErrThresholdNotSupported)
	}
}

func TestNoopThresholdInitializer_ImportShare(t *testing.T) {
	noop := NewNoopThresholdInitializer()
	err := noop.ImportShare(context.Background(), []byte("share-data"))
	if !errors.Is(err, ErrThresholdNotSupported) {
		t.Errorf("ImportShare() error = %v, want %v", err, ErrThresholdNotSupported)
	}
}

func TestNoopThresholdInitializer_ThresholdStatus(t *testing.T) {
	noop := NewNoopThresholdInitializer()
	status, err := noop.ThresholdStatus(context.Background())
	if !errors.Is(err, ErrThresholdNotSupported) {
		t.Errorf("ThresholdStatus() error = %v, want %v", err, ErrThresholdNotSupported)
	}
	if status != nil {
		t.Errorf("ThresholdStatus() status = %v, want nil", status)
	}
}

// mockThresholdInitializer is a test helper that implements ThresholdInitializer
// with configurable behavior.
type mockThresholdInitializer struct {
	vendor    string
	available bool
	imported  int
	threshold int
	total     int
}

func (m *mockThresholdInitializer) VendorName() string { return m.vendor }

func (m *mockThresholdInitializer) Available() bool { return m.available }

func (m *mockThresholdInitializer) InitializeThreshold(ctx context.Context, opts *ThresholdOptions) error {
	m.threshold = opts.Threshold
	m.total = opts.Total
	return nil
}

func (m *mockThresholdInitializer) ImportShare(ctx context.Context, share []byte) error {
	m.imported++
	return nil
}

func (m *mockThresholdInitializer) ThresholdStatus(ctx context.Context) (*ThresholdStatus, error) {
	return &ThresholdStatus{
		Threshold: m.threshold,
		Total:     m.total,
		Imported:  m.imported,
		Ready:     m.imported >= m.threshold,
	}, nil
}

func TestThresholdRegistry_RegisterAndGet(t *testing.T) {
	registry := NewThresholdRegistry()
	registry.Register("test-hsm", func() ThresholdInitializer {
		return &mockThresholdInitializer{
			vendor:    "test-hsm",
			available: true,
		}
	})

	init, err := registry.Get("test-hsm")
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if init.VendorName() != "test-hsm" {
		t.Errorf("VendorName() = %q, want %q", init.VendorName(), "test-hsm")
	}
	if !init.Available() {
		t.Error("Available() = false, want true")
	}
}

func TestThresholdRegistry_VendorNotRegistered(t *testing.T) {
	registry := NewThresholdRegistry()
	_, err := registry.Get("nonexistent-vendor")
	if !errors.Is(err, ErrVendorNotRegistered) {
		t.Errorf("Get() error = %v, want %v", err, ErrVendorNotRegistered)
	}
}

func TestThresholdRegistry_VendorNotAvailable(t *testing.T) {
	registry := NewThresholdRegistry()
	registry.Register("unavailable-hsm", func() ThresholdInitializer {
		return &mockThresholdInitializer{
			vendor:    "unavailable-hsm",
			available: false,
		}
	})

	_, err := registry.Get("unavailable-hsm")
	if !errors.Is(err, ErrVendorNotAvailable) {
		t.Errorf("Get() error = %v, want %v", err, ErrVendorNotAvailable)
	}
}

func TestThresholdRegistry_List(t *testing.T) {
	registry := NewThresholdRegistry()
	registry.Register("charlie", func() ThresholdInitializer {
		return &mockThresholdInitializer{vendor: "charlie"}
	})
	registry.Register("alpha", func() ThresholdInitializer {
		return &mockThresholdInitializer{vendor: "alpha"}
	})
	registry.Register("bravo", func() ThresholdInitializer {
		return &mockThresholdInitializer{vendor: "bravo"}
	})

	names := registry.List()
	if len(names) != 3 {
		t.Fatalf("List() returned %d names, want 3", len(names))
	}

	expected := []string{"alpha", "bravo", "charlie"}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("List()[%d] = %q, want %q", i, name, expected[i])
		}
	}
}

func TestThresholdRegistry_ListEmpty(t *testing.T) {
	registry := NewThresholdRegistry()
	names := registry.List()
	if len(names) != 0 {
		t.Errorf("List() returned %d names, want 0", len(names))
	}
}

func TestThresholdOptions_Fields(t *testing.T) {
	opts := &ThresholdOptions{
		Threshold: 3,
		Total:     5,
		SOPIN:     "654321",
	}
	if opts.Threshold != 3 {
		t.Errorf("Threshold = %d, want 3", opts.Threshold)
	}
	if opts.Total != 5 {
		t.Errorf("Total = %d, want 5", opts.Total)
	}
	if opts.SOPIN != "654321" {
		t.Errorf("SOPIN = %q, want %q", opts.SOPIN, "654321")
	}
}

func TestThresholdStatus_Fields(t *testing.T) {
	status := &ThresholdStatus{
		Threshold: 2,
		Total:     3,
		Imported:  2,
		Ready:     true,
	}
	if status.Threshold != 2 {
		t.Errorf("Threshold = %d, want 2", status.Threshold)
	}
	if status.Total != 3 {
		t.Errorf("Total = %d, want 3", status.Total)
	}
	if status.Imported != 2 {
		t.Errorf("Imported = %d, want 2", status.Imported)
	}
	if !status.Ready {
		t.Error("Ready = false, want true")
	}
}

func TestThresholdStatus_NotReady(t *testing.T) {
	status := &ThresholdStatus{
		Threshold: 3,
		Total:     5,
		Imported:  1,
		Ready:     false,
	}
	if status.Ready {
		t.Error("Ready = true, want false")
	}
}

func TestThresholdRegistry_RegisterOverwrite(t *testing.T) {
	registry := NewThresholdRegistry()

	registry.Register("vendor-a", func() ThresholdInitializer {
		return &mockThresholdInitializer{vendor: "vendor-a-v1", available: false}
	})
	registry.Register("vendor-a", func() ThresholdInitializer {
		return &mockThresholdInitializer{vendor: "vendor-a-v2", available: true}
	})

	init, err := registry.Get("vendor-a")
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if init.VendorName() != "vendor-a-v2" {
		t.Errorf("VendorName() = %q, want %q (overwritten factory)", init.VendorName(), "vendor-a-v2")
	}
}

func TestThresholdRegistry_MockInitializeAndImport(t *testing.T) {
	registry := NewThresholdRegistry()
	registry.Register("mock-hsm", func() ThresholdInitializer {
		return &mockThresholdInitializer{
			vendor:    "mock-hsm",
			available: true,
		}
	})

	init, err := registry.Get("mock-hsm")
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}

	ctx := context.Background()

	err = init.InitializeThreshold(ctx, &ThresholdOptions{
		Threshold: 2,
		Total:     3,
		SOPIN:     "123456",
	})
	if err != nil {
		t.Fatalf("InitializeThreshold() unexpected error: %v", err)
	}

	// Import first share.
	if err := init.ImportShare(ctx, []byte("share-1")); err != nil {
		t.Fatalf("ImportShare(1) unexpected error: %v", err)
	}

	status, err := init.ThresholdStatus(ctx)
	if err != nil {
		t.Fatalf("ThresholdStatus() unexpected error: %v", err)
	}
	if status.Imported != 1 {
		t.Errorf("Imported = %d, want 1", status.Imported)
	}
	if status.Ready {
		t.Error("Ready = true after 1 share, want false")
	}

	// Import second share to meet threshold.
	if err := init.ImportShare(ctx, []byte("share-2")); err != nil {
		t.Fatalf("ImportShare(2) unexpected error: %v", err)
	}

	status, err = init.ThresholdStatus(ctx)
	if err != nil {
		t.Fatalf("ThresholdStatus() unexpected error: %v", err)
	}
	if status.Imported != 2 {
		t.Errorf("Imported = %d, want 2", status.Imported)
	}
	if !status.Ready {
		t.Error("Ready = false after 2 shares (threshold=2), want true")
	}
	if status.Threshold != 2 {
		t.Errorf("Threshold = %d, want 2", status.Threshold)
	}
	if status.Total != 3 {
		t.Errorf("Total = %d, want 3", status.Total)
	}
}

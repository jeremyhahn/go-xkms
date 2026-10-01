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

package xkms

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestNewService_IsIndependentOfTheSingleton proves an embedder's instance and
// the process-wide service do not see each other: building one must not
// initialize Get, and initializing Get must not hand back the embedder's.
func TestNewService_IsIndependentOfTheSingleton(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	software := newMockKeyStoreWithSealer("software", types.BackendTypeSoftware)
	svc, err := NewService(&ServiceConfig{
		Backends:       map[string]Backend{"software": software},
		DefaultBackend: "software",
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if svc.defaultBackend != "software" || len(svc.backends) != 1 {
		t.Fatalf("instance carries default %q and %d backends", svc.defaultBackend, len(svc.backends))
	}
	if _, err := Get(); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Get after NewService = %v, want ErrNotInitialized", err)
	}

	other := newMockKeyStoreWithSealer("software", types.BackendTypeSoftware)
	if err := Initialize(&ServiceConfig{Backends: map[string]Backend{"software": other}}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	global, err := Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if global == svc {
		t.Fatal("the singleton is the embedder's instance")
	}
}

func TestNewService_RejectsInvalidConfiguration(t *testing.T) {
	software := newMockKeyStoreWithSealer("software", types.BackendTypeSoftware)
	tests := []struct {
		name   string
		config *ServiceConfig
		want   error
	}{
		{name: "nil config", config: nil, want: ErrNilConfig},
		{name: "no backends", config: &ServiceConfig{}, want: ErrNoBackendsConfigured},
		{
			name:   "named default missing",
			config: &ServiceConfig{Backends: map[string]Backend{"software": software}, DefaultBackend: "tpm2"},
			want:   ErrDefaultBackendNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewService(tt.config); !errors.Is(err, tt.want) {
				t.Fatalf("NewService error = %v, want %v", err, tt.want)
			}
		})
	}

	if _, err := NewService(&ServiceConfig{Backends: map[string]Backend{"Bad Name": software}}); err == nil {
		t.Fatal("NewService accepted an invalid backend name")
	}
}

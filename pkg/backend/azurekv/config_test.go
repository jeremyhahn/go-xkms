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

//go:build azurekv

package azurekv

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestConfig_Validate_LocalVaultURLDisallowedByDefault proves that
// AllowLocalVaultURL defaults to false and a localhost/127.0.0.1 vault URL
// is refused with ErrLocalVaultURLNotAllowed rather than silently accepted
// (#140).
func TestConfig_Validate_LocalVaultURLDisallowedByDefault(t *testing.T) {
	tests := []struct {
		name     string
		vaultURL string
	}{
		{name: "localhost", vaultURL: "https://localhost:8443/"},
		{name: "loopback IP", vaultURL: "https://127.0.0.1:8443/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				VaultURL:    tt.vaultURL,
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() error = nil, want ErrLocalVaultURLNotAllowed for %q", tt.vaultURL)
			}
			if !errors.Is(err, ErrLocalVaultURLNotAllowed) {
				t.Fatalf("Validate() error = %v, want ErrLocalVaultURLNotAllowed", err)
			}
		})
	}
}

// TestConfig_Validate_LocalVaultURLAllowedWhenEnabled proves that setting
// AllowLocalVaultURL restores the previous behavior of accepting a
// localhost/127.0.0.1 vault URL, for local development against an emulator
// or mock (#140).
func TestConfig_Validate_LocalVaultURLAllowedWhenEnabled(t *testing.T) {
	tests := []struct {
		name     string
		vaultURL string
	}{
		{name: "localhost", vaultURL: "https://localhost:8443/"},
		{name: "loopback IP", vaultURL: "https://127.0.0.1:8443/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				VaultURL:           tt.vaultURL,
				AllowLocalVaultURL: true,
				KeyStorage:         storage.New(),
				CertStorage:        storage.New(),
			}

			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error = %v, want nil with AllowLocalVaultURL set", err)
			}
		})
	}
}

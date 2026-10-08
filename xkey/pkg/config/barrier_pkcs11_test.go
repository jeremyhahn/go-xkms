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

package config

import (
	"errors"
	"testing"
)

func TestBarrierPKCS11Config_Validate(t *testing.T) {
	cfg := &BarrierPKCS11Config{Library: "/usr/lib/softhsm/libsofthsm2.so", Token: "barrier"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a library and a token", err)
	}
}

func TestBarrierPKCS11Config_Validate_Errors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *BarrierPKCS11Config
	}{
		{"nil config", nil},
		{"missing library", &BarrierPKCS11Config{Token: "barrier"}},
		{"missing token", &BarrierPKCS11Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if !errors.Is(err, ErrBarrierPKCS11ConfigInvalid) {
				t.Fatalf("Validate() = %v, want errors.Is match against ErrBarrierPKCS11ConfigInvalid", err)
			}
		})
	}
}

// TestBarrierPKCS11Config_RoundTrip proves the token `barrier init` saved is
// the one every later unseal reads back.
func TestBarrierPKCS11Config_RoundTrip(t *testing.T) {
	SetConfigDir(t.TempDir())
	t.Cleanup(ResetConfigDir)

	cfg := DefaultConfig()
	cfg.Barrier.PKCS11 = &BarrierPKCS11Config{Library: "/usr/lib/softhsm/libsofthsm2.so", Token: "barrier"}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if loaded.Barrier.PKCS11 == nil || *loaded.Barrier.PKCS11 != *cfg.Barrier.PKCS11 {
		t.Fatalf("Barrier.PKCS11 = %+v, want %+v", loaded.Barrier.PKCS11, cfg.Barrier.PKCS11)
	}
}

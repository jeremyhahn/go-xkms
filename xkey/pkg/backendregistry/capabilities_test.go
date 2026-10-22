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

package backendregistry

import (
	"slices"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

func TestConfiguredFor_NilConfig(t *testing.T) {
	ids, def := ConfiguredFor(nil, CapOATH)
	if !slices.Equal(ids, []string{SoftwareBackendID}) || def != SoftwareBackendID {
		t.Fatalf("ConfiguredFor(nil) = %v, %q; want [software], software", ids, def)
	}
}

func TestConfiguredFor_SelectsCapableLocalBackends(t *testing.T) {
	cfg := &config.Config{}
	cfg.Backends.Local = []config.LocalBackendConfig{
		{ID: "token1", Category: string(CategoryPKCS11)},
		{ID: "tpm", Category: string(CategoryTPM2)},
		{ID: "token1", Category: string(CategoryPKCS11)},
		{ID: SoftwareBackendID, Category: string(CategorySoftware)},
	}
	cfg.Backends.Defaults = map[string]string{string(CapOATH): "token1"}

	ids, def := ConfiguredFor(cfg, CapOATH)
	if !slices.Equal(ids, []string{SoftwareBackendID, "token1"}) {
		t.Errorf("ids = %v, want [software token1] (tpm2 has no OATH; duplicates dropped)", ids)
	}
	if def != "token1" {
		t.Errorf("default = %q, want token1", def)
	}
}

func TestConfiguredFor_CapabilitySoftwareLacks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Backends.Local = []config.LocalBackendConfig{{ID: "tpm", Category: string(CategoryTPM2)}}

	ids, def := ConfiguredFor(cfg, CapAttestation)
	if !slices.Equal(ids, []string{"tpm"}) || def != SoftwareBackendID {
		t.Fatalf("ConfiguredFor(attestation) = %v, %q; want [tpm], software", ids, def)
	}
}

func TestDefaultCapabilities(t *testing.T) {
	if !DefaultCapabilities(CategoryPKCS11)[CapOATH] || DefaultCapabilities(CategoryTPM2)[CapOATH] {
		t.Error("OATH must be offered by pkcs11 and not by tpm2")
	}
	unknown := DefaultCapabilities(BackendCategory("nosuch"))
	if !unknown[CapSigning] || unknown[CapOATH] {
		t.Errorf("unknown category caps = %v, want signing only base set", unknown)
	}
}

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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyBackendConfigs_LocalBackends(t *testing.T) {
	c := &Config{}
	c.TPM.Device = "/dev/tpmrm0"
	c.Backends.Local = []LocalBackendConfig{
		{Category: "tpm2", TPM2: &TPM2BackendConfig{Device: "/dev/tpm1", Simulator: true}},
		{Category: "pkcs11", PKCS11: &PKCS11BackendConfig{LibraryPath: "/usr/lib/softhsm/libsofthsm2.so", SlotID: 3}},
		{Category: "software"},
	}
	assert.Equal(t, map[string]map[string]interface{}{
		"tpm2":   {"device": "/dev/tpm1", "use_simulator": true},
		"pkcs11": {"library": "/usr/lib/softhsm/libsofthsm2.so", "slot": 3},
	}, c.KeyBackendConfigs(), "a local TPM 2.0 backend wins over the shared TPM device")
}

func TestKeyBackendConfigs_SharedTPMDeviceAndEmpty(t *testing.T) {
	c := &Config{}
	assert.Empty(t, c.KeyBackendConfigs())
	c.TPM.Device = "/dev/tpmrm0"
	assert.Equal(t, map[string]map[string]interface{}{"tpm2": {"device": "/dev/tpmrm0"}}, c.KeyBackendConfigs())
}

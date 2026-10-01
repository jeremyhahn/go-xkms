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

// KeyBackendConfigs returns the per-backend configuration xKey's local key
// store starts its xkms backends with (xkms AutoConfig.BackendConfigs, keyed
// by backend type): each configured local TPM 2.0 and PKCS#11 backend, and
// the shared TPM device when no local TPM 2.0 backend names one. The GUI and
// the CLI both build their local key store from it, so the two open the
// same backends.
func (c *Config) KeyBackendConfigs() map[string]map[string]interface{} {
	configs := make(map[string]map[string]interface{})
	for _, lb := range c.Backends.Local {
		switch lb.Category {
		case "tpm2":
			if lb.TPM2 != nil {
				cfg := make(map[string]interface{})
				if lb.TPM2.Device != "" {
					cfg["device"] = lb.TPM2.Device
				}
				if lb.TPM2.Simulator {
					cfg["use_simulator"] = true
				}
				configs["tpm2"] = cfg
			}
		case "pkcs11":
			if lb.PKCS11 != nil {
				cfg := make(map[string]interface{})
				if lb.PKCS11.LibraryPath != "" {
					cfg["library"] = lb.PKCS11.LibraryPath
				}
				if lb.PKCS11.SlotID != 0 {
					cfg["slot"] = lb.PKCS11.SlotID
				}
				configs["pkcs11"] = cfg
			}
		}
	}
	if _, hasTPM2 := configs["tpm2"]; !hasTPM2 && c.TPM.Device != "" {
		configs["tpm2"] = map[string]interface{}{"device": c.TPM.Device}
	}
	return configs
}

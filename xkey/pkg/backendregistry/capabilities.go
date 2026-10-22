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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// SoftwareBackendID is the local software backend, which the registry
// always registers whatever the unified config lists.
const SoftwareBackendID = "software"

// ConfiguredFor returns the IDs of the backends in cfg that offer capability
// c, and the backend a feature uses when none is named. The IDs are
// SoftwareBackendID (when the software category offers c) followed by every
// local backend whose category offers c (DefaultCapabilities). The default
// is cfg.Backends.Defaults[c] when set, otherwise SoftwareBackendID. A nil
// cfg (no unified config) is treated as an empty one.
func ConfiguredFor(cfg *config.Config, c Capability) (ids []string, defaultID string) {
	if DefaultCapabilities(CategorySoftware)[c] {
		ids = append(ids, SoftwareBackendID)
	}
	defaultID = SoftwareBackendID
	if cfg == nil {
		return ids, defaultID
	}

	for _, lb := range cfg.Backends.Local {
		if DefaultCapabilities(BackendCategory(lb.Category))[c] && !slices.Contains(ids, lb.ID) {
			ids = append(ids, lb.ID)
		}
	}
	if configured := cfg.Backends.Defaults[string(c)]; configured != "" {
		defaultID = configured
	}
	return ids, defaultID
}

// DefaultCapabilities returns the capabilities a local backend of category
// cat offers. It is the one table both the GUI's registry and the CLI's
// per-feature backend selection (OATH) read, so the two never disagree.
func DefaultCapabilities(cat BackendCategory) map[Capability]bool {
	caps := map[Capability]bool{
		CapSigning:    true,
		CapEncryption: true,
		// Every signing-capable backend can mint SSH keys (ed25519/ecdsa/rsa),
		// so SSH capability tracks signing capability.
		CapSSH: true,
	}
	switch cat {
	case CategorySoftware:
		caps[CapFIDO2] = true
		caps[CapOATH] = true
		caps[CapPasswords] = true
		caps[CapSealing] = true
		caps[CapPIV] = true
	case CategoryTPM2:
		caps[CapFIDO2] = true
		caps[CapSealing] = true
		caps[CapAttestation] = true
		caps[CapPasswords] = true
		caps[CapPIV] = true
	case CategoryPKCS11:
		caps[CapFIDO2] = true
		caps[CapPIV] = true
		caps[CapSealing] = true
		caps[CapOATH] = true
		caps[CapPasswords] = true
	case CategoryPhone:
		caps[CapFIDO2] = true
		caps[CapAttestation] = true
	}
	return caps
}

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

// BarrierPKCS11Config names the HSM token the pkcs11 barrier strategy logs
// in to. It has no PIN field: the token PIN is a pre-barrier secret, sealed
// to this host's TPM under the platform PCR policy by `xkey barrier init
// --strategy pkcs11 --pkcs11-pin-stdin`, and never written to this file.
type BarrierPKCS11Config struct {
	// Library is the path of the PKCS#11 module.
	Library string `yaml:"library" json:"library" mapstructure:"library"`

	// Token is the label of the token holding the seal key.
	Token string `yaml:"token" json:"token" mapstructure:"token"`
}

// Validate checks that c holds a usable pkcs11 barrier configuration.
func (c *BarrierPKCS11Config) Validate() error {
	if c == nil {
		return &DetailError{Err: ErrBarrierPKCS11ConfigInvalid, Detail: ": no configuration provided (run 'xkey barrier init --strategy pkcs11 --pkcs11-library <path> --pkcs11-token <label> --pkcs11-pin-stdin')"}
	}
	if c.Library == "" {
		return &DetailError{Err: ErrBarrierPKCS11ConfigInvalid, Detail: ": library is required"}
	}
	if c.Token == "" {
		return &DetailError{Err: ErrBarrierPKCS11ConfigInvalid, Detail: ": token is required"}
	}
	return nil
}

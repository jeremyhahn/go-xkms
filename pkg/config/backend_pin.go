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
	"fmt"
)

var (
	// ErrBackendPINSelfStore refuses backend_pin.strategy pkcs11: the
	// PKCS#11 backend is never the store of its own PIN.
	ErrBackendPINSelfStore = errors.New("config: backend_pin.strategy pkcs11 refused: PKCS#11 cannot store its own PIN")
	// ErrInvalidBackendPINStrategy reports an unknown backend_pin value.
	ErrInvalidBackendPINStrategy = errors.New("config: invalid backend PIN strategy")
)

// BackendPINConfig selects how xkmsd obtains the PIN of a PIN-protected
// PKCS#11 backend (backends.pkcs11.pin, rng.pkcs11.pin), resolved through
// pinselect.ResolveBackendPIN (owner decision 230, #2262).
type BackendPINConfig struct {
	// Strategy is auto (default), tpm2, sealed or manual.
	Strategy string `yaml:"strategy,omitempty" json:"strategy,omitempty"`
	// Minimum refuses start below it (sealed < tpm2 < manual); empty
	// means no minimum.
	Minimum string `yaml:"minimum,omitempty" json:"minimum,omitempty"`
}

// Validate refuses pkcs11 and unknown values; minimum must be concrete.
func (c BackendPINConfig) Validate() error {
	switch c.Strategy {
	case "", "auto", "tpm2", "sealed", "manual":
	case "pkcs11":
		return ErrBackendPINSelfStore
	default:
		return fmt.Errorf("%w: backend_pin.strategy %q", ErrInvalidBackendPINStrategy, c.Strategy)
	}
	switch c.Minimum {
	case "", "tpm2", "sealed", "manual":
	default:
		return fmt.Errorf("%w: backend_pin.minimum %q", ErrInvalidBackendPINStrategy, c.Minimum)
	}
	return nil
}

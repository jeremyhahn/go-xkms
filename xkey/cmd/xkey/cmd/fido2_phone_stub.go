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

//go:build !ble

package cmd

import (
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator/keybackend"
)

// ErrFIDO2BLENotAvailable indicates the phone backend requires BLE support.
var ErrFIDO2BLENotAvailable = errors.New("fido2: phone backend requires BLE support; rebuild with -tags ble")

// createFIDO2PhoneKeyBackend returns an error when BLE is not available.
func createFIDO2PhoneKeyBackend(cfg *FIDO2Config, logger *slog.Logger) (keybackend.FIDO2KeyBackend, error) {
	return nil, ErrFIDO2BLENotAvailable
}

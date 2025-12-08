// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !tpm_simulator

package tpm2

import (
	"errors"
)

// ErrSimulatorNotAvailable is returned when simulator support is not compiled in
var ErrSimulatorNotAvailable = errors.New("tpm: simulator support not compiled (build with -tags tpm_simulator)")

// openSimulator returns an error when simulator support is not compiled in
func openSimulator() (SimulatorInterface, error) {
	return nil, ErrSimulatorNotAvailable
}

func init() {
	simulatorOpener = openSimulator
}

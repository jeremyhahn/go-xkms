//go:build !tpm_simulator
// +build !tpm_simulator

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

package tpm2

import "errors"

// ErrSimulatorNotAvailable is returned when the TPM simulator is not compiled in.
// Build with -tags tpm_simulator to enable the simulator.
var ErrSimulatorNotAvailable = errors.New("TPM simulator not available: build with -tags tpm_simulator")

// OpenSimulator returns an error when the simulator is not compiled in.
// The go-tpm-tools simulator requires CGO and the Microsoft TPM 2.0
// reference implementation headers which are not available in all builds.
// Use swtpm for software TPM functionality instead.
func OpenSimulator() (SimulatorInterface, error) {
	return nil, ErrSimulatorNotAvailable
}

func init() {
	// Set the simulator opener to return the not-available error
	simulatorOpener = func() (SimulatorInterface, error) {
		return nil, ErrSimulatorNotAvailable
	}
}

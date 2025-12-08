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

//go:build tpm_simulator

package tpm2

import (
	"io"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
)

// simulatorWrapper wraps the TPM simulator
type simulatorWrapper struct {
	sim *simulator.Simulator
}

func (s *simulatorWrapper) Close() error {
	if s.sim != nil {
		return s.sim.Close()
	}
	return nil
}

func (s *simulatorWrapper) Transport() transport.TPM {
	return transport.FromReadWriter(s.sim)
}

func (s *simulatorWrapper) ReadWriter() io.ReadWriter {
	return s.sim
}

// openSimulator opens a TPM simulator with a fixed seed
func openSimulator() (SimulatorInterface, error) {
	sim, err := simulator.GetWithFixedSeedInsecure(1234567890)
	if err != nil {
		return nil, err
	}
	return &simulatorWrapper{sim: sim}, nil
}

func init() {
	simulatorOpener = openSimulator
}

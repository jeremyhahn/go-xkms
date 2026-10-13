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

//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider/enclaveprovidertest"
)

// TestEnclaveProvider_Conformance_Simulator runs go-enclave's provider
// conformance suite, in both modes, over TPM 2.0 sealed objects on the
// reference simulator.
//
// The residue sweep is skipped: the simulator is a TPM inside this process,
// so the unsealed secret sits in its own RAM, and the TPM2_Unseal response
// carrying it crosses the command transport's buffers before pkg/tpm2 sees
// it. Both are below the provider, which wipes the slice it is handed.
func TestEnclaveProvider_Conformance_Simulator(t *testing.T) {
	h := newSimHarness(t, nil)
	enclaveprovidertest.Run(t, enclaveprovidertest.Backend{
		Sealer:           h.TPM,
		KeyAttributes:    sealedKeyAttrs(t, h, "enclave-provider", false, mustPassword(objectPassword)),
		SkipResidueSweep: "the reference TPM simulator runs in this process and holds the unsealed secret in its own RAM; the TPM2_Unseal response crosses the command transport's buffers below pkg/tpm2",
	})
}

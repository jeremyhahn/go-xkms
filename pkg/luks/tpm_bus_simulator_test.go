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

package luks

import (
	"context"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test/tpmbus"
	"github.com/stretchr/testify/require"
)

// TestTPMSealer_PassphraseNeverCrossesTheBus seals a LUKS passphrase under
// the SRK with a PCR policy and unseals it, recording the TPM bus. The
// passphrase must appear nowhere in the traffic: TPM2_Create must carry it in
// a salted session with the decrypt attribute, and TPM2_Unseal must return
// it under a salted session with the encrypt attribute.
func TestTPMSealer_PassphraseNeverCrossesTheBus(t *testing.T) {
	simLock.Lock()
	sim, err := simulator.Get()
	if err != nil {
		simLock.Unlock()
		t.Fatalf("simulator.Get: %v", err)
	}
	defer func() {
		require.NoError(t, sim.Close())
		simLock.Unlock()
	}()

	sharedTPM := transport.FromReadWriter(sim)
	provisionPersistentSRK(t, sharedTPM, libtpm2.TPMHandle(DefaultTPMParentHandle))

	bus := tpmbus.New(sharedTPM)
	sealer, err := NewTPMSealer(nil, &sharedSimOpener{tpm: bus})
	require.NoError(t, err)

	res, err := sealer.SealPassphrase(context.Background(), "", []int32{7})
	require.NoError(t, err)
	defer res.Passphrase.Destroy()
	passphrase := res.Passphrase.Bytes()

	unsealed, err := sealer.UnsealPassphrase(context.Background(), res.TokenJSON)
	require.NoError(t, err)
	require.Equal(t, passphrase, unsealed)

	bus.RequireAbsent(t, "the LUKS passphrase", passphrase)
	bus.RequireSessionAttr(t, libtpm2.TPMCCCreate, tpmbus.SessionAttrDecrypt)
	bus.RequireSessionAttr(t, libtpm2.TPMCCUnseal, tpmbus.SessionAttrEncrypt)
}

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
	"bytes"
	"context"
	"testing"

	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"

	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test/tpmbus"
)

// busTPM routes the commands the backend sends on Transport() -- the raw
// go-tpm commands of the import path -- through a bus capture.
type busTPM struct {
	pkgtpm2.TrustedPlatformModule
	bus *tpmbus.Capture
}

// Transport returns the capture in place of the TPM's own transport.
func (b busTPM) Transport() transport.TPM { return b.bus }

// TestUnwrapKey_KeyMaterialNeverCrossesTheBus unwraps key material through
// TPM2_Import, TPM2_Load and TPM2_Unseal, recording the TPM bus. The
// recovered material must appear nowhere in the traffic: TPM2_Unseal must
// return it under a salted session with the encrypt attribute.
func TestUnwrapKey_KeyMaterialNeverCrossesTheBus(t *testing.T) {
	b := newSimBackend(t)
	material := bytes.Repeat([]byte("import-secret-4f2a"), 2)
	params, wrapped := wrapMaterial(t, b, material)

	bus := tpmbus.New(b.tpm.Transport())
	inner := b.tpm
	b.tpm = busTPM{TrustedPlatformModule: inner, bus: bus}
	t.Cleanup(func() { b.tpm = inner })

	recovered, err := b.UnwrapKey(context.Background(), wrapped, params)
	require.NoError(t, err)
	require.Equal(t, material, recovered)

	bus.RequireAbsent(t, "the unwrapped key material", material)
	bus.RequireSessionAttr(t, gotpm2.TPMCCUnseal, tpmbus.SessionAttrEncrypt)
}

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
// +build tpm_simulator

package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// commandNotSupportedOnceTransport answers the first TPM2_CreateLoaded it
// sees with a synthetic TPM response carrying ErrCommandNotSupported
// (TPM_RC 0xb0143) instead of forwarding it, and passes every other command
// -- including every later TPM2_CreateLoaded -- straight through to the
// real simulator. This reproduces, without any TPM firmware that actually
// lacks TPM2_CreateLoaded, the one condition CreateRSA/CreateECDSA's legacy
// TPM2_Create+TPM2_Load fallback exists to handle.
//
// A raw TPM response is just a 10-byte header (TPMI_ST_COMMAND_TAG,
// UINT32 size, TPMRC) when the response code is not success -- Part 1,
// Architecture, and go-tpm's rspHeader, which returns hdr.ResponseCode
// itself as the error whenever it isn't TPM_RC_SUCCESS.
type commandNotSupportedOnceTransport struct {
	inner  transport.TPM
	done   bool
	failCC tpm2.TPMCC
}

func (f *commandNotSupportedOnceTransport) Send(input []byte) ([]byte, error) {
	if !f.done && len(input) >= tpmCCOffset+4 {
		cc := tpm2.TPMCC(binary.BigEndian.Uint32(input[tpmCCOffset : tpmCCOffset+4]))
		if cc == f.failCC {
			f.done = true
			resp := make([]byte, 10)
			binary.BigEndian.PutUint16(resp[0:2], uint16(tpm2.TPMSTNoSessions))
			binary.BigEndian.PutUint32(resp[2:6], 10)
			binary.BigEndian.PutUint32(resp[6:10], uint32(ErrCommandNotSupported))
			return resp, nil
		}
	}
	return f.inner.Send(input)
}

// TestCreateRSA_LegacyCreateLoadFallback_Succeeds proves CreateRSA's legacy
// TPM2_Create+TPM2_Load fallback -- entirely unreached by every other test
// in this package, since the simulator always supports TPM2_CreateLoaded --
// actually produces a usable, correctly loaded key when TPM2_CreateLoaded
// itself is unsupported.
func TestCreateRSA_LegacyCreateLoadFallback_Succeeds(t *testing.T) {
	tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)
	tpmImpl := tpm.(*TPM2)
	tpmImpl.transport = &commandNotSupportedOnceTransport{inner: tpmImpl.transport, failCC: tpm2.TPMCCCreateLoaded}

	genAttrs := &types.KeyAttributes{
		CN:            "create-rsa-legacy-fallback",
		KeyAlgorithm:  x509.RSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		Parent:        srkAttrs,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}
	pub, err := tpmImpl.CreateRSA(genAttrs, backend, true)
	require.NoError(t, err, "the legacy Create+Load sequence must still produce a usable key")
	require.NotNil(t, pub)
	require.NotZero(t, genAttrs.TPMAttributes.Handle, "the key loaded via the legacy path must be evicted to a persistent handle like the CreateLoaded path")
}

// TestCreateECDSA_LegacyCreateLoadFallback_Succeeds is the ECDSA mirror of
// TestCreateRSA_LegacyCreateLoadFallback_Succeeds.
func TestCreateECDSA_LegacyCreateLoadFallback_Succeeds(t *testing.T) {
	tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)
	tpmImpl := tpm.(*TPM2)
	tpmImpl.transport = &commandNotSupportedOnceTransport{inner: tpmImpl.transport, failCC: tpm2.TPMCCCreateLoaded}

	genAttrs := &types.KeyAttributes{
		CN:            "create-ecdsa-legacy-fallback",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		Parent:        srkAttrs,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	pub, err := tpmImpl.CreateECDSA(genAttrs, backend, true)
	require.NoError(t, err, "the legacy Create+Load sequence must still produce a usable key")
	require.NotNil(t, pub)
	require.NotZero(t, genAttrs.TPMAttributes.Handle, "the key loaded via the legacy path must be evicted to a persistent handle like the CreateLoaded path")
}

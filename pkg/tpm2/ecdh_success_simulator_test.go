//go:build tpm_simulator
// +build tpm_simulator

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

package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestECDHZGen_DecryptCapableKey_ComputesSharedSecret exercises ECDHZGen's
// success path end to end: TPM2_ECDH_ZGen against a genuinely decrypt-capable
// ECC key, extracting the response point and returning its X coordinate.
//
// No exported creation entry point in this package builds a decrypt-capable
// ECC key today -- CreateECDSA (ecdsa.go) always builds a sign-only template
// regardless of keyAttrs.KeyType, unlike CreateRSA (rsa.go), which sets
// Decrypt from KeyTypeEncryption. See the KNOWN GAP note in this file's
// package documentation comment for the finding this proves is real; this
// test reaches the success path by creating the decrypt-capable object
// directly with TPM2_CreateLoaded, exactly as a future KeyType-aware
// CreateECDSA would, then routes it through the same SaveKeyPair/LoadKeyPair/
// ECDHZGen path a caller would use.
func TestECDHZGen_DecryptCapableKey_ComputesSharedSecret(t *testing.T) {
	h := newSimHarness(t, nil)

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	srkName, _, err := h.TPM.ReadHandle(srkAttrs.TPMAttributes.Handle)
	require.NoError(t, err)

	tmpl, err := KeyTemplateSpec{
		Algorithm: x509.ECDSA,
		Curve:     elliptic.P256(),
		Decrypt:   true,
	}.Template()
	require.NoError(t, err)

	createRsp, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkAttrs.TPMAttributes.Handle,
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&tmpl),
	}.Execute(h.TPM.transport)
	require.NoError(t, err, "test setup: a decrypt-capable ECC key must be creatable directly")

	outPub, err := createRsp.OutPublic.Contents()
	require.NoError(t, err)
	tpmPub, err := eccPublicKey(outPub)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "ecdh-decrypt-capable",
		Parent:       srkAttrs,
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	require.NoError(t, h.TPM.SaveKeyPair(attrs, createRsp.OutPrivate, createRsp.OutPublic, h.Backend, true))
	h.TPM.Flush(createRsp.ObjectHandle)

	peerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerRaw, err := peerPriv.PublicKey.Bytes()
	require.NoError(t, err)
	peerSize := ecpoint.CoordinateSize(peerPriv.Curve)
	peerPoint := &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: peerRaw[1 : 1+peerSize]},
		Y: tpm2.TPM2BECCParameter{Buffer: peerRaw[1+peerSize:]},
	}

	shared, err := h.TPM.ECDHZGen(attrs, peerPoint, h.Backend)
	require.NoError(t, err, "a decrypt-capable ECC key must be usable for ECDH key agreement")
	require.NotEmpty(t, shared)

	// ECDH is symmetric: peer-private * TPM-public must equal what the TPM
	// itself would compute as TPM-private * peer-public. crypto/ecdh's ECDH
	// method returns exactly the X coordinate, matching NIST SP 800-56A and
	// this package's documented ECDHZGen contract.
	peerECDH, err := peerPriv.ECDH()
	require.NoError(t, err)
	tpmECDHPub, err := tpmPub.ECDH()
	require.NoError(t, err)
	expected, err := peerECDH.ECDH(tpmECDHPub)
	require.NoError(t, err)

	assert.Equal(t, expected, shared,
		"ECDHZGen must return the same shared secret X coordinate the peer computes independently")

	// A second call against the same saved key must be able to reload it and
	// reach the identical result -- it is not consumed or invalidated by use.
	again, err := h.TPM.ECDHZGen(attrs, peerPoint, h.Backend)
	require.NoError(t, err)
	assert.Equal(t, shared, again)
}

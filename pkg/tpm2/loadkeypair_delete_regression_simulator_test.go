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
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// These tests guard a real product bug found by live GUI testing: deleting a
// TPM2-backed PIV key left the slot permanently occupied because
// TPM2.LoadKeyPair (called from DeleteKey) built its own ad hoc ParentHandle
// authorization session with TPM2.HMAC using the CHILD key's own Password,
// instead of delegating to TPM2.CreateSession -- the same helper key
// creation (CreateECDSA/CreateRSA) already uses, which correctly authorizes
// the *parent* using the parent's own PlatformPolicy/Password. Two distinct
// consequences follow from that divergence:
//
//  1. Authorization correctness: when a parent (SRK) has its own auth value,
//     the old code presented the wrong auth value (the child's, not the
//     parent's) to TPM2_Load's ParentHandle, producing TPM_RC_BAD_AUTH. This
//     is reproducible on any TPM, including the simulator, and is what the
//     tests below exercise directly.
//  2. Session-shape asymmetry: CreateSession answers a parent with no auth
//     value and no PlatformPolicy with a zero-round-trip empty PasswordAuth
//     pseudo-session, while the old LoadKeyPair unconditionally
//     built a real TPM2.HMAC session requiring a live TPM2_StartAuthSession
//     round trip. On the reporter's real host TPM this made key generation
//     (via CreateSession) succeed while every subsequent LoadKeyPair call
//     (delete, sign, ECDH, attestation) failed at the kernel resource-manager
//     layer with "write /dev/tpmrm0: bad address" -- confirmed by a manual
//     reproduction against the physical device during triage. That specific
//     kernel/resource-manager failure mode is host/kernel-specific and does
//     not reproduce on the in-process simulator, so it is not asserted here;
//     the logic defect that the same fix (routing through CreateSession)
//     also resolves is what these tests hold to the line.

// deleteKeyRegressionFixture provisions a simulator TPM plus an SRK whose
// UserAuth ("srk-pass") differs from the child key's own Password
// ("key-pass"), matching the shape createKey already establishes elsewhere
// in this package. It also returns a KeyBackend so tests can independently
// verify blobs are actually removed from storage after DeleteKey.
func deleteKeyRegressionFixture(t *testing.T) (tpm TrustedPlatformModule, srkAttrs *types.KeyAttributes, backend store.KeyBackend) {
	t.Helper()

	_, tpm = createSim(t, false)
	t.Cleanup(func() { _ = tpm.Close() })

	// createKey provisions a fresh SRK (Password "srk-pass") under the EK
	// and returns a template child KeyAttributes (Password "key-pass")
	// parented to it -- exactly the "parent auth != child auth" shape
	// needed to distinguish the two code paths.
	childTemplate := createKey(tpm, false)
	srkAttrs = childTemplate.Parent

	storageFactory, err := store.NewStorageFactory(slog.Default(), "")
	require.NoError(t, err)
	backend = storageFactory.KeyBackend()

	return tpm, srkAttrs, backend
}

// freshListKeysStyleAttrs mimics exactly what pkg/backend/tpm2's ListKeys
// (and the resulting DeleteKey call) reconstructs from disk: a minimal
// KeyAttributes carrying only CN, StoreType and the recovered KeyAlgorithm --
// no cached Password, no cached TPMAttributes. Parent is set to the SRK the
// same way backend.DeleteKey defaults it when nil.
func freshListKeysStyleAttrs(cn string, algo x509.PublicKeyAlgorithm, srkAttrs *types.KeyAttributes) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		StoreType:    types.StoreTPM2,
		KeyAlgorithm: algo,
		Parent:       srkAttrs,
	}
}

// TestDeleteKey_ECDSA_UsesParentAuthNotChildAuth_Simulator is the primary
// regression test: it generates a PIV-style ECDSA signing key under an SRK
// that requires its own auth value, then deletes it using a freshly
// reconstructed KeyAttributes (no cached Password, as ListKeys produces).
// Before the fix, DeleteKey (via LoadKeyPair) authorized the ParentHandle
// with the child key's Password instead of the parent's, so it always failed
// with TPM_RC_BAD_AUTH whenever the two differed -- leaving the slot
// permanently occupied exactly as reported.
func TestDeleteKey_ECDSA_UsesParentAuthNotChildAuth_Simulator(t *testing.T) {
	tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)

	const cn = "piv-9a-ecdsa-repro"
	genAttrs := &types.KeyAttributes{
		CN:            cn,
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		Parent:        srkAttrs,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}

	tpmImpl := tpm.(*TPM2)
	_, err := tpmImpl.CreateECDSA(genAttrs, backend, true)
	require.NoError(t, err, "CreateECDSA must succeed (matches the live report: generation works)")

	fresh := freshListKeysStyleAttrs(cn, x509.ECDSA, srkAttrs)
	err = tpmImpl.DeleteKey(fresh, backend)
	require.NoError(t, err, "DeleteKey must succeed using the parent's own auth, not the child's")

	// The slot must actually be gone, not merely report success.
	_, getErr := backend.Get(fresh, store.FSEXT_PRIVATE_BLOB)
	require.Error(t, getErr, "private blob must be removed after DeleteKey")
}

// TestDeleteKey_RSA_UsesParentAuthNotChildAuth_Simulator mirrors the ECDSA
// regression test for RSA, since both key algorithms share the identical
// DeleteKey/LoadKeyPair code path (pkg/tpm2/key.go branches on
// x509.RSA/x509.ECDSA to the same LoadKeyPair call).
func TestDeleteKey_RSA_UsesParentAuthNotChildAuth_Simulator(t *testing.T) {
	tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)

	const cn = "piv-9c-rsa-repro"
	genAttrs := &types.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}

	tpmImpl := tpm.(*TPM2)
	_, err := tpmImpl.CreateRSA(genAttrs, backend, true)
	require.NoError(t, err, "CreateRSA must succeed (matches the live report: generation works)")

	fresh := freshListKeysStyleAttrs(cn, x509.RSA, srkAttrs)
	err = tpmImpl.DeleteKey(fresh, backend)
	require.NoError(t, err, "DeleteKey must succeed using the parent's own auth, not the child's")

	_, getErr := backend.Get(fresh, store.FSEXT_PRIVATE_BLOB)
	require.Error(t, getErr, "private blob must be removed after DeleteKey")
}

// TestLoadKeyPair_NilParent_ReturnsTypedError_Simulator is the error-handling
// counterpart: LoadKeyPair used to dereference keyAttrs.Parent.TPMAttributes
// unconditionally, so a nil Parent (e.g. a caller-assembled KeyAttributes
// that forgot to set one) paniced instead of failing gracefully. It must now
// return the typed store.ErrInvalidParentAttributes sentinel.
func TestLoadKeyPair_NilParent_ReturnsTypedError_Simulator(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()
	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN:           "no-parent-key",
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreTPM2,
	}

	_, err := tpmImpl.LoadKeyPair(keyAttrs, nil, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, store.ErrInvalidParentAttributes),
		"expected ErrInvalidParentAttributes, got %v", err)
}

// TestLoadKeyPairFromBlobs_NilParent_ReturnsTypedError_Simulator mirrors the
// above for LoadKeyPairFromBlobs, which had the identical defect.
func TestLoadKeyPairFromBlobs_NilParent_ReturnsTypedError_Simulator(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()
	tpmImpl := tpm.(*TPM2)

	keyAttrs := &types.KeyAttributes{
		CN:           "no-parent-key-blobs",
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreTPM2,
	}

	_, err := tpmImpl.LoadKeyPairFromBlobs(keyAttrs, nil, []byte("pub"), []byte("priv"))
	require.Error(t, err)
	require.True(t, errors.Is(err, store.ErrInvalidParentAttributes),
		"expected ErrInvalidParentAttributes, got %v", err)
}

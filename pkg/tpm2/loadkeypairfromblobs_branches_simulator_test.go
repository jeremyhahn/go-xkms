//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestLoadKeyPairFromBlobs_NilSession_BuildsItsOwnSession proves
// LoadKeyPairFromBlobs, when called with a nil session (as every real caller
// does -- the explicit-session parameter exists for callers that already
// hold one open), builds a working session itself via CreateSession rather
// than leaving ParentHandle.Auth unset.
func TestLoadKeyPairFromBlobs_NilSession_BuildsItsOwnSession(t *testing.T) {
	tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)
	tpmImpl := tpm.(*TPM2)

	const cn = "loadfromblobs-nil-session"
	genAttrs := &types.KeyAttributes{
		CN:            cn,
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		Parent:        srkAttrs,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	_, err := tpmImpl.CreateECDSA(genAttrs, backend, true)
	require.NoError(t, err)

	pub, err := backend.Get(genAttrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	priv, err := backend.Get(genAttrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)

	loadAttrs := &types.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
	}

	loadRsp, err := tpmImpl.LoadKeyPairFromBlobs(loadAttrs, nil, pub, priv)
	require.NoError(t, err, "LoadKeyPairFromBlobs must build its own session when none is supplied")
	require.NotNil(t, loadRsp)
	require.NotZero(t, loadRsp.ObjectHandle)

	_, err = tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(tpmImpl.transport)
	require.NoError(t, err)
}

// TestLoadKeyPairFromBlobs_EmptyParentName_ResolvesFromTPM proves the
// fallback path documented in LoadKeyPairFromBlobs: a KeyAttributes whose
// Parent carries only a persistent handle -- exactly what survives an app
// restart, since the cached config has no Name -- still loads, because the
// function reads the parent's Name back from the TPM instead of sending
// TPM2_Load with an empty one.
func TestLoadKeyPairFromBlobs_EmptyParentName_ResolvesFromTPM(t *testing.T) {
	tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)
	tpmImpl := tpm.(*TPM2)

	const cn = "loadfromblobs-empty-parent-name"
	genAttrs := &types.KeyAttributes{
		CN:            cn,
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		Parent:        srkAttrs,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	_, err := tpmImpl.CreateECDSA(genAttrs, backend, true)
	require.NoError(t, err)

	pub, err := backend.Get(genAttrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	priv, err := backend.Get(genAttrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)

	// A parent reconstructed from config alone: handle present, Name absent.
	bareParent := &types.KeyAttributes{
		CN:           srkAttrs.CN,
		Password:     srkAttrs.Password,
		KeyAlgorithm: srkAttrs.KeyAlgorithm,
		StoreType:    srkAttrs.StoreType,
		TPMAttributes: &types.TPMAttributes{
			Handle:    srkAttrs.TPMAttributes.Handle,
			Hierarchy: srkAttrs.TPMAttributes.Hierarchy,
		},
	}
	require.Empty(t, bareParent.TPMAttributes.Name.Buffer, "precondition: the parent Name must start empty")

	loadAttrs := &types.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.StoreTPM2,
		Parent:       bareParent,
	}

	loadRsp, err := tpmImpl.LoadKeyPairFromBlobs(loadAttrs, nil, pub, priv)
	require.NoError(t, err, "an empty parent Name must be resolved from the TPM, not sent empty to TPM2_Load")
	require.NotNil(t, loadRsp)
	require.NotEmpty(t, bareParent.TPMAttributes.Name.Buffer,
		"the resolved parent Name must be cached back onto the caller's KeyAttributes")

	_, err = tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}.Execute(tpmImpl.transport)
	require.NoError(t, err)
}

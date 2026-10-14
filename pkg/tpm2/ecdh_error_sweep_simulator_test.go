//go:build tpm_simulator

package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestECDHZGen_EveryCommandFailurePropagates sweeps ECDHZGen's command
// sequence (load, key session, encryption session, ECDH_ZGen) proving no TPM
// failure yields a shared secret.
func TestECDHZGen_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		attrs := saveDecryptCapableECCKey(t, h)
		peerPoint := newPeerPoint(t)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.ECDHZGen(attrs, peerPoint, h.Backend)
			return err
		}
	},
		// The last two commands are the deferred flushes of the encryption
		// session and the loaded key; they are logged, not returned.
		6, 7)
}

// saveDecryptCapableECCKey creates a decrypt-capable P-256 key under the SRK
// with TPM2_CreateLoaded and saves it to the harness backend, returning its
// attributes.
func saveDecryptCapableECCKey(t *testing.T, h *simHarness) *types.KeyAttributes {
	t.Helper()
	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	srkName, _, err := h.TPM.ReadHandle(srkAttrs.TPMAttributes.Handle)
	require.NoError(t, err)

	tmpl, err := KeyTemplateSpec{Algorithm: x509.ECDSA, Curve: elliptic.P256(), Decrypt: true}.Template()
	require.NoError(t, err)
	createRsp, err := tpm2.CreateLoaded{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkAttrs.TPMAttributes.Handle,
			Name:   srkName,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2BTemplate(&tmpl),
	}.Execute(h.TPM.transport)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:            "ecdh-sweep",
		Parent:        srkAttrs,
		KeyAlgorithm:  x509.ECDSA,
		StoreType:     types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
	}
	require.NoError(t, h.TPM.SaveKeyPair(attrs, createRsp.OutPrivate, createRsp.OutPublic, h.Backend, true))
	h.TPM.Flush(createRsp.ObjectHandle)
	return attrs
}

// newPeerPoint returns the public point of a fresh P-256 peer key.
func newPeerPoint(t *testing.T) *tpm2.TPMSECCPoint {
	t.Helper()
	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	raw, err := peer.PublicKey.Bytes()
	require.NoError(t, err)
	size := ecpoint.CoordinateSize(peer.Curve)
	return &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: raw[1 : 1+size]},
		Y: tpm2.TPM2BECCParameter{Buffer: raw[1+size:]},
	}
}

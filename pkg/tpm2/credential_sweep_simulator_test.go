//go:build tpm_simulator

package tpm2

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// credentialChallengeInputs returns the harness TPM's own EK certificate and
// IAK public area, the inputs a CA builds a credential challenge from.
func credentialChallengeInputs(t *testing.T, h *simHarness) (*x509.Certificate, []byte) {
	t.Helper()
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	_, iakTPMPub, err := h.TPM.ReadHandle(iakAttrs.TPMAttributes.Handle)
	require.NoError(t, err)
	iak2B := tpm2.New2B(iakTPMPub)
	return selfSignedCertForKey(t, ekPub), iak2B.Bytes()
}

// TestMakeCredentialWithExternalEK_EveryCommandFailurePropagates sweeps the
// CA-side challenge (load the IAK and EK publics, MakeCredential) proving no
// TPM failure yields a challenge.
func TestMakeCredentialWithExternalEK_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekCert, iakPub := credentialChallengeInputs(t, h)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, _, _, err := h.TPM.MakeCredentialWithExternalEK(ekCert, iakPub, nil)
			return err
		}
	},
		// The last two commands are the deferred flushes of the loaded EK
		// and IAK publics; they are logged, not returned.
		5, 6)
}

// TestActivateCredential_EveryCommandFailurePropagates sweeps credential
// activation (EK policy session, PolicySecret, ActivateCredential) proving no
// TPM failure yields the secret.
func TestActivateCredential_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekCert, iakPub := credentialChallengeInputs(t, h)
		blob, encSecret, _, err := h.TPM.MakeCredentialWithExternalEK(ekCert, iakPub, nil)
		require.NoError(t, err)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.ActivateCredential(blob, encSecret)
			return err
		}
	},
		// The last three commands are deferred flushes of the sessions and
		// loaded objects; they are logged, not returned.
		10, 11, 12)
}

// TestMakeCredentialWithExternalEK_EntropyFailure proves no challenge is
// built when the secret cannot be generated.
func TestMakeCredentialWithExternalEK_EntropyFailure(t *testing.T) {
	h := newSimHarness(t, nil)
	ekCert, iakPub := credentialChallengeInputs(t, h)
	h.TPM.random = failingReader{}

	blob, encSecret, secret, err := h.TPM.MakeCredentialWithExternalEK(ekCert, iakPub, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate secret")
	assert.Nil(t, blob)
	assert.Nil(t, encSecret)
	assert.Nil(t, secret)
}

// TestMakeCredentialWithExternalEK_OversizedSecretRefused proves a secret
// longer than the EK's name digest is refused by TPM2_MakeCredential rather
// than truncated.
func TestMakeCredentialWithExternalEK_OversizedSecretRefused(t *testing.T) {
	h := newSimHarness(t, nil)
	ekCert, iakPub := credentialChallengeInputs(t, h)

	blob, encSecret, secret, err := h.TPM.MakeCredentialWithExternalEK(ekCert, iakPub, bytes.Repeat([]byte{0x5a}, 128))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TPM2_MakeCredential failed")
	assert.Nil(t, blob)
	assert.Nil(t, encSecret)
	assert.Nil(t, secret)
}

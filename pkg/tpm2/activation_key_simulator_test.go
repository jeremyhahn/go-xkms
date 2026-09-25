//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateActivationKey_Success proves CreateActivationKey loads a
// transient key with a non-zero handle and a non-empty Name, in the null
// hierarchy (no hierarchy auth required to create it).
func TestCreateActivationKey_Success(t *testing.T) {
	h := newSimHarness(t, nil)

	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	require.NotNil(t, key)
	assert.NotZero(t, key.Handle)
	assert.NotEmpty(t, key.Name.Buffer)

	h.TPM.Flush(key.Handle)
}

// TestCreateActivationKey_TransportError proves CreateActivationKey returns
// the typed ErrActivationKeyCreate, not a bare TPM response error, when
// TPM2_CreatePrimary fails at the transport.
func TestCreateActivationKey_TransportError(t *testing.T) {
	h := newSimHarness(t, nil)
	h.TPM.transport = &createFaultyTransport{inner: h.TPM.transport, failCC: tpm2.TPMCCCreatePrimary}

	_, err := h.TPM.CreateActivationKey()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrActivationKeyCreate)
}

// TestCreateActivationKey_AnswerCredentialChallenge_RoundTrip proves the
// full software-verifier / real-device round trip: a challenge built by
// NewCredentialChallenge against a CreateActivationKey object's Name is
// answered correctly by AnswerCredentialChallenge on the same TPM, and the
// Name CreateActivationKey reports matches what ActivationKeyName computes
// purely in software from the same public area (the invariant a real,
// TPM-less verifier depends on).
func TestCreateActivationKey_AnswerCredentialChallenge_RoundTrip(t *testing.T) {
	h := newSimHarness(t, nil)

	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)

	wantName, err := ActivationKeyName(tpm2.Marshal(&key.Public))
	require.NoError(t, err)
	assert.Equal(t, wantName, key.Name.Buffer, "CreateActivationKey's Name must match a verifier's software computation")

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)

	challenge, secret, err := NewCredentialChallenge(ekPub, key.Name.Buffer)
	require.NoError(t, err)

	got, err := h.TPM.AnswerCredentialChallenge(key, challenge)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

// TestAnswerCredentialChallenge_WrongEK_Fails proves a challenge built
// against a public key that is NOT this TPM's real EK -- a copied or
// forged EK certificate -- cannot be answered, even by the exact activation
// key the challenge names: the TPM's real EK private key cannot decrypt a
// seed it was never encrypted to.
func TestAnswerCredentialChallenge_WrongEK_Fails(t *testing.T) {
	h := newSimHarness(t, nil)

	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	defer h.TPM.Flush(key.Handle)

	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	challenge, _, err := NewCredentialChallenge(&foreignKey.PublicKey, key.Name.Buffer)
	require.NoError(t, err)

	_, err = h.TPM.AnswerCredentialChallenge(key, challenge)
	require.Error(t, err)
}

// TestAnswerCredentialChallenge_WrongActivationKey_Fails proves a challenge
// bound to one activation key's Name cannot be answered by presenting a
// different activation key on the same TPM: the credential's integrity HMAC
// is computed over that exact Name, and TPM2_ActivateCredential's own
// integrity check refuses a mismatch even when the EK (and hence the
// decrypted seed) is correct.
//
// key2 is built with a different RSA modulus (1024 vs. CreateActivationKey's
// 2048) rather than by a second CreateActivationKey call: TPM2_CreatePrimary
// derives a Primary Object deterministically from (primary seed, template),
// so two CreateActivationKey calls in the same power cycle produce the
// identical key -- varying the template is what makes key2 a genuinely
// different key with a different Name.
func TestAnswerCredentialChallenge_WrongActivationKey_Fails(t *testing.T) {
	h := newSimHarness(t, nil)

	key1, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	defer h.TPM.Flush(key1.Handle)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	challenge, _, err := NewCredentialChallenge(ekPub, key1.Name.Buffer)
	require.NoError(t, err)

	key2 := createDistinctActivationKey(t, h.TPM)
	require.NotEqual(t, key1.Name.Buffer, key2.Name.Buffer, "the test requires two distinct keys")
	defer h.TPM.Flush(key2.Handle)

	_, err = h.TPM.AnswerCredentialChallenge(key2, challenge)
	require.Error(t, err)
}

// createDistinctActivationKey builds a null-hierarchy transient key exactly
// like CreateActivationKey, but with a 1024-bit RSA modulus instead of
// CreateActivationKey's fixed 2048-bit default, guaranteeing a different
// Primary Object (and therefore a different Name) from any key
// CreateActivationKey itself produced in the same power cycle.
func createDistinctActivationKey(t *testing.T, tpm *TPM2) *ActivationKey {
	t.Helper()

	template, err := tpm.KeyTemplate(KeyTemplateSpec{KeyBits: 1024})
	require.NoError(t, err)

	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHNull,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(template),
	}.Execute(tpm.transport)
	require.NoError(t, err)

	pub, err := rsp.OutPublic.Contents()
	require.NoError(t, err)

	return &ActivationKey{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Public: *pub,
	}
}

// TestNewCredentialChallenge_AnsweredByRealActivateCredential_IAK proves the
// software-built challenge -- the same construction pkg/ca's
// VerifyTCG_CSR_IDevIDBytes now uses, via ActivationKeyName +
// NewCredentialChallenge against a TCG-CSR-IDEVID's EkCert/AttestPub bytes
// -- is answered correctly by the real device's IAK-bound ActivateCredential.
// This is the byte-for-byte compatibility proof that the pkg/ca refactor
// (go-xkms#798) left enroll-01's wire behaviour unchanged: the CA no longer
// needs a TPM to build this exact challenge.
func TestNewCredentialChallenge_AnsweredByRealActivateCredential_IAK(t *testing.T) {
	h := newIdentityHarness(t, EnrollmentStrategyIAK, false)
	csr := h.csr(t)

	activationKeyName, err := ActivationKeyName(csr.CsrContents.AttestPub)
	require.NoError(t, err)
	require.NotEmpty(t, activationKeyName)
	assert.Equal(t, h.IAK.TPMAttributes.Name.Buffer, activationKeyName,
		"the Name computed in software from AttestPub must equal the IAK's real TPM-computed Name")

	challenge, secret, err := NewCredentialChallenge(h.EKCert.PublicKey, activationKeyName)
	require.NoError(t, err)

	got, err := h.TPM.ActivateCredential(challenge.CredentialBlob, challenge.EncryptedSecret)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

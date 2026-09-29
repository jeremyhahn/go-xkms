//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sealedKeyAttrs builds key attributes for a keyed-hash sealed object whose
// parent is the SSRK. The SSRK itself carries no platform policy, so the
// parent authorization is a plain password session and the only policy under
// test is the one attached to the sealed object itself.
func sealedKeyAttrs(t *testing.T, h *simHarness, cn string, platformPolicy bool, password types.Password) *types.KeyAttributes {
	t.Helper()

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	return &types.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeHMAC,
		Parent:       srkAttrs,
		Password:     password,
		TPMPolicy:    platformPolicyName(platformPolicy),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
}

// platformPolicySRKConfig puts the harness's PLATFORM SRK into the shape a real
// deployment uses: platform-srk.platform-policy enabled. The user PIN itself
// is installed as the SRK's auth value later, by PlatformKeyStore.Initialize
// or directly by the test through platformPolicySRKAttrs/createPlatformPolicySRK
// -- PlatformSRKConfig carries no auth field of its own for a caller to set
// here. The platform SRK's own PolicyOR therefore governs TPM2_Load of every
// object beneath it.
//
// The shared SRK is deliberately left alone: it cannot be given a platform
// policy at all, so it is not the key these recovery journeys are about.
func platformPolicySRKConfig() func(*Config) {
	return func(config *Config) {
		config.PlatformSRK.PlatformPolicy = true
	}
}

// platformPolicySRKAttrs builds the platform SRK attributes exactly the way the
// platform key store builds them (PlatformSRKAttributesFromConfig): SSRK algorithm and
// key parameters, at the platform SRK's own handle, carrying the platform
// policy taken from PlatformSRKConfig.
//
// TPM2.SSRKAttributes deliberately reports neither a policy nor a password --
// it reads the handle back from the TPM -- so it cannot be used to exercise an
// SRK's own authorization policy. password is supplied by the caller so a test
// can present the right PIN, the wrong one, or none at all.
func platformPolicySRKAttrs(t *testing.T, h *simHarness, password types.Password) *types.KeyAttributes {
	t.Helper()

	attrs, err := PlatformSRKAttributesFromConfig(h.TPM.config)
	require.NoError(t, err)
	require.Equal(t, tpm2.TPMHandle(h.TPM.config.PlatformSRK.SRKHandle),
		attrs.TPMAttributes.Handle)

	// Provision installs no owner hierarchy authorization in the harness, so
	// the configured hierarchy auth would be rejected with TPM_RC_BAD_AUTH.
	attrs.TPMAttributes.HierarchyAuth = nil
	attrs.Password = password

	return attrs
}

// createPlatformPolicySRK creates the platform SRK the way
// PlatformKeyStore.Initialize does: after provisioning, with the user PIN as
// its auth value.
//
// The timing matters. Provision creates the SHARED SRK inside ProvisionOwner
// and only afterwards calls CreatePlatformPolicy, which extends the golden
// measurement into the platform PCR -- so a shared SRK created with
// PlatformPolicy carries a policy computed from a PCR state that no longer
// exists by the time provisioning returns. The platform SRK is created after
// that extend, so its policy describes the state the machine is actually
// running in, which is what makes it usable as a baseline here.
func createPlatformPolicySRK(t *testing.T, h *simHarness, pin types.Password) *types.KeyAttributes {
	t.Helper()

	srkAttrs := platformPolicySRKAttrs(t, h, pin)
	require.True(t, (srkAttrs.TPMPolicy == types.TPMPolicyPlatform), "the SRK under test must carry the platform policy")
	require.NoError(t, h.TPM.CreateSRK(srkAttrs))

	return srkAttrs
}

// sealedKeyAttrsUnder builds sealed-object attributes beneath an explicit
// parent, so a test can choose how the parent itself is authorized.
func sealedKeyAttrsUnder(
	parent *types.KeyAttributes,
	cn string,
	password types.Password) *types.KeyAttributes {

	return &types.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeHMAC,
		Parent:       parent,
		Password:     password,
		TPMPolicy:    types.TPMPolicyPlatform,
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
}

// TestSealUnseal_PINRecoveryThroughPlatformPolicySRK is the end-to-end recovery
// journey on the DEFAULT configuration, where SSRK.PlatformPolicy is enabled.
//
// Pinning the sealed object alone was not enough there. The object's parent is
// itself a platform-policy key, so TPM2_Load was refused on the SRK's own
// PolicyOR -- recomputed from live PCRs -- before the object's PIN branch was
// ever reached. The PIN opened nothing on the only configuration that ships.
//
// The SRK now records the same kind of pin when it is created, and its password
// branch rebuilds its PolicyPCR operand from that record. Note what this does
// NOT change: TPM2_CreatePrimary still derives the SRK from the seed and the
// template exactly as before, so no existing SRK is invalidated. Only the
// authorization of an already-persisted SRK is repaired.
//
// Both policies are exercised here: the SRK's, at TPM2_Load, and the object's,
// at TPM2_Unseal.
func TestSealUnseal_PINRecoveryThroughPlatformPolicySRK(t *testing.T) {
	h := newSimHarness(t, platformPolicySRKConfig())

	srk := createPlatformPolicySRK(t, h, mustPassword([]byte("srk-recovery-pin")))

	secret := []byte("recoverable-through-both-policies")
	keyAttrs := sealedKeyAttrsUnder(srk, "srk-policy-sealed",
		mustPassword([]byte("object-recovery-pin")))
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	got, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err, "the object must open on the platform state it was sealed on")
	require.Equal(t, secret, got)

	// The machine boots different software.
	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	recovered, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err,
		"the PINs must recover the object end to end: TPM2_Load under the SRK and TPM2_Unseal of the object")
	assert.Equal(t, secret, recovered)
}

// TestSealUnseal_PlatformPolicySRK_PCRBranchesStillFailAfterExtend proves the
// platform binding survives at BOTH levels. Making the SRK's password branch
// pin-stable must not make its PCR branch pin-stable: an unattended boot, which
// has no PIN to offer, must still be refused on a changed platform.
func TestSealUnseal_PlatformPolicySRK_PCRBranchesStillFailAfterExtend(t *testing.T) {
	h := newSimHarness(t, platformPolicySRKConfig())

	srkPIN := mustPassword([]byte("srk-recovery-pin"))
	srk := createPlatformPolicySRK(t, h, srkPIN)
	secret := []byte("bound-to-the-sealed-platform-state")

	keyAttrs := sealedKeyAttrsUnder(srk, "srk-policy-pcr-branch",
		mustPassword([]byte("object-recovery-pin")))
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	// Baseline: with no PIN anywhere, the PCR branches open the object while
	// the platform state is unchanged. Without this the assertions below would
	// pass even if the PCR branches were broken outright.
	unattended := sealedKeyAttrsUnder(
		platformPolicySRKAttrs(t, h, nil), "srk-policy-pcr-branch", nil)
	got, err := h.TPM.UnsealKey(unattended, h.Backend)
	require.NoError(t, err, "the PCR branches must open the object on the sealed platform state")
	require.Equal(t, secret, got)

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	// The SRK's PCR branch: refused at TPM2_Load, before the object is
	// even loaded.
	out, err := h.TPM.UnsealKey(unattended, h.Backend)
	require.Error(t, err, "the SRK's PCR branch must not survive a platform change")
	assert.Nil(t, out)
	assert.Equal(t, ErrPolicyCheckFailed, err)

	// The object's PCR branch, reached by authorizing the SRK with its PIN:
	// refused at TPM2_Unseal.
	objectPCRBranch := sealedKeyAttrsUnder(
		platformPolicySRKAttrs(t, h, srkPIN), "srk-policy-pcr-branch", nil)
	out, err = h.TPM.UnsealKey(objectPCRBranch, h.Backend)
	require.Error(t, err, "the object's PCR branch must not survive a platform change")
	assert.Nil(t, out)
	assert.Equal(t, ErrPolicyCheckFailed, err)
}

// TestSealUnseal_WrongSRKPINAfterExtend_Rejected proves the SRK's recovery path
// still demands the SRK's auth value. The pin record removes the PCR coupling
// of the OR digest; it does not remove the PIN requirement, which the TPM
// enforces through the session HMAC (TPM 2.0 Part 1, Section 19.6).
func TestSealUnseal_WrongSRKPINAfterExtend_Rejected(t *testing.T) {
	h := newSimHarness(t, platformPolicySRKConfig())

	secret := []byte("guarded-by-the-srk-pin")
	correct := mustPassword([]byte("srk-recovery-pin"))
	srk := createPlatformPolicySRK(t, h, correct)

	keyAttrs := sealedKeyAttrsUnder(srk, "srk-policy-wrong-pin",
		mustPassword([]byte("object-recovery-pin")))
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	wrong := sealedKeyAttrsUnder(
		platformPolicySRKAttrs(t, h, mustPassword([]byte("not-the-srk-pin"))),
		"srk-policy-wrong-pin", mustPassword([]byte("object-recovery-pin")))
	out, err := h.TPM.UnsealKey(wrong, h.Backend)
	require.Error(t, err, "a wrong SRK PIN must not load the object")
	assert.Nil(t, out)
	assert.True(t, isTPMAuthError(err) || isTPMBadAuth(err),
		"expected a TPM authorization failure, got %v", err)

	// The correct SRK PIN must still recover it: the rejection must be of the
	// caller, not of the object.
	recovered, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	assert.Equal(t, secret, recovered)
}

// TestSealUnseal_SRKWithoutPolicyPin_BehavesAsBefore is the SRK's backward
// compatibility case: an SRK persisted before pins existed has no record, and
// must keep authorizing exactly as it did. Deleting the record reproduces that
// on-disk state precisely.
//
// After a platform change such an SRK refuses TPM2_Load on both branches, which
// is the behaviour every deployment had before this change -- and the proof
// that the recovery above comes from the record rather than from some general
// weakening of the SRK's policy.
func TestSealUnseal_SRKWithoutPolicyPin_BehavesAsBefore(t *testing.T) {
	h := newSimHarness(t, platformPolicySRKConfig())

	srkPIN := mustPassword([]byte("srk-recovery-pin"))
	srk := createPlatformPolicySRK(t, h, srkPIN)

	secret := []byte("sealed-under-a-pre-pin-srk")
	keyAttrs := sealedKeyAttrsUnder(srk, "pre-pin-srk-object",
		mustPassword([]byte("object-recovery-pin")))
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	// The SRK's pin record is written by CreateSRK under a handle-qualified
	// name; removing it leaves the SRK in its pre-change form.
	pinAttrs := primaryPolicyPinAttrs(srk)
	require.NotNil(t, pinAttrs)
	_, err = h.Backend.Get(pinAttrs, store.FSEXT_PLATFORM_POLICY)
	require.NoError(t, err, "creating a platform-policy SRK must record its pin")
	require.NoError(t, h.Backend.Delete(pinAttrs))

	// Unchanged platform state: the SRK opens with or without a record.
	got, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err, "a pre-change SRK must keep authorizing as it did")
	assert.Equal(t, secret, got)

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	out, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.Error(t, err,
		"without a record the SRK's PIN branch cannot rebuild its OR digest, exactly as before")
	assert.Nil(t, out)
	assert.Equal(t, ErrPolicyCheckFailed, err)
}

// TestCreateSRK_RecordsPinPerHandle proves two platform-policy primaries built
// from the same configuration do not share a pin record. They carry the same
// CN and differ only by persistent handle; a single record name would let
// whichever was created last overwrite the other's pin and silently lock the
// other's PIN branch out.
//
// The pair used here is the platform SRK and a second platform-policy primary
// at the next handle, created after a measurement change. The shared SRK is not
// one of them: it carries no platform policy and therefore records no pin at
// all — which TestProvision_SSRKRecordsNoPolicyPin asserts directly.
func TestCreateSRK_RecordsPinPerHandle(t *testing.T) {
	h := newSimHarness(t, platformPolicySRKConfig())

	first := createPlatformPolicySRK(t, h, mustPassword([]byte("first-srk-pin")))

	// The machine measures something new between the two creations, so the two
	// records must describe different platform states.
	h.extendPlatformPCR(t, []byte("measured-between-the-two-srks"))

	second := platformPolicySRKAttrs(t, h, mustPassword([]byte("second-srk-pin")))
	second.TPMAttributes.Handle = first.TPMAttributes.Handle + 1
	require.NoError(t, h.TPM.CreateSRK(second))

	require.Equal(t, first.CN, second.CN,
		"the two SRKs are expected to share a CN; the handle is what separates them")
	require.NotEqual(t, first.TPMAttributes.Handle, second.TPMAttributes.Handle)

	firstPin := primaryPolicyPinAttrs(first)
	secondPin := primaryPolicyPinAttrs(second)
	require.NotEqual(t, firstPin.CN, secondPin.CN,
		"each persistent handle must own its pin record")

	firstRecord, err := h.Backend.Get(firstPin, store.FSEXT_PLATFORM_POLICY)
	require.NoError(t, err, "creating the second SRK must not remove the first's record")
	secondRecord, err := h.Backend.Get(secondPin, store.FSEXT_PLATFORM_POLICY)
	require.NoError(t, err)

	firstDecoded, err := store.UnmarshalPlatformPolicyPin(firstRecord)
	require.NoError(t, err)
	secondDecoded, err := store.UnmarshalPlatformPolicyPin(secondRecord)
	require.NoError(t, err)

	// The two records describe different platform states, which is exactly
	// what a shared record would have destroyed.
	assert.NotEqual(t, firstDecoded.PCRDigest, secondDecoded.PCRDigest,
		"each SRK's record must describe the platform state that SRK was created on")

	live, err := h.TPM.PlatformPolicyDigestHash()
	require.NoError(t, err)
	assert.Equal(t, live, secondDecoded.PCRDigest,
		"the second SRK was created on the current platform state")
}

// platformPolicyChildAttrs builds attributes for a platform-policy child key
// beneath the harness's shared SRK. The shared SRK carries no platform policy
// in the harness, so the parent authorizes with a plain password session and
// the only policy under test is the child key's own.
func platformPolicyChildAttrs(
	t *testing.T,
	h *simHarness,
	cn string,
	algorithm x509.PublicKeyAlgorithm,
	password types.Password) *types.KeyAttributes {

	t.Helper()

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 cn,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       algorithm,
		KeyType:            types.KeyTypeSigning,
		Parent:             srkAttrs,
		Password:           password,
		TPMPolicy:          types.TPMPolicyPlatform,
		SignatureAlgorithm: x509.SHA256WithRSA,
		StoreType:          types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	switch algorithm {
	case x509.RSA:
		attrs.RSAAttributes = &types.RSAAttributes{KeySize: 2048}
	case x509.ECDSA:
		attrs.SignatureAlgorithm = x509.ECDSAWithSHA256
		attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P256()}
	}

	return attrs
}

// TestCreateRSA_PINSignsAfterPCRExtend is the recovery journey for a
// platform-policy RSA signing key.
//
// A signing key is not sealed data: nothing about it is released by
// TPM2_Unseal, so the operation that proves recovery is a signature. Before
// the key recorded its platform policy pin, a PCR change made its PolicyOR
// digest unreachable on both branches, so a key with a recovery PIN could not
// sign on a machine whose measurements had moved -- the same defect the sealed
// objects had, on the keys that issue certificates and terminate TLS.
//
// The second half is what keeps the platform binding honest: on the same key,
// after the same extend, the PCR branch is still refused.
func TestCreateRSA_PINSignsAfterPCRExtend(t *testing.T) {
	h := newSimHarness(t, nil)

	pin := mustPassword([]byte("rsa-recovery-pin"))
	attrs := platformPolicyChildAttrs(t, h, "rsa-pin-key", x509.RSA, pin)

	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)
	require.NotNil(t, pub)

	digest := sha256.Sum256([]byte("payload signed across a platform change"))

	// Baseline: the key signs on the platform state it was created on.
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature))

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	// The PIN must still authorize a signature, and it must verify under the
	// public key the TPM returned at creation.
	recovered, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err, "the PIN must still authorize signing after a platform change")
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], recovered),
		"a recovered signature must verify under the key's own public half")

	// The PCR branch of the same key must not survive the change.
	pcrBranch := platformPolicyChildAttrs(t, h, "rsa-pin-key", x509.RSA, nil)
	out, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: pcrBranch,
		Backend:       h.Backend,
	})
	require.Error(t, err, "the PCR branch must not sign on a changed platform")
	assert.Nil(t, out)
	assert.Equal(t, ErrPolicyCheckFailed, err)
}

// TestCreateRSA_WrongPINAfterPCRExtend_Rejected proves the recovered signing
// path still demands the key's own auth value.
func TestCreateRSA_WrongPINAfterPCRExtend_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := platformPolicyChildAttrs(t, h, "rsa-wrong-pin-key", x509.RSA,
		mustPassword([]byte("rsa-recovery-pin")))
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	digest := sha256.Sum256([]byte("payload a wrong PIN must not sign"))
	wrong := platformPolicyChildAttrs(t, h, "rsa-wrong-pin-key", x509.RSA,
		mustPassword([]byte("not-the-rsa-pin")))

	out, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: wrong,
		Backend:       h.Backend,
	})
	require.Error(t, err, "a wrong PIN must not produce a signature")
	assert.Nil(t, out)
	assert.True(t, isTPMAuthError(err) || isTPMBadAuth(err),
		"expected a TPM authorization failure, got %v", err)
}

// TestCreateECDSA_PINSignsAfterPCRExtend is the ECDSA counterpart to
// TestCreateRSA_PINSignsAfterPCRExtend.
func TestCreateECDSA_PINSignsAfterPCRExtend(t *testing.T) {
	h := newSimHarness(t, nil)

	pin := mustPassword([]byte("ecdsa-recovery-pin"))
	attrs := platformPolicyChildAttrs(t, h, "ecdsa-pin-key", x509.ECDSA, pin)

	pub, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)
	require.NotNil(t, pub)

	digest := sha256.Sum256([]byte("ecdsa payload signed across a platform change"))

	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err)
	require.True(t, ecdsa.VerifyASN1(pub, digest[:], signature))

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	recovered, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err, "the PIN must still authorize signing after a platform change")
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], recovered),
		"a recovered signature must verify under the key's own public half")

	pcrBranch := platformPolicyChildAttrs(t, h, "ecdsa-pin-key", x509.ECDSA, nil)
	out, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: pcrBranch,
		Backend:       h.Backend,
	})
	require.Error(t, err, "the PCR branch must not sign on a changed platform")
	assert.Nil(t, out)
	assert.Equal(t, ErrPolicyCheckFailed, err)
}

// encryptWithSecretKey runs TPM2_EncryptDecrypt2 against a stored AES key,
// authorizing it through the production session builder. A symmetric cipher
// object has no wrapper in this package, and it is the authorization that is
// under test, not the cipher.
func encryptWithSecretKey(
	t *testing.T,
	h *simHarness,
	attrs *types.KeyAttributes,
	plaintext []byte) ([]byte, error) {

	t.Helper()

	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err, "loading authorizes the parent, which is not what this test varies")
	defer h.TPM.Flush(loaded.ObjectHandle)

	session, closer, err := h.TPM.CreateKeySession(attrs)
	if err != nil {
		return nil, err
	}
	defer func() {
		require.NoError(t, closer())
	}()

	rsp, err := tpm2.EncryptDecrypt2{
		KeyHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   session,
		},
		Message: tpm2.TPM2BMaxBuffer{Buffer: plaintext},
		Decrypt: false,
		Mode:    tpm2.TPMAlgCFB,
		IV:      tpm2.TPM2BIV{Buffer: make([]byte, 16)},
	}.Execute(h.TPM.Transport())
	if err != nil {
		return nil, err
	}

	return rsp.OutData.Buffer, nil
}

// TestCreateSecretKey_PINEncryptsAfterPCRExtend is the recovery journey for a
// platform-policy AES key.
//
// This key kind needed a second fix as well: CreateSecretKey passed no
// InSensitive at all, so the object was created with an empty UserAuth and its
// PolicyAuthValue branch could never be satisfied by any PIN -- the same
// structural defect sealed objects had. A PIN is now installed as the key's
// auth value, and the platform policy pin makes that branch survive a platform
// change.
func TestCreateSecretKey_PINEncryptsAfterPCRExtend(t *testing.T) {
	h := newSimHarness(t, nil)

	pin := mustPassword([]byte("aes-recovery-pin"))
	attrs := platformPolicyChildAttrs(t, h, "aes-pin-key", x509.RSA, pin)
	attrs.KeyType = types.KeyTypeHMAC

	require.NoError(t, h.TPM.CreateSecretKey(attrs, h.Backend))

	plaintext := []byte("sixteen bytes ..")

	baseline, err := encryptWithSecretKey(t, h, attrs, plaintext)
	require.NoError(t, err, "the key must encrypt on the platform state it was created on")
	require.NotEmpty(t, baseline)
	require.NotEqual(t, plaintext, baseline)

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	recovered, err := encryptWithSecretKey(t, h, attrs, plaintext)
	require.NoError(t, err, "the PIN must still authorize the key after a platform change")
	assert.Equal(t, baseline, recovered,
		"the recovered key must be the same key, producing the same ciphertext")

	// The PCR branch of the same key must not survive the change.
	pcrBranch := platformPolicyChildAttrs(t, h, "aes-pin-key", x509.RSA, nil)
	pcrBranch.KeyType = types.KeyTypeHMAC
	out, err := encryptWithSecretKey(t, h, pcrBranch, plaintext)
	require.Error(t, err, "the PCR branch must not authorize the key on a changed platform")
	assert.Nil(t, out)
	assert.Equal(t, ErrPolicyCheckFailed, err)
}

// TestCreateSecretKey_WrongPINAfterPCRExtend_Rejected proves the AES key's
// recovered path still demands its auth value.
func TestCreateSecretKey_WrongPINAfterPCRExtend_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := platformPolicyChildAttrs(t, h, "aes-wrong-pin-key", x509.RSA,
		mustPassword([]byte("aes-recovery-pin")))
	attrs.KeyType = types.KeyTypeHMAC
	require.NoError(t, h.TPM.CreateSecretKey(attrs, h.Backend))

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	wrong := platformPolicyChildAttrs(t, h, "aes-wrong-pin-key", x509.RSA,
		mustPassword([]byte("not-the-aes-pin")))
	wrong.KeyType = types.KeyTypeHMAC

	out, err := encryptWithSecretKey(t, h, wrong, []byte("sixteen bytes .."))
	require.Error(t, err, "a wrong PIN must not authorize the key")
	assert.Nil(t, out)
	assert.True(t, isTPMAuthError(err) || isTPMBadAuth(err),
		"expected a TPM authorization failure, got %v", err)
}

// TestPlatformPolicyChildKeys_RecordPinBesideTheirBlobs proves each child key
// kind records its pin under its own name, and that the record shares the
// blobs' collision domain: two keys that could overwrite one another's record
// would already be overwriting one another's key material.
func TestPlatformPolicyChildKeys_RecordPinBesideTheirBlobs(t *testing.T) {
	h := newSimHarness(t, nil)

	live, err := h.TPM.PlatformPolicyDigestHash()
	require.NoError(t, err)

	rsaAttrs := platformPolicyChildAttrs(t, h, "rsa-record", x509.RSA,
		mustPassword([]byte("pin")))
	_, err = h.TPM.CreateRSA(rsaAttrs, h.Backend, true)
	require.NoError(t, err)

	eccAttrs := platformPolicyChildAttrs(t, h, "ecdsa-record", x509.ECDSA,
		mustPassword([]byte("pin")))
	_, err = h.TPM.CreateECDSA(eccAttrs, h.Backend, true)
	require.NoError(t, err)

	aesAttrs := platformPolicyChildAttrs(t, h, "aes-record", x509.RSA,
		mustPassword([]byte("pin")))
	aesAttrs.KeyType = types.KeyTypeHMAC
	require.NoError(t, h.TPM.CreateSecretKey(aesAttrs, h.Backend))

	for _, attrs := range []*types.KeyAttributes{rsaAttrs, eccAttrs, aesAttrs} {
		record, err := h.Backend.Get(attrs, store.FSEXT_PLATFORM_POLICY)
		require.NoError(t, err, "%s must record its platform policy pin", attrs.CN)

		pin, err := store.UnmarshalPlatformPolicyPin(record)
		require.NoError(t, err)
		assert.Equal(t, live, pin.PCRDigest,
			"%s must record the platform state it was created on", attrs.CN)

		// The record lives and dies with the key material it describes.
		require.NoError(t, h.TPM.DeleteKeyPair(attrs, h.Backend))
		_, err = h.Backend.Get(attrs, store.FSEXT_PLATFORM_POLICY)
		assert.Error(t, err, "%s: deleting the key must delete its pin", attrs.CN)
	}

	// A key created without the platform policy has no policy to pin.
	unbound := platformPolicyChildAttrs(t, h, "unbound-record", x509.RSA, nil)
	unbound.TPMPolicy = ""
	_, err = h.TPM.CreateRSA(unbound, h.Backend, true)
	require.NoError(t, err)

	_, err = h.Backend.Get(unbound, store.FSEXT_PLATFORM_POLICY)
	assert.Error(t, err, "a key with no platform policy must not record a pin")
}

// TestSealUnseal_PCRMismatch_UnsealFailsAfterPCRExtend is the core security
// property of PCR-bound sealing: data sealed under one platform state must not
// be releasable once that state changes.
//
// The test seals a secret with PlatformPolicy enabled (which attaches the
// PolicyOR(PolicyPCR, PolicyAuthValue) digest computed over the *current*
// platform PCR to the sealed object), proves it round-trips, then extends the
// platform PCR -- simulating a boot with different firmware/software -- and
// proves the same unseal now fails with a TPM policy failure and returns no
// plaintext.
//
// A regression that silently dropped the AuthPolicy from the sealed object, or
// that made PlatformPolicySession satisfy a stale policy, would make the second
// unseal succeed and fail this test.
func TestSealUnseal_PCRMismatch_UnsealFailsAfterPCRExtend(t *testing.T) {
	h := newSimHarness(t, nil)

	secret := []byte("golden-platform-state-secret-0123")
	keyAttrs := sealedKeyAttrs(t, h, "pcr-bound-secret", true, nil)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err, "sealing under the current PCR state must succeed")

	// Baseline: the same PCR state releases the secret.
	got, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err, "unsealing under the unchanged PCR state must succeed")
	require.Equal(t, secret, got, "the unsealed plaintext must match what was sealed")

	// Platform state changes.
	h.extendPlatformPCR(t, []byte("a-different-boot-measurement"))

	// The secret must now be unreachable.
	after, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.Error(t, err, "unsealing after a PCR change must fail")
	assert.Nil(t, after, "no plaintext may be returned when the policy check fails")
	assert.Equal(t, ErrPolicyCheckFailed, err,
		"the TPM must reject the unseal with TPM_RC_POLICY_FAIL, got %v", err)
}

// TestSealUnseal_PlatformPolicyWithPassword_PINBranchOpensTheObject is the
// PIN-fallback regression test.
//
// PlatformPolicySession implements a PolicyOR whose second branch is a
// password-based PIN fallback, and CreateKeySession selects that branch whenever
// the key attributes carry a non-empty Password. But sealKeyInternal installed
// the caller's password as the sealed object's UserAuth only when PlatformPolicy
// was *disabled*:
//
//	if keyAttrs.Password != nil && !keyAttrs.PlatformPolicy {
//	        keyUserAuth = keyAttrs.Password.Bytes()
//	}
//
// An object sealed with BOTH a Password and PlatformPolicy therefore had an
// empty UserAuth, while every unseal of it authorized through PolicyAuthValue
// with the PIN bound into the session HMAC (TPM 2.0 Part 1, Section 19.6). The
// HMAC keys never agreed, so the TPM answered TPM_RC_AUTH_FAIL -- and because
// that is an auth failure rather than a policy failure it also incremented the
// dictionary-attack counter, so repeated attempts locked the TPM out.
//
// The condition is gone: an object sealed with a password now carries it, and
// both branches of the PolicyOR open the object.
func TestSealUnseal_PlatformPolicyWithPassword_PINBranchOpensTheObject(t *testing.T) {
	h := newSimHarness(t, nil)

	pin := mustPassword([]byte("recovery-pin-9876"))
	secret := []byte("secret-with-pin-fallback")

	keyAttrs := sealedKeyAttrs(t, h, "pcr-bound-with-pin", true, pin)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	// The PIN branch must open the object it was sealed with.
	out, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err, "the PIN branch must open the object it sealed")
	assert.Equal(t, secret, out)

	// The PCR branch must keep working on the same object: installing the
	// UserAuth must not have cost the PolicyPCR path.
	pcrBranch := sealedKeyAttrs(t, h, "pcr-bound-with-pin", true, nil)
	got, err := h.TPM.UnsealKey(pcrBranch, h.Backend)
	require.NoError(t, err, "the PCR branch must still open the object")
	assert.Equal(t, secret, got)
}

// TestSealUnseal_PINBranchRecoversAfterPCRExtend is the recovery journey the
// PIN fallback exists for, and the behaviour this file previously documented as
// impossible.
//
// The platform policy is PolicyOR(PolicyPCR, PolicyAuthValue), and the OR
// digest an object is created with covers BOTH branch digests. While the
// PolicyPCR branch digest was recomputed from live PCRs at every unseal, moving
// the PCRs changed the OR digest itself -- so the PIN branch stopped matching
// the object's AuthPolicy too, and a PIN could not recover a machine whose
// measurements had changed. The PIN was a recovery mechanism that only worked
// when nothing needed recovering.
//
// Sealing now records the PCR state its policy was computed from beside the key
// blobs, and the PIN branch rebuilds the PolicyPCR branch digest from that
// record instead of from live PCRs. The OR digest is therefore stable across a
// platform change and a correct PIN still opens the object.
//
// The platform binding is not weakened, and the second half of this test is
// what proves it: on the very same object, after the very same extend, the PCR
// branch is still refused by the TPM with TPM_RC_POLICY_FAIL. If the PolicyPCR
// binding were dropped or pinned as well, the first unseal in this test (before
// any extend) would keep working while this assertion started failing.
func TestSealUnseal_PINBranchRecoversAfterPCRExtend(t *testing.T) {
	h := newSimHarness(t, nil)

	pin := mustPassword([]byte("recovery-pin-9876"))
	secret := []byte("secret-with-pin-fallback")

	keyAttrs := sealedKeyAttrs(t, h, "pcr-bound-with-pin", true, pin)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	// Baseline: the object opens on the platform state it was sealed on.
	got, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	// The machine boots different software.
	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	// The recovery PIN must still return the exact plaintext.
	recovered, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err, "the PIN branch must recover a machine whose PCRs moved")
	assert.Equal(t, secret, recovered,
		"PIN recovery must return the sealed plaintext, not a truncated or re-derived value")

	// The PCR branch of the same object must remain bound to the platform
	// state it was sealed on.
	pcrBranch := sealedKeyAttrs(t, h, "pcr-bound-with-pin", true, nil)
	out, err := h.TPM.UnsealKey(pcrBranch, h.Backend)
	require.Error(t, err, "the PCR branch must not survive a platform change")
	assert.Nil(t, out, "no plaintext may be returned when the platform state does not match")
	assert.Equal(t, ErrPolicyCheckFailed, err,
		"the TPM must reject the PCR branch with TPM_RC_POLICY_FAIL, got %v", err)
}

// TestSealUnseal_WrongPINAfterPCRExtend_Rejected is the counterpart to the
// recovery test: making the PIN branch survive a platform change must not make
// it survive a wrong PIN. The PolicyOR digest is reachable with any PIN -- it is
// only an operand list -- so what has to reject the caller is the object's own
// UserAuth, bound into the session HMAC by PolicyAuthValue (TPM 2.0 Part 1,
// Section 19.6).
func TestSealUnseal_WrongPINAfterPCRExtend_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	secret := []byte("only-the-right-pin-opens-this")
	keyAttrs := sealedKeyAttrs(t, h, "pcr-bound-wrong-pin", true,
		mustPassword([]byte("recovery-pin-9876")))
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	wrongPIN := sealedKeyAttrs(t, h, "pcr-bound-wrong-pin", true,
		mustPassword([]byte("not-the-recovery-pin")))
	out, err := h.TPM.UnsealKey(wrongPIN, h.Backend)
	require.Error(t, err, "a wrong PIN must not open the object")
	assert.Nil(t, out, "no plaintext may be returned to a caller with the wrong PIN")
	assert.True(t, isTPMAuthError(err) || isTPMBadAuth(err),
		"expected a TPM authorization failure, got %v", err)

	// The correct PIN must still work afterwards: the rejection must be of
	// the caller, not of the object.
	recovered, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	assert.Equal(t, secret, recovered)
}

// legacyKeyBackend presents the pre-pin on-disk form of a sealed object: the
// public and private areas only, with no platform policy record. Writes of the
// record are dropped, and reads report the same not-found the store reports for
// an object sealed before the record existed.
type legacyKeyBackend struct {
	store.KeyBackend
}

func (b *legacyKeyBackend) Get(attrs *types.KeyAttributes, ext types.FSExtension) ([]byte, error) {
	if ext == store.FSEXT_PLATFORM_POLICY {
		return nil, storage.ErrNotFound
	}
	return b.KeyBackend.Get(attrs, ext)
}

func (b *legacyKeyBackend) Save(
	attrs *types.KeyAttributes, data []byte, ext types.FSExtension, overwrite bool) error {

	if ext == store.FSEXT_PLATFORM_POLICY {
		return nil
	}
	return b.KeyBackend.Save(attrs, data, ext, overwrite)
}

// TestSealUnseal_ObjectWithoutPolicyPin_StillOpens is the backward
// compatibility test. Objects sealed before the platform policy pin existed
// have only their public and private areas on disk, and they must keep
// unsealing exactly as they did -- nothing may be re-sealed or migrated behind
// the operator's back.
//
// The object here is sealed through a backend that drops the pin record, which
// leaves the store in precisely the pre-change form; every unseal below then
// runs against the real store, where the record is genuinely absent.
//
// The second half asserts the old limitation is still the old objects' fate:
// with no record there is nothing to rebuild the PolicyPCR branch digest from,
// so the PIN branch of a pre-change object still cannot survive a PCR change.
// That is what proves the legacy path is really the legacy path and not the new
// one with a different name.
func TestSealUnseal_ObjectWithoutPolicyPin_StillOpens(t *testing.T) {
	h := newSimHarness(t, nil)

	legacy := &legacyKeyBackend{KeyBackend: h.Backend}
	secret := []byte("sealed-before-pins-existed")
	pin := mustPassword([]byte("recovery-pin-9876"))

	keyAttrs := sealedKeyAttrs(t, h, "legacy-sealed-object", true, pin)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, legacy, true)
	require.NoError(t, err)

	_, err = h.Backend.Get(keyAttrs, store.FSEXT_PLATFORM_POLICY)
	require.Error(t, err, "the pre-change on-disk form carries no platform policy record")

	// The PCR branch must open it, from the real store.
	pcrBranch := sealedKeyAttrs(t, h, "legacy-sealed-object", true, nil)
	got, err := h.TPM.UnsealKey(pcrBranch, h.Backend)
	require.NoError(t, err, "an object sealed under the previous scheme must still unseal")
	assert.Equal(t, secret, got)

	// And so must the PIN branch, while the platform state is unchanged.
	withPIN, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	assert.Equal(t, secret, withPIN)

	// After a platform change a pre-change object behaves the way it always
	// did: neither branch opens it.
	h.extendPlatformPCR(t, []byte("post-update-measurement"))

	out, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.Error(t, err, "without a recorded pin the PIN branch cannot rebuild the OR digest")
	assert.Nil(t, out)
	assert.Equal(t, ErrPolicyCheckFailed, err)

	out, err = h.TPM.UnsealKey(pcrBranch, h.Backend)
	require.Error(t, err)
	assert.Nil(t, out)
	assert.Equal(t, ErrPolicyCheckFailed, err)
}

// TestSealKey_PlatformPolicy_RecordsLivePCRState proves the record written at
// seal time describes the platform state the object was actually sealed on. A
// record holding anything else would rebuild the wrong PolicyOR operand and
// lock the PIN branch out - the failure this whole mechanism exists to prevent.
func TestSealKey_PlatformPolicy_RecordsLivePCRState(t *testing.T) {
	h := newSimHarness(t, nil)

	live, err := h.TPM.PlatformPolicyDigestHash()
	require.NoError(t, err)

	keyAttrs := sealedKeyAttrs(t, h, "pin-record-contents", true,
		mustPassword([]byte("recovery-pin-9876")))
	keyAttrs.SealData = types.NewSealData([]byte("any-secret"))

	_, err = h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	record, err := h.Backend.Get(keyAttrs, store.FSEXT_PLATFORM_POLICY)
	require.NoError(t, err, "sealing under the platform policy must record its pin")

	recorded, err := store.UnmarshalPlatformPolicyPin(record)
	require.NoError(t, err)
	assert.Equal(t, live, recorded.PCRDigest,
		"the recorded PCR digest must be the platform state the object was sealed on")
	assert.Equal(t, uint32(h.TPM.config.PlatformPCR), recorded.PCRIndex)
	assert.Equal(t, uint16(tpm2.TPMAlgSHA256), recorded.PCRBank)

	// A sealed object without the platform policy has no policy to pin.
	unbound := sealedKeyAttrs(t, h, "unbound-no-pin", false, nil)
	unbound.SealData = types.NewSealData([]byte("any-secret"))
	_, err = h.TPM.SealKey(unbound, h.Backend, true)
	require.NoError(t, err)

	_, err = h.Backend.Get(unbound, store.FSEXT_PLATFORM_POLICY)
	assert.Error(t, err, "an object with no platform policy must not record a pin")
}

// TestSealUnseal_CorruptPolicyPin_Rejected covers the error contract of the
// record: a pin that exists but cannot be decoded is reported, not ignored.
// Falling back to the live-PCR computation would turn a legible storage fault
// into an opaque TPM authorization failure, and would do it silently on exactly
// the objects whose recovery depends on the record being intact.
func TestSealUnseal_CorruptPolicyPin_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	keyAttrs := sealedKeyAttrs(t, h, "corrupt-pin-record", true,
		mustPassword([]byte("recovery-pin-9876")))
	keyAttrs.SealData = types.NewSealData([]byte("secret-behind-a-broken-record"))

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	require.NoError(t, h.Backend.Save(keyAttrs,
		[]byte("not-a-platform-policy-pin"), store.FSEXT_PLATFORM_POLICY, true))

	out, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.Error(t, err, "a corrupt pin record must be reported")
	assert.Nil(t, out)
	assert.IsType(t, &store.PlatformPolicyPinFormatError{}, err)

	// The PCR branch never consults the record, so it must be unaffected.
	pcrBranch := sealedKeyAttrs(t, h, "corrupt-pin-record", true, nil)
	got, err := h.TPM.UnsealKey(pcrBranch, h.Backend)
	require.NoError(t, err, "the PCR branch must not depend on the pin record")
	assert.Equal(t, []byte("secret-behind-a-broken-record"), got)
}

// TestSealUnseal_NoPlatformPolicy_SurvivesPCRExtend is the control for the
// PCR-mismatch tests: without PlatformPolicy the sealed object carries no PCR
// binding, so extending the platform PCR must NOT affect it. Without this
// control, a bug that broke unsealing for an unrelated reason would still make
// the PCR-mismatch test pass.
func TestSealUnseal_NoPlatformPolicy_SurvivesPCRExtend(t *testing.T) {
	h := newSimHarness(t, nil)

	secret := []byte("not-bound-to-any-pcr")
	keyAttrs := sealedKeyAttrs(t, h, "unbound-secret", false, nil)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	h.extendPlatformPCR(t, []byte("irrelevant-measurement"))

	got, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err, "a sealed object without PlatformPolicy must be unaffected by PCR changes")
	assert.Equal(t, secret, got)
}

// TestSealUnseal_WrongPassword_Rejected proves the sealed object's UserAuth is
// actually enforced: a caller holding the sealed blob but not the password
// cannot recover the plaintext.
func TestSealUnseal_WrongPassword_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	secret := []byte("password-protected-secret")
	correct := mustPassword([]byte("correct-horse-battery"))

	keyAttrs := sealedKeyAttrs(t, h, "password-sealed", false, correct)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	// Sanity: the correct password works.
	got, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.NoError(t, err)
	require.Equal(t, secret, got)

	// The wrong password must be rejected by the TPM, not silently accepted.
	wrongAttrs := sealedKeyAttrs(t, h, "password-sealed", false,
		mustPassword([]byte("wrong-password")))
	out, err := h.TPM.UnsealKey(wrongAttrs, h.Backend)
	require.Error(t, err, "the TPM must reject an unseal authorized with the wrong password")
	assert.Nil(t, out)
	assert.True(t, isTPMAuthError(err) || isTPMBadAuth(err),
		"expected a TPM authorization failure, got %v", err)
}

// TestUnsealKey_CorruptPrivateBlob_Rejected proves the TPM's integrity
// protection on the sealed private area is enforced end to end: a single
// flipped byte in the stored private blob must make the load fail rather than
// yield attacker-influenced plaintext.
func TestUnsealKey_CorruptPrivateBlob_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	secret := []byte("integrity-protected-secret")
	keyAttrs := sealedKeyAttrs(t, h, "corruptible-secret", false, nil)
	keyAttrs.SealData = types.NewSealData(secret)

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	priv, err := h.Backend.Get(keyAttrs, store.FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	require.NotEmpty(t, priv)

	corrupted := make([]byte, len(priv))
	copy(corrupted, priv)
	corrupted[len(corrupted)-1] ^= 0xFF
	require.NoError(t, h.Backend.Save(keyAttrs, corrupted, store.FSEXT_PRIVATE_BLOB, true))

	out, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.Error(t, err, "a corrupted private blob must not unseal")
	assert.Nil(t, out)
}

// TestUnsealKey_TruncatedPublicBlob_Rejected covers the sibling corruption
// case: the public area is what the TPM parses to rebuild the object, so a
// truncated public blob must be rejected during load, not fall through to a
// partially-parsed object.
func TestUnsealKey_TruncatedPublicBlob_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	keyAttrs := sealedKeyAttrs(t, h, "truncated-public", false, nil)
	keyAttrs.SealData = types.NewSealData([]byte("some-secret"))

	_, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	pub, err := h.Backend.Get(keyAttrs, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)
	require.Greater(t, len(pub), 8)

	require.NoError(t, h.Backend.Save(keyAttrs, pub[:len(pub)/2], store.FSEXT_PUBLIC_BLOB, true))

	out, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.Error(t, err, "a truncated public blob must not unseal")
	assert.Nil(t, out)
}

// TestSealKey_OversizedData_Rejected proves the TPM's TPM2B_SENSITIVE_DATA
// limit is surfaced as an error rather than silently truncating the caller's
// secret. Truncation would be the dangerous failure mode: the caller would
// believe a full-length key was sealed while only a prefix was protected.
func TestSealKey_OversizedData_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	// TPM2B_SENSITIVE_DATA for a keyed-hash object is bounded by the largest
	// supported digest size (128 bytes for SHA-512 based TPMs); 4 KiB is far
	// beyond any implementation's limit.
	oversized := bytes.Repeat([]byte{0xAB}, 4096)

	keyAttrs := sealedKeyAttrs(t, h, "oversized-secret", false, nil)
	keyAttrs.SealData = types.NewSealData(oversized)

	resp, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.Error(t, err, "the TPM must reject sealing data larger than TPM2B_SENSITIVE_DATA")
	assert.Nil(t, resp)

	// Nothing partial may be left behind that a later unseal could return.
	out, unsealErr := h.TPM.UnsealKey(keyAttrs, h.Backend)
	require.Error(t, unsealErr)
	assert.Nil(t, out)
}

// TestSealKey_NilParent_Rejected covers the invalid-input contract of all three
// internal seal/unseal entry points.
func TestSealKey_NilParent_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	keyAttrs := &types.KeyAttributes{CN: "no-parent", StoreType: types.StoreTPM2}

	resp, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)

	out, err := h.TPM.UnsealKey(keyAttrs, h.Backend)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)

	out, err = h.TPM.unsealFromBlobs(keyAttrs, []byte{0x01}, []byte{0x02})
	assert.Nil(t, out)
	assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)
}

// TestSealKey_NilSealData_GeneratesRandomSecret proves the documented
// behaviour that sealing with no supplied secret generates a fresh AES-256 key
// -- and that two such seals do not produce the same secret, which would
// indicate a broken or static entropy source.
func TestSealKey_NilSealData_GeneratesRandomSecret(t *testing.T) {
	h := newSimHarness(t, nil)

	first := sealedKeyAttrs(t, h, "generated-secret-a", false, nil)
	_, err := h.TPM.SealKey(first, h.Backend, true)
	require.NoError(t, err)
	require.NotNil(t, first.SealData, "SealKey must populate SealData when the caller supplies none")
	secretA := first.SealData.Bytes()
	assert.Len(t, secretA, 32, "a generated seal secret must be an AES-256 key")

	second := sealedKeyAttrs(t, h, "generated-secret-b", false, nil)
	_, err = h.TPM.SealKey(second, h.Backend, true)
	require.NoError(t, err)
	secretB := second.SealData.Bytes()

	assert.NotEqual(t, secretA, secretB, "generated seal secrets must not repeat")

	// Both must round-trip to the value that was generated.
	gotA, err := h.TPM.UnsealKey(first, h.Backend)
	require.NoError(t, err)
	assert.Equal(t, secretA, gotA)

	gotB, err := h.TPM.UnsealKey(second, h.Backend)
	require.NoError(t, err)
	assert.Equal(t, secretB, gotB)
}

// emptySealData is a types.SealData whose Bytes() yields nil, modelling a
// caller-supplied implementation (for example one backed by an already-cleared
// buffer or a secret store that failed to resolve). sealKeyInternal must reject
// it rather than sealing nothing.
type emptySealData struct{}

func (emptySealData) Bytes() []byte { return nil }
func (emptySealData) Clear()        {}

// TestSealKey_SealDataYieldingNoBytes_Rejected covers the explicit
// ErrInvalidKeyedHashSecret guard for a SealData that resolves to no bytes.
func TestSealKey_SealDataYieldingNoBytes_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	keyAttrs := sealedKeyAttrs(t, h, "empty-seal-data", false, nil)
	keyAttrs.SealData = emptySealData{}

	resp, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, store.ErrInvalidKeyedHashSecret)
}

// TestUnsealFromBlobs_RoundTripAndTamper exercises the in-memory blob unseal
// path used at boot when the sealed object is read from the EFI partition
// rather than the key backend.
func TestUnsealFromBlobs_RoundTripAndTamper(t *testing.T) {
	h := newSimHarness(t, nil)

	secret := []byte("efi-partition-sealed-secret")
	keyAttrs := sealedKeyAttrs(t, h, "blob-sealed", false, nil)
	keyAttrs.SealData = types.NewSealData(secret)

	resp, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
	require.NoError(t, err)

	pub := resp.OutPublic.Bytes()
	priv := resp.OutPrivate.Buffer

	got, err := h.TPM.unsealFromBlobs(keyAttrs, pub, priv)
	require.NoError(t, err, "unsealing from in-memory blobs must round-trip")
	assert.Equal(t, secret, got)

	// A tampered private blob must not yield the secret.
	tampered := make([]byte, len(priv))
	copy(tampered, priv)
	tampered[0] ^= 0x01
	out, err := h.TPM.unsealFromBlobs(keyAttrs, pub, tampered)
	require.Error(t, err)
	assert.Nil(t, out)

	// Mismatched public/private pair (public taken from a different object).
	other := sealedKeyAttrs(t, h, "blob-sealed-other", false, nil)
	other.SealData = types.NewSealData([]byte("another-secret"))
	otherResp, err := h.TPM.SealKey(other, h.Backend, true)
	require.NoError(t, err)

	out, err = h.TPM.unsealFromBlobs(keyAttrs, otherResp.OutPublic.Bytes(), priv)
	require.Error(t, err, "a mismatched public/private pair must not load")
	assert.Nil(t, out)
}

// TestSealer_SealUnseal_PublicAPIRoundTrip drives the exported types.Sealer
// surface (Seal/Unseal) rather than the internal helpers, including the
// in-memory blob path taken when the SealedData carries TPMPublic/TPMPrivate.
func TestSealer_SealUnseal_PublicAPIRoundTrip(t *testing.T) {
	h := newSimHarness(t, nil)
	ctx := context.Background()

	require.True(t, h.TPM.CanSeal())

	plaintext := []byte("barrier-root-key-material")
	sealed, err := h.TPM.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "sealer-api-key", false, nil),
	})
	require.NoError(t, err)
	require.NotNil(t, sealed)
	assert.Equal(t, types.BackendTypeTPM2, sealed.Backend)
	assert.NotEmpty(t, sealed.TPMPublic)
	assert.NotEmpty(t, sealed.TPMPrivate)
	assert.Nil(t, sealed.Ciphertext, "TPM sealing must not emit a separate ciphertext")

	// The sealed blobs must not carry the plaintext.
	assert.NotContains(t, string(sealed.TPMPrivate), string(plaintext))
	assert.NotContains(t, string(sealed.TPMPublic), string(plaintext))

	got, err := h.TPM.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "sealer-api-key", false, nil),
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// TestSealer_Unseal_TamperedSealedData covers the error contract of the
// exported Unseal when the SealedData it is handed has been modified.
func TestSealer_Unseal_TamperedSealedData(t *testing.T) {
	h := newSimHarness(t, nil)
	ctx := context.Background()

	sealed, err := h.TPM.Seal(ctx, []byte("tamper-target"), &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "tamper-key", false, nil),
	})
	require.NoError(t, err)

	tampered := *sealed
	tampered.TPMPrivate = append([]byte(nil), sealed.TPMPrivate...)
	tampered.TPMPrivate[len(tampered.TPMPrivate)-1] ^= 0xFF

	out, err := h.TPM.Unseal(ctx, &tampered, &types.UnsealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "tamper-key", false, nil),
	})
	require.Error(t, err)
	assert.Nil(t, out)
}

// TestSealer_Unseal_FromBackendStorage_WrongKeyID proves the storage-backed
// Unseal path (SealedData without inline blobs) resolves the object by KeyID
// and fails cleanly when that object does not exist, rather than returning
// another object's plaintext.
func TestSealer_Unseal_FromBackendStorage_WrongKeyID(t *testing.T) {
	h := newSimHarness(t, nil)
	ctx := context.Background()

	plaintext := []byte("storage-backed-secret")
	sealed, err := h.TPM.Seal(ctx, plaintext, &types.SealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "storage-backed", false, nil),
		Backend:       h.Backend,
	})
	require.NoError(t, err)

	// Drop the inline blobs so Unseal must go through backend storage.
	fromStore := *sealed
	fromStore.TPMPublic = nil
	fromStore.TPMPrivate = nil

	got, err := h.TPM.Unseal(ctx, &fromStore, &types.UnsealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "storage-backed", false, nil),
		Backend:       h.Backend,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	// An unknown KeyID must not resolve to any stored object.
	out, err := h.TPM.Unseal(ctx, &fromStore, &types.UnsealOptions{
		KeyAttributes: sealedKeyAttrs(t, h, "no-such-sealed-object", false, nil),
		Backend:       h.Backend,
	})
	require.Error(t, err)
	assert.Nil(t, out)
	assert.ErrorIs(t, err, ErrUnsealFailed)
}

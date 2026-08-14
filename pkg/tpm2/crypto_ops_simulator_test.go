//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers TPM-resident child key creation and the crypto operations
// performed with those keys: RSA sign/decrypt, ECDSA sign, ECDH shared-secret
// derivation and sealed secret keys. Each test owns a single simulator via
// newSimHarness -- the go-tpm-tools simulator is a process-global singleton, so
// only one may be live at a time.

// childKeyAttrs builds attributes for a child key under the SSRK. The SSRK
// carries no platform policy, so the parent authorization is a plain password
// session and the test isolates the child key behaviour under test.
func childKeyAttrs(
	t *testing.T,
	h *simHarness,
	cn string,
	algorithm x509.PublicKeyAlgorithm,
	keyType types.KeyType,
) *types.KeyAttributes {
	t.Helper()

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 cn,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       algorithm,
		KeyType:            keyType,
		Parent:             srkAttrs,
		StoreType:          types.StoreTPM2,
		SignatureAlgorithm: x509.SHA256WithRSA,
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

// TestCreateRSA_SignsAndVerifiesUnderReturnedPublicKey proves a TPM-resident
// RSA key is usable end to end: the public key returned at creation must verify
// a signature the TPM produces with the private half it kept. If creation
// returned a public key that did not correspond to the retained private key,
// every certificate issued for it would be silently unusable.
func TestCreateRSA_SignsAndVerifiesUnderReturnedPublicKey(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "rsa-signing-key", x509.RSA, types.KeyTypeSigning)
	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)
	require.NotNil(t, pub)
	assert.Equal(t, 2048, pub.N.BitLen(), "the key must have the requested modulus size")

	digest := sha256.Sum256([]byte("payload the TPM must sign"))
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	require.NoError(t,
		rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature),
		"the public key returned by CreateRSA must verify what the TPM signed")

	// A signature over a different digest must not verify -- proving the
	// verification above is actually checking the message.
	otherDigest := sha256.Sum256([]byte("a different payload"))
	assert.Error(t,
		rsa.VerifyPKCS1v15(pub, crypto.SHA256, otherDigest[:], signature),
		"the signature must not verify against an unrelated digest")
}

// TestCreateECDSA_SignsAndVerifiesUnderReturnedPublicKey is the ECDSA
// counterpart: the curve point returned at creation must verify a TPM-produced
// signature.
func TestCreateECDSA_SignsAndVerifiesUnderReturnedPublicKey(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "ecdsa-signing-key", x509.ECDSA, types.KeyTypeSigning)
	pub, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)
	require.NotNil(t, pub)
	assert.Equal(t, elliptic.P256(), pub.Curve, "the key must use the requested curve")
	assert.True(t, pub.Curve.IsOnCurve(pub.X, pub.Y),
		"the returned public point must lie on the curve")

	digest := sha256.Sum256([]byte("payload the TPM must sign with ECDSA"))
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	assert.True(t,
		ecdsa.VerifyASN1(pub, digest[:], signature),
		"the public key returned by CreateECDSA must verify what the TPM signed")

	otherDigest := sha256.Sum256([]byte("a different payload"))
	assert.False(t,
		ecdsa.VerifyASN1(pub, otherDigest[:], signature),
		"the signature must not verify against an unrelated digest")
}

// TestCreateRSA_NilParent_Rejected covers the invalid-input contract shared by
// every child-key constructor: without a parent there is nothing to create the
// key under, and that must be reported rather than defaulting to a hierarchy.
func TestCreateRSA_NilParent_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := &types.KeyAttributes{CN: "orphan-rsa", StoreType: types.StoreTPM2}
	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	assert.Nil(t, pub)
	assert.ErrorIs(t, err, store.ErrInvalidKeyAttributes)

	ecAttrs := &types.KeyAttributes{CN: "orphan-ecdsa", StoreType: types.StoreTPM2}
	ecPub, err := h.TPM.CreateECDSA(ecAttrs, h.Backend, true)
	assert.Nil(t, ecPub)
	assert.ErrorIs(t, err, store.ErrInvalidParentAttributes)

	secretAttrs := &types.KeyAttributes{CN: "orphan-secret", StoreType: types.StoreTPM2}
	assert.ErrorIs(t,
		h.TPM.CreateSecretKey(secretAttrs, h.Backend),
		store.ErrInvalidKeyAttributes)
}

// TestCreateRSA_RejectedCreate_FlushesTransientObjectHandle is the
// resource-leak regression test for CreateRSA (and identically CreateECDSA).
//
// Both create the key with TPM2_CreateLoaded, which leaves the new object LOADED
// in TPM transient memory, and document that "Caller is responsible for flushing
// the handle". But on the SaveKeyPair error path -- most commonly the entirely
// normal, caller-triggerable "key already exists and overwrite is false" -- the
// function returned the error without flushing, and the caller received nil so
// it could not flush either. Every rejected create stranded one object.
//
// A TPM holds only a handful of transient objects, so this was not a slow leak:
// see the exhaustion test below.
func TestCreateRSA_RejectedCreate_FlushesTransientObjectHandle(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "no-clobber-key", x509.RSA, types.KeyTypeSigning)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	// Flush whatever the successful create left loaded so the baseline below
	// measures only what the FAILED create leaves behind.
	h.TPM.Flush(attrs.TPMAttributes.Handle)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	second := childKeyAttrs(t, h, "no-clobber-key", x509.RSA, types.KeyTypeSigning)
	_, err = h.TPM.CreateRSA(second, h.Backend, false)
	require.Error(t, err, "creating over an existing key without overwrite must fail")

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	assert.Len(t, after, len(before),
		"a rejected create must leave no transient object behind: the SaveKeyPair "+
			"error path has to flush the handle CreateLoaded produced")
}

// TestCreateECDSA_RejectedCreate_FlushesTransientObjectHandle is the same guard
// for the ECDSA path, which had an identical leak.
func TestCreateECDSA_RejectedCreate_FlushesTransientObjectHandle(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "no-clobber-ecc", x509.ECDSA, types.KeyTypeSigning)
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)
	h.TPM.Flush(attrs.TPMAttributes.Handle)

	before, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	second := childKeyAttrs(t, h, "no-clobber-ecc", x509.ECDSA, types.KeyTypeSigning)
	_, err = h.TPM.CreateECDSA(second, h.Backend, false)
	require.Error(t, err)

	after, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)

	assert.Len(t, after, len(before),
		"a rejected ECDSA create must leave no transient object behind")
}

// TestCreateRSA_RepeatedRejectedCreates_DoNotExhaustTPMObjectMemory is the
// consequence test. Before the flush was added, repeating an ordinary "key
// already exists" rejection a handful of times exhausted TPM object memory and
// bricked the connection for ALL keys -- including unrelated ones that had been
// working. Far more rejections than a TPM has object slots must now be harmless.
func TestCreateRSA_RepeatedRejectedCreates_DoNotExhaustTPMObjectMemory(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "exhaustion-key", x509.RSA, types.KeyTypeSigning)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)
	h.TPM.Flush(attrs.TPMAttributes.Handle)

	// Comfortably more iterations than the simulator has transient object
	// slots, so a per-call leak of even one handle would be caught.
	for i := 0; i < 16; i++ {
		dup := childKeyAttrs(t, h, "exhaustion-key", x509.RSA, types.KeyTypeSigning)
		_, createErr := h.TPM.CreateRSA(dup, h.Backend, false)
		require.Error(t, createErr, "iteration %d: duplicate create must be rejected", i)
		require.False(t, isObjectMemoryError(createErr),
			"iteration %d: rejected creates must not exhaust TPM object memory: %v", i, createErr)
	}

	// The real damage was never confined to the key being created, so this is
	// the assertion that matters: an unrelated key still works afterwards.
	other := childKeyAttrs(t, h, "innocent-bystander-key", x509.RSA, types.KeyTypeSigning)
	_, err = h.TPM.CreateRSA(other, h.Backend, true)
	assert.NoError(t, err,
		"repeated rejected creates must not break unrelated key operations on the same connection")
}

// isObjectMemoryError reports whether err is the TPM's out-of-object-memory
// response, TPM_RC_OBJECT_MEMORY.
func isObjectMemoryError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "TPM_RC_OBJECT_MEMORY")
}

// TestRSADecrypt_RoundTripsOAEPCiphertext proves the TPM's RSA decrypt path
// recovers a message encrypted to the key's public half under OAEP-SHA256, the
// scheme the implementation hardcodes.
func TestRSADecrypt_RoundTripsOAEPCiphertext(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "rsa-decrypt-key", x509.RSA, types.KeyTypeEncryption)
	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	plaintext := []byte("message encrypted to the TPM public key")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
	require.NoError(t, err)

	// Load the key so its transient handle and name are available.
	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loaded.ObjectHandle)

	recovered, err := h.TPM.RSADecrypt(loaded.ObjectHandle, loaded.Name, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered,
		"the TPM must recover the exact plaintext encrypted to its public key")
}

// TestRSADecrypt_CorruptCiphertext_Rejected proves OAEP integrity checking is
// enforced by the TPM: a tampered ciphertext must fail rather than yield
// attacker-influenced plaintext.
func TestRSADecrypt_CorruptCiphertext_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "rsa-decrypt-tamper", x509.RSA, types.KeyTypeEncryption)
	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		pub, []byte("secret"), nil)
	require.NoError(t, err)
	ciphertext[len(ciphertext)-1] ^= 0xFF

	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loaded.ObjectHandle)

	out, err := h.TPM.RSADecrypt(loaded.ObjectHandle, loaded.Name, ciphertext)
	require.Error(t, err, "a corrupted OAEP ciphertext must not decrypt")
	assert.Nil(t, out)
}

// TestECDHZGen_SigningKey_Rejected proves ECDH agreement cannot be performed
// with a key that was not created for it. Every ECC template the product
// exposes (RSASSA/ECDSA signing templates in types.go) sets SignEncrypt and
// leaves Decrypt clear, so the TPM must refuse rather than derive a secret from
// a key whose attributes forbid key agreement.
//
// A regression that made this succeed would mean a signing key was silently
// granted decrypt capability -- exactly the key-reuse violation TPM object
// attributes exist to prevent.
func TestECDHZGen_SigningKey_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "ecdsa-not-for-ecdh", x509.ECDSA, types.KeyTypeSigning)
	pub, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)
	h.TPM.Flush(attrs.TPMAttributes.Handle)

	peerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	peerPoint := &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: peerPriv.PublicKey.X.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: peerPriv.PublicKey.Y.FillBytes(make([]byte, 32))},
	}
	require.True(t, pub.Curve.IsOnCurve(peerPriv.PublicKey.X, peerPriv.PublicKey.Y),
		"precondition: the peer point is a valid point on the same curve, so any "+
			"rejection is due to the key's attributes and not a bad point")

	shared, err := h.TPM.ECDHZGen(attrs, peerPoint, h.Backend)
	require.Error(t, err,
		"a sign-only ECC key must not be usable for ECDH key agreement")
	assert.Nil(t, shared, "no shared secret may be returned when the TPM refuses")
}

// TestECDHZGen_InvalidInputs_Rejected covers the documented invalid-input
// contract of the ECDH entry point.
func TestECDHZGen_InvalidInputs_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "ecdh-invalid", x509.ECDSA, types.KeyTypeEncryption)
	_, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)

	t.Run("nil key attributes", func(t *testing.T) {
		out, err := h.TPM.ECDHZGen(nil, &tpm2.TPMSECCPoint{}, h.Backend)
		assert.Nil(t, out)
		assert.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
	})

	t.Run("nil peer public key", func(t *testing.T) {
		out, err := h.TPM.ECDHZGen(attrs, nil, h.Backend)
		assert.Nil(t, out)
		assert.ErrorIs(t, err, store.ErrInvalidPublicKey)
	})

	t.Run("peer point not on curve", func(t *testing.T) {
		// A point whose coordinates do not satisfy the curve equation must be
		// rejected by the TPM rather than used to derive a secret -- accepting
		// it is the classic invalid-curve attack.
		bogus := &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}
		bogus.X.Buffer[31] = 0x02
		bogus.Y.Buffer[31] = 0x03

		out, err := h.TPM.ECDHZGen(attrs, bogus, h.Backend)
		require.Error(t, err, "a point off the curve must be rejected")
		assert.Nil(t, out)
	})
}

// TestCreateSecretKey_CreatesLoadableAESKeyUnderSRK proves CreateSecretKey
// produces a real AES-256 symmetric object under the SRK whose blobs persist
// and reload.
//
// Note what it does NOT do: despite the "secret key" name it ignores
// keyAttrs.SealData entirely and always lets the TPM generate the key material
// (secretkey.go passes no InSensitive). The object is a symmetric cipher key,
// not a sealed data blob, so it cannot be unsealed -- attempting it returns
// TPM_RC_TYPE. Both properties are asserted so the API's actual contract is
// pinned rather than assumed from its name.
func TestCreateSecretKey_CreatesLoadableAESKeyUnderSRK(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "aes-secret-key", x509.RSA, types.KeyTypeHMAC)
	attrs.SealData = types.NewSealData([]byte("this-supplied-secret-is-ignored"))

	require.NoError(t, h.TPM.CreateSecretKey(attrs, h.Backend))

	// The blobs were persisted and the object reloads onto the TPM.
	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err, "the created AES key must reload from its stored blobs")
	defer h.TPM.Flush(loaded.ObjectHandle)
	assert.NotEmpty(t, loaded.Name.Buffer)

	// It is a symmetric cipher object, so it is not unsealable.
	out, err := h.TPM.UnsealKey(attrs, h.Backend)
	require.Error(t, err,
		"an AES cipher object is not a sealed data blob and must not unseal")
	assert.Nil(t, out)
}

// TestCreateSecretKey_TwoKeysAreDistinct proves each call creates independent
// key material rather than deriving the same key twice, which would make every
// "secret key" in the system identical.
func TestCreateSecretKey_TwoKeysAreDistinct(t *testing.T) {
	h := newSimHarness(t, nil)

	first := childKeyAttrs(t, h, "aes-secret-1", x509.RSA, types.KeyTypeHMAC)
	require.NoError(t, h.TPM.CreateSecretKey(first, h.Backend))
	firstPub, err := h.Backend.Get(first, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)

	second := childKeyAttrs(t, h, "aes-secret-2", x509.RSA, types.KeyTypeHMAC)
	require.NoError(t, h.TPM.CreateSecretKey(second, h.Backend))
	secondPub, err := h.Backend.Get(second, store.FSEXT_PUBLIC_BLOB)
	require.NoError(t, err)

	assert.NotEqual(t, firstPub, secondPub,
		"two secret keys must not share the same public area / key material")
}

// TestSign_UnknownKey_Rejected proves signing with attributes that name a key
// which was never created fails, rather than silently creating one or signing
// with an unrelated key.
func TestSign_UnknownKey_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "never-created-key", x509.RSA, types.KeyTypeSigning)
	digest := sha256.Sum256([]byte("payload"))

	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.Error(t, err, "signing with a key that does not exist must fail")
	assert.Nil(t, signature)
}

// TestSign_WrongSignerOptsType_Rejected proves the signer refuses opts it
// cannot interpret instead of falling back to a default key.
func TestSign_WrongSignerOptsType_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	digest := sha256.Sum256([]byte("payload"))
	signature, err := h.TPM.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.Error(t, err, "opts that are not *store.SignerOpts must be rejected")
	assert.Nil(t, signature)
}

// TestDeleteKey_RemovesKeyAndPreventsFurtherUse proves deletion is real: after
// deleting, the key can no longer be loaded or used to sign. A delete that only
// removed a directory entry while leaving the TPM object loadable would be a
// data-retention defect.
func TestDeleteKey_RemovesKeyAndPreventsFurtherUse(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "deletable-key", x509.RSA, types.KeyTypeSigning)
	_, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)

	// Sanity: the key works before deletion.
	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	h.TPM.Flush(loaded.ObjectHandle)

	require.NoError(t, h.TPM.DeleteKey(attrs, h.Backend))

	_, err = h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.Error(t, err, "a deleted key must no longer load")

	digest := sha256.Sum256([]byte("payload"))
	signature, err := h.TPM.Sign(rand.Reader, digest[:], &store.SignerOpts{
		KeyAttributes: attrs,
		Backend:       h.Backend,
	})
	require.Error(t, err, "a deleted key must not sign")
	assert.Nil(t, signature)
}

// TestDeleteKey_UnknownKey_Rejected proves deleting a key that does not exist
// is reported rather than silently succeeding, so callers can distinguish "it
// is gone because I deleted it" from "it was never there".
func TestDeleteKey_UnknownKey_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)

	attrs := childKeyAttrs(t, h, "never-existed", x509.RSA, types.KeyTypeSigning)
	err := h.TPM.DeleteKey(attrs, h.Backend)
	assert.Error(t, err, "deleting a non-existent key must be reported")
}

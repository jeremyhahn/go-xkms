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
	"github.com/jeremyhahn/go-xkms/pkg/crypto/ecpoint"
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

	recovered, err := h.TPM.RSADecrypt(attrs, h.Backend, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered,
		"the TPM must recover the exact plaintext encrypted to its public key")
}

// TestRSADecrypt_MissingKey_Rejected proves RSADecrypt reports a key whose
// blobs do not exist rather than decrypting with anything else.
func TestRSADecrypt_MissingKey_Rejected(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := childKeyAttrs(t, h, "rsa-decrypt-missing", x509.RSA, types.KeyTypeEncryption)
	out, err := h.TPM.RSADecrypt(attrs, h.Backend, []byte("ciphertext"))
	require.Error(t, err)
	assert.Nil(t, out)
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

	out, err := h.TPM.RSADecrypt(attrs, h.Backend, ciphertext)
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
	peerRaw, err := peerPriv.PublicKey.Bytes()
	require.NoError(t, err)
	peerSize := ecpoint.CoordinateSize(peerPriv.Curve)
	peerX, peerY := peerRaw[1:1+peerSize], peerRaw[1+peerSize:]
	peerPoint := &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: peerX},
		Y: tpm2.TPM2BECCParameter{Buffer: peerY},
	}
	_, err = ecpoint.PublicKey(pub.Curve, peerX, peerY)
	require.NoError(t, err,
		"precondition: the peer point is a valid point on the same curve, so any "+
			"rejection is due to the key's attributes and not a bad point")

	shared, err := h.TPM.ECDHZGen(attrs, peerPoint, h.Backend)
	require.Error(t, err,
		"a sign-only ECC key must not be usable for ECDH key agreement")
	assert.Nil(t, shared, "no shared secret may be returned when the TPM refuses")
}

// TestECDHZGen_EncryptionKey_RoundTripsWithCryptoECDH is the success-path
// companion to TestECDHZGen_SigningKey_Rejected above: a key created through
// CreateECDSA with KeyTypeEncryption must carry Decrypt instead of
// SignEncrypt (ecdsa.go), so TPM2_ECDH_ZGen must accept it and the shared
// secret it computes must equal the one crypto/ecdh computes independently
// from the peer's side.
//
// The oracle is crypto/ecdh, never the TPM's own inverse: the TPM derives Z
// from its retained private key and the peer's public point, the test
// derives Z from the peer's private key and the TPM's returned public point,
// and ECDH means those two agree only if the TPM actually performed the
// agreement this test asked for.
func TestECDHZGen_EncryptionKey_RoundTripsWithCryptoECDH(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			h := newSimHarness(t, nil)

			attrs := childKeyAttrs(t, h, "ecdh-decrypt-key", x509.ECDSA, types.KeyTypeEncryption)
			attrs.ECCAttributes = &types.ECCAttributes{Curve: curve}

			pub, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
			require.NoError(t, err,
				"a decrypt-typed ECC key must be creatable through the public API")

			tpmECDHPub, err := pub.ECDH()
			require.NoError(t, err, "the returned public point must lie on the curve")

			peerPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
			require.NoError(t, err)
			peerECDHPriv, err := peerPriv.ECDH()
			require.NoError(t, err)

			peerRaw := peerECDHPriv.PublicKey().Bytes()
			peerSize := ecpoint.CoordinateSize(curve)
			peerPoint := &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: peerRaw[1 : 1+peerSize]},
				Y: tpm2.TPM2BECCParameter{Buffer: peerRaw[1+peerSize:]},
			}

			shared, err := h.TPM.ECDHZGen(attrs, peerPoint, h.Backend)
			require.NoError(t, err,
				"ECDH_ZGen must succeed against a key created with KeyTypeEncryption")

			expected, err := peerECDHPriv.ECDH(tpmECDHPub)
			require.NoError(t, err)

			assert.Equal(t, expected, shared,
				"the TPM and the peer must agree on the ECDH shared secret")
		})
	}
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

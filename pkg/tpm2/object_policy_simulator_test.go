//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// objectUse runs one TPM command that exercises the USER role of the loaded
// object at handle under auth.
type objectUse func(handle tpm2.TPMHandle, name tpm2.TPM2BName, auth tpm2.Session) error

// platformKeyAttrs returns child key attributes bound to the platform policy
// and to password (nil for none).
func platformKeyAttrs(
	t *testing.T,
	h *simHarness,
	cn string,
	algorithm x509.PublicKeyAlgorithm,
	keyType types.KeyType,
	password types.Password) *types.KeyAttributes {

	t.Helper()
	attrs := childKeyAttrs(t, h, cn, algorithm, keyType)
	attrs.TPMPolicy = types.TPMPolicyPlatform
	attrs.Password = password
	return attrs
}

// requireLoadedUserWithAuth asserts the USERWITHAUTH attribute of the key the
// TPM loads for attrs, and that the key carries a policy exactly when it is
// clear.
func requireLoadedUserWithAuth(t *testing.T, h *simHarness, attrs *types.KeyAttributes, want bool) {
	t.Helper()
	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loaded.ObjectHandle)
	pub, err := tpm2.ReadPublic{ObjectHandle: loaded.ObjectHandle}.Execute(h.TPM.transport)
	require.NoError(t, err)
	public, err := pub.OutPublic.Contents()
	require.NoError(t, err)
	require.Equal(t, want, public.ObjectAttributes.UserWithAuth)
	require.Equal(t, !want, len(public.AuthPolicy.Buffer) > 0)
}

// requirePolicyBypassRefused moves the platform PCR and then proves the key
// attrs names cannot be used outside its policy: neither by a plain
// empty-password authorization nor through an empty-auth PolicyAuthValue
// branch of the platform PolicyOR.
func requirePolicyBypassRefused(t *testing.T, h *simHarness, attrs *types.KeyAttributes, use objectUse) {
	t.Helper()
	pin, err := h.TPM.loadPlatformPolicyPin(attrs, h.Backend)
	require.NoError(t, err)
	require.NotNil(t, pin, "a platform-policy key records its pin")

	h.extendPlatformPCR(t, []byte("tampered-boot"))

	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loaded.ObjectHandle)

	err = use(loaded.ObjectHandle, loaded.Name, tpm2.PasswordAuth(nil))
	require.ErrorIs(t, err, tpm2.TPMRCAuthUnavailable, "a plain empty password must not answer a policy-bound key")

	session, closer, err := h.TPM.platformPolicySession([]byte{}, pin)
	require.NoError(t, err)
	defer h.TPM.closeSession(closer, "attack session")
	err = use(loaded.ObjectHandle, loaded.Name, session)
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail, "an empty-auth PolicyAuthValue branch must not satisfy the key's policy")
}

// signUse signs a SHA-256 digest with scheme.
func signUse(h *simHarness, scheme tpm2.TPMAlgID) objectUse {
	digest := sha256.Sum256([]byte("bypass attempt"))
	return func(handle tpm2.TPMHandle, name tpm2.TPM2BName, auth tpm2.Session) error {
		_, err := tpm2.Sign{
			KeyHandle: tpm2.AuthHandle{Handle: handle, Name: name, Auth: auth},
			Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
			InScheme: tpm2.TPMTSigScheme{
				Scheme:  scheme,
				Details: tpm2.NewTPMUSigScheme(scheme, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256}),
			},
			Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck, Hierarchy: tpm2.TPMRHNull},
		}.Execute(h.TPM.transport)
		return err
	}
}

// signDigest signs digest through the TPM2 signing API.
func signDigest(h *simHarness, attrs *types.KeyAttributes, digest []byte) ([]byte, error) {
	return h.TPM.Sign(rand.Reader, digest, &store.SignerOpts{KeyAttributes: attrs, Backend: h.Backend})
}

// TestObjectPolicy_RSASigningKeyWithoutPassword proves a passwordless
// platform-policy RSA signing key signs through its PolicyPCR session, is
// refused once the platform state moves, and cannot be used outside its
// policy.
func TestObjectPolicy_RSASigningKeyWithoutPassword(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := platformKeyAttrs(t, h, "policy-rsa-sign", x509.RSA, types.KeyTypeSigning, nil)
	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)
	requireLoadedUserWithAuth(t, h, attrs, false)

	digest := sha256.Sum256([]byte("signed under the platform policy"))
	signature, err := signDigest(h, attrs, digest[:])
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature))

	requirePolicyBypassRefused(t, h, attrs, signUse(h, tpm2.TPMAlgRSASSA))

	_, err = signDigest(h, attrs, digest[:])
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail, "the key must not sign on a moved platform state")
}

// TestObjectPolicy_RSASigningKeyWithPassword proves a platform-policy RSA key
// with a password signs through its PolicyAuthValue branch after the
// platform state moves, while the password alone, outside the policy, is
// refused.
func TestObjectPolicy_RSASigningKeyWithPassword(t *testing.T) {
	h := newSimHarness(t, nil)
	pin := []byte("rsa-key-pin")
	attrs := platformKeyAttrs(t, h, "policy-rsa-pin", x509.RSA, types.KeyTypeSigning, mustPassword(pin))
	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)
	requireLoadedUserWithAuth(t, h, attrs, false)

	h.extendPlatformPCR(t, []byte("post-update"))

	digest := sha256.Sum256([]byte("signed with the recovery pin"))
	signature, err := signDigest(h, attrs, digest[:])
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature))

	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	defer h.TPM.Flush(loaded.ObjectHandle)
	err = signUse(h, tpm2.TPMAlgRSASSA)(loaded.ObjectHandle, loaded.Name, tpm2.PasswordAuth(pin))
	require.ErrorIs(t, err, tpm2.TPMRCAuthUnavailable)
}

// TestObjectPolicy_ECDSASigningKeyWithoutPassword is the ECDSA counterpart.
func TestObjectPolicy_ECDSASigningKeyWithoutPassword(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := platformKeyAttrs(t, h, "policy-ecdsa-sign", x509.ECDSA, types.KeyTypeSigning, nil)
	pub, err := h.TPM.CreateECDSA(attrs, h.Backend, true)
	require.NoError(t, err)
	requireLoadedUserWithAuth(t, h, attrs, false)

	digest := sha256.Sum256([]byte("signed under the platform policy"))
	signature, err := signDigest(h, attrs, digest[:])
	require.NoError(t, err)
	require.True(t, ecdsa.VerifyASN1(pub, digest[:], signature))

	requirePolicyBypassRefused(t, h, attrs, signUse(h, tpm2.TPMAlgECDSA))
}

// TestObjectPolicy_RSADecryptionKeyWithoutPassword proves a passwordless
// platform-policy RSA decryption key decrypts through its policy, and only
// through it.
func TestObjectPolicy_RSADecryptionKeyWithoutPassword(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := platformKeyAttrs(t, h, "policy-rsa-decrypt", x509.RSA, types.KeyTypeEncryption, nil)
	pub, err := h.TPM.CreateRSA(attrs, h.Backend, true)
	require.NoError(t, err)
	requireLoadedUserWithAuth(t, h, attrs, false)

	plaintext := []byte("decrypted under the platform policy")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
	require.NoError(t, err)
	got, err := h.TPM.RSADecrypt(attrs, h.Backend, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	requirePolicyBypassRefused(t, h, attrs,
		func(handle tpm2.TPMHandle, name tpm2.TPM2BName, auth tpm2.Session) error {
			_, err := tpm2.RSADecrypt{
				KeyHandle:  tpm2.AuthHandle{Handle: handle, Name: name, Auth: auth},
				CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: ciphertext},
				InScheme: tpm2.TPMTRSADecrypt{
					Scheme:  tpm2.TPMAlgOAEP,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgOAEP, &tpm2.TPMSEncSchemeOAEP{HashAlg: tpm2.TPMAlgSHA256}),
				},
			}.Execute(h.TPM.transport)
			return err
		})

	_, err = h.TPM.RSADecrypt(attrs, h.Backend, ciphertext)
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail)
}

// aesUse runs TPM2_EncryptDecrypt2 over message with the AES key at handle.
func aesUse(h *simHarness, message []byte, decrypt bool, out *[]byte) objectUse {
	iv := make([]byte, 16)
	return func(handle tpm2.TPMHandle, name tpm2.TPM2BName, auth tpm2.Session) error {
		rsp, err := tpm2.EncryptDecrypt2{
			KeyHandle: tpm2.AuthHandle{Handle: handle, Name: name, Auth: auth},
			Message:   tpm2.TPM2BMaxBuffer{Buffer: message},
			Decrypt:   tpm2.TPMIYesNo(decrypt),
			Mode:      tpm2.TPMAlgCFB,
			IV:        tpm2.TPM2BIV{Buffer: iv},
		}.Execute(h.TPM.transport)
		if err != nil {
			return err
		}
		if out != nil {
			*out = rsp.OutData.Buffer
		}
		return nil
	}
}

// TestObjectPolicy_AESKeyWithoutPassword proves a passwordless
// platform-policy AES key (CreateSecretKey) encrypts and decrypts through
// its policy, and only through it.
func TestObjectPolicy_AESKeyWithoutPassword(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs := platformKeyAttrs(t, h, "policy-aes", x509.RSA, types.KeyTypeEncryption, nil)
	require.NoError(t, h.TPM.CreateSecretKey(attrs, h.Backend))
	requireLoadedUserWithAuth(t, h, attrs, false)

	loaded, err := h.TPM.LoadKeyPair(attrs, nil, h.Backend)
	require.NoError(t, err)
	plaintext := []byte("encrypted under the platform policy")
	var ciphertext, recovered []byte
	for _, step := range []objectUse{
		aesUse(h, plaintext, false, &ciphertext),
		func(handle tpm2.TPMHandle, name tpm2.TPM2BName, auth tpm2.Session) error {
			return aesUse(h, ciphertext, true, &recovered)(handle, name, auth)
		},
	} {
		session, closer, err := h.TPM.objectSession(attrs, h.Backend, loaded.ObjectHandle)
		require.NoError(t, err)
		require.NoError(t, step(loaded.ObjectHandle, loaded.Name, session))
		h.TPM.closeSession(closer, "aes use")
	}
	h.TPM.Flush(loaded.ObjectHandle)
	assert.NotEqual(t, plaintext, ciphertext)
	assert.Equal(t, plaintext, recovered)

	requirePolicyBypassRefused(t, h, attrs, aesUse(h, plaintext, false, nil))
}

// TestObjectPolicy_NVIndexWithPlatformPolicy proves an NV index bound to the
// platform policy is read through its PolicyPCR policy, is refused once the
// platform state moves, and cannot be read with its empty auth value either
// directly or through an empty-auth PolicyAuthValue branch.
func TestObjectPolicy_NVIndexWithPlatformPolicy(t *testing.T) {
	h := newSimHarness(t, nil)
	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	index, err := h.TPM.FindFreeNVIndex(NVOwnerIndexFirst, NVOwnerIndexLast)
	require.NoError(t, err)

	secret := []byte("nv secret under the platform policy")
	attrs := &types.KeyAttributes{
		CN:        "policy-nv",
		Parent:    srkAttrs,
		TPMPolicy: types.TPMPolicyPlatform,
		SealData:  types.NewSealData(secret),
		TPMAttributes: &types.TPMAttributes{
			Handle:    index,
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	require.NoError(t, h.TPM.NVWrite(attrs))
	t.Cleanup(func() { _ = h.TPM.NVUndefine(attrs) })

	readPub, err := tpm2.NVReadPublic{NVIndex: index}.Execute(h.TPM.transport)
	require.NoError(t, err)
	nvPub, err := readPub.NVPublic.Contents()
	require.NoError(t, err)
	assert.False(t, nvPub.Attributes.AuthRead, "the index's empty auth value must not authorize reads")
	assert.False(t, nvPub.Attributes.AuthWrite, "the index's empty auth value must not authorize writes")
	assert.True(t, nvPub.Attributes.PolicyRead)

	got, err := h.TPM.NVRead(attrs, uint16(len(secret)))
	require.NoError(t, err)
	require.Equal(t, secret, got)

	unnamed := *attrs
	unnamed.TPMPolicy = ""
	got, err = h.TPM.NVRead(&unnamed, uint16(len(secret)))
	require.NoError(t, err, "the index, not the caller's attributes, names its read policy")
	require.Equal(t, secret, got)

	pcrPin, err := h.TPM.capturePlatformPolicyPin()
	require.NoError(t, err)
	h.extendPlatformPCR(t, []byte("tampered-boot"))

	read := func(auth tpm2.Session) error {
		_, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: index, Name: readPub.NVName, Auth: auth},
			NVIndex:    tpm2.NamedHandle{Handle: index, Name: readPub.NVName},
			Size:       uint16(len(secret)),
		}.Execute(h.TPM.transport)
		return err
	}
	err = read(tpm2.PasswordAuth(nil))
	require.Error(t, err, "the index's empty auth value must not read it")
	require.True(t, errors.Is(err, tpm2.TPMRCAuthUnavailable) || errors.Is(err, tpm2.TPMRCNVAuthorization), err.Error())

	session, closer, err := h.TPM.platformPolicySession([]byte{}, pcrPin)
	require.NoError(t, err)
	defer h.TPM.closeSession(closer, "attack session")
	require.ErrorIs(t, read(session), tpm2.TPMRCPolicyFail)

	_, err = h.TPM.NVRead(attrs, uint16(len(secret)))
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail)
}

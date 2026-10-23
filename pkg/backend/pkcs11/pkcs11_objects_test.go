// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build pkcs11

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivpkcs11 "github.com/jeremyhahn/go-xkms/pkg/pivcert/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage/hardware"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rsaKeyAttrs builds attributes for an RSA key of the given size.
func rsaKeyAttrs(cn string, bits int) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            cn,
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     types.StorePKCS11,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: bits},
	}
}

// ecdsaKeyAttrs builds attributes for an ECDSA key on the given curve.
func ecdsaKeyAttrs(cn string, curve elliptic.Curve) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            cn,
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     types.StorePKCS11,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: curve},
	}
}

// ed25519KeyAttrs builds attributes for an Ed25519 key.
func ed25519KeyAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    types.StorePKCS11,
		KeyAlgorithm: x509.Ed25519,
	}
}

// countObjects reports how many objects of the given class carry the CKA_ID,
// read through a session the backend under test is not using. It is the oracle
// for create and delete assertions: it asks the token directly instead of
// asking the backend to confirm its own bookkeeping.
func countObjects(t *testing.T, b *Backend, session pkcs11.SessionHandle, class uint, id []byte) int {
	t.Helper()

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	require.NoError(t, b.p11ctx.FindObjectsInit(session, template))
	handles, _, err := b.p11ctx.FindObjects(session, 16)
	require.NoError(t, err)
	require.NoError(t, b.p11ctx.FindObjectsFinal(session))

	return len(handles)
}

// TestBackend_GenerateKey_WritesRequestedAttributes proves the objects
// GenerateKey creates on the token carry exactly the class, key type and
// CKA_ID the backend promised, read back from the token itself.
func TestBackend_GenerateKey_WritesRequestedAttributes(t *testing.T) {
	b := newProvisionedBackend(t, "generate-attributes")
	session := openIntrospectionSession(t, b)

	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		keyType byte
	}{
		{"rsa-2048", rsaKeyAttrs("attr-rsa", 2048), pkcs11.CKK_RSA},
		{"ecdsa-p256", ecdsaKeyAttrs("attr-ecdsa", elliptic.P256()), pkcs11.CKK_EC},
		{"ed25519", ed25519KeyAttrs("attr-ed25519"), CKK_EC_EDWARDS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.GenerateKey(context.Background(), tt.attrs)
			require.NoError(t, err)

			id := []byte(createKeyID(tt.attrs))
			assert.Equal(t, 1, countObjects(t, b, session, pkcs11.CKO_PRIVATE_KEY, id),
				"exactly one private key object must carry CKA_ID %q", id)
			assert.Equal(t, 1, countObjects(t, b, session, pkcs11.CKO_PUBLIC_KEY, id),
				"exactly one public key object must carry CKA_ID %q", id)

			handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			})

			read, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
				pkcs11.NewAttribute(pkcs11.CKA_TOKEN, nil),
				pkcs11.NewAttribute(pkcs11.CKA_SIGN, nil),
			})
			require.NoError(t, err)

			assert.Equal(t, tt.keyType, read[0].Value[0], "CKA_KEY_TYPE must match the requested algorithm")
			assert.Equal(t, string(id), string(read[1].Value), "CKA_LABEL must be the generated key ID")
			assert.Equal(t, byte(1), read[2].Value[0], "generated keys must be token objects, not session objects")
			assert.Equal(t, byte(1), read[3].Value[0], "a signing key must have CKA_SIGN set")
		})
	}
}

// TestBackend_GenerateKey_Rejected proves GenerateKey refuses algorithms it
// cannot place on the token and refuses to run before login.
func TestBackend_GenerateKey_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "generate-rejected")

	t.Run("unsupported-algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "dsa-key", KeyAlgorithm: x509.DSA}
		key, err := b.GenerateKey(context.Background(), attrs)
		require.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
		assert.Nil(t, key)
	})

	t.Run("not-initialized", func(t *testing.T) {
		fresh := &Backend{config: b.config}
		for name, gen := range map[string]func() (crypto.Signer, error){
			"rsa":     func() (crypto.Signer, error) { return fresh.GenerateRSA(rsaKeyAttrs("x", 2048)) },
			"ecdsa":   func() (crypto.Signer, error) { return fresh.GenerateECDSA(ecdsaKeyAttrs("x", nil)) },
			"ed25519": func() (crypto.Signer, error) { return fresh.GenerateEd25519(ed25519KeyAttrs("x")) },
		} {
			t.Run(name, func(t *testing.T) {
				signer, err := gen()
				require.ErrorIs(t, err, ErrNotInitialized)
				assert.Nil(t, signer)
			})
		}
	})
}

// TestBackend_GenerateEd25519_SignatureVerifies proves an Ed25519 key
// generated on the token produces signatures that crypto/ed25519 accepts
// under the public key the backend exports.
//
// crypto/ed25519 is the oracle here: verifying the HSM signature with the
// HSM's own verify call would only prove self-consistency, not RFC 8032
// conformance.
func TestBackend_GenerateEd25519_SignatureVerifies(t *testing.T) {
	b := newProvisionedBackend(t, "ed25519-verify")

	attrs := ed25519KeyAttrs("ed25519-signer")
	signer, err := b.GenerateEd25519(attrs)
	require.NoError(t, err)
	require.NotNil(t, signer)

	pub, ok := signer.Public().(ed25519.PublicKey)
	require.True(t, ok, "an Ed25519 key must expose an ed25519.PublicKey")
	require.Len(t, pub, ed25519.PublicKeySize)

	// Ed25519 signs the message itself, never a pre-computed digest.
	message := []byte("pkcs11 ed25519 message under test")
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	require.NoError(t, err)
	require.Len(t, signature, ed25519.SignatureSize)

	assert.True(t, ed25519.Verify(pub, message, signature),
		"crypto/ed25519 must accept the signature the token produced")
	assert.False(t, ed25519.Verify(pub, []byte("a different message"), signature),
		"the signature must not verify over a different message")

	// The cached public key must be stable across calls.
	assert.Equal(t, pub, signer.Public().(ed25519.PublicKey))
}

// TestBackend_GenerateEd25519_Rejected proves Ed25519 generation is refused
// where it cannot work: YubiKey PIV has no Edwards curve slot, and an
// unauthenticated backend has no session to generate in.
func TestBackend_GenerateEd25519_Rejected(t *testing.T) {
	t.Run("yubikey-piv", func(t *testing.T) {
		b := &Backend{config: &Config{Library: "/usr/lib/libykcs11.so", TokenLabel: "piv"}}
		require.True(t, b.config.IsYubiKeyPIV())

		signer, err := b.GenerateEd25519(ed25519KeyAttrs("piv-ed25519"))
		require.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
		assert.Contains(t, err.Error(), "YubiKey PIV does not support Ed25519")
		assert.Nil(t, signer)
	})

	t.Run("invalid-piv-slot", func(t *testing.T) {
		b := newProvisionedBackend(t, "ed25519-bad-slot")

		attrs := ed25519KeyAttrs("ed25519-bad-slot")
		attrs.PIVSlot = "zz"

		signer, err := b.GenerateEd25519(attrs)
		require.ErrorIs(t, err, ErrInvalidKeyAttributes)
		assert.Nil(t, signer)
	})
}

// TestPkcs11Ed25519Signer_Errors proves the Ed25519 signer degrades safely
// when it has no pool, and that a public key that cannot be read from the HSM
// fails signer construction loudly rather than being deferred to a silent nil
// from Public() later (M4).
func TestPkcs11Ed25519Signer_Errors(t *testing.T) {
	t.Run("no-pool", func(t *testing.T) {
		signer := &pkcs11Ed25519Signer{label: "orphan"}

		assert.Nil(t, signer.Public(), "an unconstructed signer reports no public key")

		signature, err := signer.Sign(rand.Reader, []byte("message"), crypto.Hash(0))
		require.Error(t, err)
		var msg *errs.Message
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "pkcs11: session pool not initialized", msg.Msg)
		assert.Nil(t, signature)
	})

	t.Run("construction-fails-on-unreadable-public-handle", func(t *testing.T) {
		b := newProvisionedBackend(t, "ed25519-bad-handle")

		signer, err := newEd25519Signer(b.Pool(), 0, 0, []byte("bogus"))
		require.Error(t, err,
			"a signer must not be constructed when its public key cannot be read from the HSM")
		assert.Nil(t, signer)
	})

	t.Run("sign-with-non-signing-handle", func(t *testing.T) {
		b := newProvisionedBackend(t, "ed25519-bad-signer")
		signer := &pkcs11Ed25519Signer{pool: b.Pool(), privateHandle: 0, label: "bogus"}

		signature, err := signer.Sign(rand.Reader, []byte("message"), crypto.Hash(0))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pkcs11: Ed25519 SignInit")
		assert.Nil(t, signature)
	})
}

// TestBackend_Signer_RSASignatureVerifies proves the signer returned for an
// RSA key on the token signs with the key the token holds.
//
// Two independent oracles are used: the exported modulus is compared against
// CKA_MODULUS read straight from the token, and the signature is checked with
// crypto/rsa rather than with the token's own C_Verify.
func TestBackend_Signer_RSASignatureVerifies(t *testing.T) {
	b := newProvisionedBackend(t, "signer-rsa")
	session := openIntrospectionSession(t, b)

	attrs := rsaKeyAttrs("rsa-signer", 2048)
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	signer, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err)

	pub, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, 2048, pub.N.BitLen(), "the generated key must be 2048 bits")
	assert.Equal(t, 65537, pub.E)

	// Oracle 1: the modulus the backend reports must be the modulus stored on
	// the token.
	handle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(createKeyID(attrs))),
	})
	read, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, new(big.Int).SetBytes(read[0].Value).Cmp(pub.N),
		"the exported modulus must equal CKA_MODULUS on the token")

	// Oracle 2: crypto/rsa must accept the signature.
	digest := sha256.Sum256([]byte("rsa payload"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature),
		"crypto/rsa must accept the PKCS#1 v1.5 signature the token produced")

	tampered := append([]byte(nil), signature...)
	tampered[0] ^= 0xff
	assert.Error(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], tampered),
		"a corrupted signature must not verify")
}

// TestBackend_Signer_ECDSASignatureVerifies proves the ECDSA signer produces
// ASN.1 signatures that crypto/ecdsa accepts, and that the exported point
// matches the curve requested.
func TestBackend_Signer_ECDSASignatureVerifies(t *testing.T) {
	b := newProvisionedBackend(t, "signer-ecdsa")

	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			attrs := ecdsaKeyAttrs("ecdsa-"+curve.Params().Name, curve)
			_, err := b.GenerateKey(context.Background(), attrs)
			require.NoError(t, err)

			signer, err := b.Signer(context.Background(), attrs)
			require.NoError(t, err)

			pub, ok := signer.Public().(*ecdsa.PublicKey)
			require.True(t, ok)
			assert.Equal(t, curve.Params().Name, pub.Curve.Params().Name,
				"the key must live on the requested curve")
			assert.True(t, pub.IsOnCurve(pub.X, pub.Y), //nolint:staticcheck // SA1019: on-curve validation of the exported point; crypto/ecdh migration is a separate, behavior-sensitive change
				"the exported point must lie on the curve")

			digest := sha256.Sum256([]byte("ecdsa payload"))
			signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			require.NoError(t, err)

			assert.True(t, ecdsa.VerifyASN1(pub, digest[:], signature),
				"crypto/ecdsa must accept the signature the token produced")

			digest[0] ^= 0xff
			assert.False(t, ecdsa.VerifyASN1(pub, digest[:], signature),
				"the signature must not verify over a different digest")
		})
	}
}

// TestBackend_Signer_Rejected proves the signer lookup distinguishes "no
// session" from "no such key" and refuses an unmappable PIV slot, so a caller
// never receives a signer for a key it did not ask for.
func TestBackend_Signer_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "signer-rejected")

	t.Run("key-not-found", func(t *testing.T) {
		signer, err := b.Signer(context.Background(), rsaKeyAttrs("never-generated", 2048))
		require.ErrorIs(t, err, backend.ErrKeyNotFound)
		assert.Contains(t, err.Error(), "never-generated")
		assert.Nil(t, signer)
	})

	t.Run("invalid-piv-slot", func(t *testing.T) {
		attrs := rsaKeyAttrs("piv-key", 2048)
		attrs.PIVSlot = "ff"

		signer, err := b.Signer(context.Background(), attrs)
		require.ErrorIs(t, err, ErrInvalidKeyAttributes)
		assert.Contains(t, err.Error(), "invalid PIV slot: ff")
		assert.Nil(t, signer)
	})

	t.Run("not-initialized", func(t *testing.T) {
		fresh := &Backend{config: b.config}
		signer, err := fresh.Signer(context.Background(), rsaKeyAttrs("any", 2048))
		require.ErrorIs(t, err, ErrNotInitialized)
		assert.Nil(t, signer)
	})
}

// TestBackend_GetKey_MatchesSigner proves GetKey resolves the same hardware
// key as Signer. GetKey is the types.KeyProvider entry point, so a divergence
// would mean two APIs addressing different keys.
func TestBackend_GetKey_MatchesSigner(t *testing.T) {
	b := newProvisionedBackend(t, "getkey")

	attrs := ecdsaKeyAttrs("getkey-ecdsa", elliptic.P256())
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	key, err := b.GetKey(context.Background(), attrs)
	require.NoError(t, err)

	signer, ok := key.(crypto.Signer)
	require.True(t, ok, "PKCS#11 keys are always hardware signers")

	reference, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, reference.Public(), signer.Public(),
		"GetKey and Signer must resolve the same public key")
}

// TestBackend_GetKey_NotFound proves GetKey surfaces a missing key rather
// than a nil interface a caller would panic on.
func TestBackend_GetKey_NotFound(t *testing.T) {
	b := newProvisionedBackend(t, "getkey-missing")

	key, err := b.GetKey(context.Background(), ecdsaKeyAttrs("absent", elliptic.P256()))
	require.ErrorIs(t, err, backend.ErrKeyNotFound)
	assert.Nil(t, key)
}

// TestBackend_GetSignerByID proves the by-name lookup addresses the same
// object as the attribute-based lookup.
//
// GetSignerByID builds attributes with no key algorithm, so it can only
// resolve keys whose CKA_ID was derived the same way. The test pins that
// contract explicitly so a change to createKeyID cannot silently break it.
func TestBackend_GetSignerByID(t *testing.T) {
	b := newProvisionedBackend(t, "signer-by-id")

	attrs := &types.KeyAttributes{
		CN:        "by-id-key",
		KeyType:   backend.KEY_TYPE_SIGNING,
		StoreType: types.StorePKCS11,
	}
	require.Equal(t, "by-id-key.", createKeyID(attrs),
		"an attribute set with no algorithm yields a bare CN key ID")

	generated, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	signer, err := b.GetSignerByID("by-id-key")
	require.NoError(t, err)
	assert.Equal(t, generated.Public(), signer.Public(),
		"GetSignerByID must resolve the key GenerateRSA created")
}

// TestBackend_GetSignerByID_NotFound proves an unknown name is reported as a
// missing key instead of a nil signer.
func TestBackend_GetSignerByID_NotFound(t *testing.T) {
	b := newProvisionedBackend(t, "signer-by-id-missing")

	signer, err := b.GetSignerByID("no-such-key")
	require.ErrorIs(t, err, backend.ErrKeyNotFound)
	assert.Nil(t, signer)
}

// TestBackend_GetDecrypterByID proves the by-name decrypter lookup returns a
// key that actually decrypts, using crypto/rsa as the encryption oracle.
// encryptPKCS1v15 is the software oracle for the decrypter's PKCS#1 v1.5 path
// (nil opts). The token performs that decryption (CKM_RSA_PKCS), outside the
// stdlib's FIPS 140 module, so the backend serves it in every FIPS mode; the
// oracle stands in for the remote sender and encrypts outside this process's
// enforcement (#23).
func encryptPKCS1v15(t *testing.T, pub *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()

	var ciphertext []byte
	var err error
	fips140.WithoutEnforcement(func() {
		ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext) //nolint:staticcheck // SA1019: exercises the decrypter's PKCS#1 v1.5 path (nil opts), which the pkcs11 backend supports for real via CKM_RSA_PKCS
	})
	require.NoError(t, err)
	return ciphertext
}

func TestBackend_GetDecrypterByID(t *testing.T) {
	b := newProvisionedBackend(t, "decrypter-by-id")

	attrs := &types.KeyAttributes{
		CN:        "decrypt-by-id",
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: types.StorePKCS11,
	}
	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	decrypter, err := b.GetDecrypterByID("decrypt-by-id")
	require.NoError(t, err)

	pub, ok := decrypter.Public().(*rsa.PublicKey)
	require.True(t, ok)

	plaintext := []byte("decrypter-by-id secret")
	ciphertext := encryptPKCS1v15(t, pub, plaintext)

	recovered, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered)
}

// TestBackend_GetDecrypterByID_NotFound proves an unknown name is reported as
// a missing key.
func TestBackend_GetDecrypterByID_NotFound(t *testing.T) {
	b := newProvisionedBackend(t, "decrypter-by-id-missing")

	decrypter, err := b.GetDecrypterByID("no-such-key")
	require.ErrorIs(t, err, backend.ErrKeyNotFound)
	assert.Nil(t, decrypter)
}

// TestBackend_Decrypter_RSARoundTrip proves the decrypter recovers a
// plaintext that crypto/rsa encrypted under the token's public key. The
// software side is the oracle: the HSM never sees the plaintext beforehand.
func TestBackend_Decrypter_RSARoundTrip(t *testing.T) {
	b := newProvisionedBackend(t, "decrypter-rsa")

	attrs := rsaKeyAttrs("decrypt-rsa", 2048)
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	decrypter, err := b.Decrypter(context.Background(), attrs)
	require.NoError(t, err)

	pub, ok := decrypter.Public().(*rsa.PublicKey)
	require.True(t, ok)

	plaintext := []byte("hardware-protected plaintext")
	ciphertext := encryptPKCS1v15(t, pub, plaintext)

	recovered, err := decrypter.Decrypt(rand.Reader, ciphertext, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered, "the HSM must recover the exact plaintext")

	// A ciphertext that is not modulus-sized is structurally invalid and must
	// be rejected, not silently zero-extended.
	_, err = decrypter.Decrypt(rand.Reader, ciphertext[:len(ciphertext)-1], nil)
	assert.Error(t, err, "a ciphertext of the wrong length must be rejected")

	// A ciphertext whose PKCS#1 v1.5 padding is corrupted may legitimately
	// return either an error or a pseudorandom message: OpenSSL, which backs
	// SoftHSM, applies implicit rejection to close the Bleichenbacher oracle
	// rather than reporting a padding failure. The property that must hold in
	// every case is that the true plaintext is never recovered.
	corrupted := append([]byte(nil), ciphertext...)
	corrupted[1] ^= 0xff
	recovered, err = decrypter.Decrypt(rand.Reader, corrupted, nil)
	if err == nil {
		assert.NotEqual(t, plaintext, recovered,
			"a corrupted ciphertext must never yield the original plaintext")
	}
}

// TestBackend_Decrypter_Rejected proves Decrypter refuses keys that cannot
// decrypt and reports a missing key distinctly.
func TestBackend_Decrypter_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "decrypter-rejected")

	t.Run("ecdsa-cannot-decrypt", func(t *testing.T) {
		attrs := ecdsaKeyAttrs("decrypt-ecdsa", elliptic.P256())
		_, err := b.GenerateKey(context.Background(), attrs)
		require.NoError(t, err)

		decrypter, err := b.Decrypter(context.Background(), attrs)
		require.ErrorIs(t, err, backend.ErrOperationNotSupported)
		assert.Nil(t, decrypter)
	})

	t.Run("key-not-found", func(t *testing.T) {
		decrypter, err := b.Decrypter(context.Background(), rsaKeyAttrs("absent-rsa", 2048))
		require.ErrorIs(t, err, backend.ErrKeyNotFound)
		assert.Nil(t, decrypter)
	})
}

// TestBackend_Sign_UsesToken proves the package-level Sign helper produces a
// signature verifiable with crypto/ecdsa under the key it names.
func TestBackend_Sign_UsesToken(t *testing.T) {
	b := newProvisionedBackend(t, "sign-helper")

	attrs := ecdsaKeyAttrs("sign-helper-key", elliptic.P256())
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("sign helper payload"))
	signature, err := b.Sign(attrs, digest[:], crypto.SHA256)
	require.NoError(t, err)

	signer, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err)
	pub := signer.Public().(*ecdsa.PublicKey)

	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], signature))
}

// TestBackend_Sign_KeyNotFound proves Sign refuses to sign with a key that
// does not exist rather than returning an empty signature.
func TestBackend_Sign_KeyNotFound(t *testing.T) {
	b := newProvisionedBackend(t, "sign-missing")

	digest := sha256.Sum256([]byte("payload"))
	signature, err := b.Sign(ecdsaKeyAttrs("absent", elliptic.P256()), digest[:], crypto.SHA256)
	require.ErrorIs(t, err, backend.ErrKeyNotFound)
	assert.Nil(t, signature)
}

// TestBackend_Verify_RealToken exercises Verify against keys that actually
// live on the token.
//
// The negative cases matter most: Verify must reject a signature over a
// different digest, and must refuse rather than guess for key types whose
// verification needs information it was not given.
func TestBackend_Verify_RealToken(t *testing.T) {
	b := newProvisionedBackend(t, "verify-real")

	t.Run("ecdsa-accepts-valid-signature", func(t *testing.T) {
		attrs := ecdsaKeyAttrs("verify-ecdsa", elliptic.P256())
		_, err := b.GenerateKey(context.Background(), attrs)
		require.NoError(t, err)

		digest := sha256.Sum256([]byte("verify payload"))
		signature, err := b.Sign(attrs, digest[:], crypto.SHA256)
		require.NoError(t, err)

		require.NoError(t, b.Verify(attrs, digest[:], signature))

		other := sha256.Sum256([]byte("a different payload"))
		err = b.Verify(attrs, other[:], signature)
		require.Error(t, err)
		var msg *errs.Message
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "signature verification failed", msg.Msg)
	})

	t.Run("rsa-requires-a-stated-signature-algorithm", func(t *testing.T) {
		attrs := rsaKeyAttrs("verify-rsa-unstated", 2048)
		_, err := b.GenerateKey(context.Background(), attrs)
		require.NoError(t, err)

		digest := sha256.Sum256([]byte("verify payload"))
		signature, err := b.Sign(attrs, digest[:], crypto.SHA256)
		require.NoError(t, err)

		err = b.Verify(attrs, digest[:], signature)
		require.ErrorIs(t, err, backend.ErrInvalidAlgorithm,
			"PKCS#1 v1.5 and PSS are not interchangeable, so the scheme must be stated rather than guessed")
		assert.Contains(t, err.Error(), "SignatureAlgorithm",
			"the error must name the attribute the caller has to set")
	})

	t.Run("ed25519-accepts-valid-signature", func(t *testing.T) {
		attrs := ed25519KeyAttrs("verify-ed25519")
		signer, err := b.GenerateKey(context.Background(), attrs)
		require.NoError(t, err)

		// Ed25519 signs the message itself, not a digest (RFC 8032 section 4).
		message := []byte("ed25519 verify payload")
		signature, err := b.Sign(attrs, message, crypto.Hash(0))
		require.NoError(t, err)

		public, ok := signer.(crypto.Signer).Public().(ed25519.PublicKey)
		require.True(t, ok, "an Ed25519 key must expose an ed25519.PublicKey")
		require.True(t, ed25519.Verify(public, message, signature),
			"oracle: crypto/ed25519 must accept the token's signature")

		require.NoError(t, b.Verify(attrs, message, signature))

		err = b.Verify(attrs, []byte("a different message"), signature)
		require.Error(t, err)
		var msg *errs.Message
		require.ErrorAs(t, err, &msg)
		assert.Equal(t, "signature verification failed", msg.Msg)
	})

	t.Run("key-not-found", func(t *testing.T) {
		err := b.Verify(ecdsaKeyAttrs("absent", elliptic.P256()), []byte("d"), []byte("s"))
		require.ErrorIs(t, err, backend.ErrKeyNotFound)
	})

	t.Run("not-initialized", func(t *testing.T) {
		fresh := &Backend{config: b.config}
		err := fresh.Verify(ecdsaKeyAttrs("x", elliptic.P256()), []byte("d"), []byte("s"))
		require.ErrorIs(t, err, ErrNotInitialized)
	})
}

// rsaSignatureCase describes one RSA signature algorithm together with the
// hash it is defined over and the signer options that produce a signature
// under it.
type rsaSignatureCase struct {
	algorithm x509.SignatureAlgorithm
	hash      crypto.Hash
	opts      crypto.SignerOpts
	// mismatched is the algorithm that uses the same digest but the other
	// padding scheme, which a signature under algorithm must not verify under.
	mismatched x509.SignatureAlgorithm
}

// rsaSignatureCases covers both RSA padding schemes at three digest sizes.
func rsaSignatureCases() map[string]rsaSignatureCase {
	return map[string]rsaSignatureCase{
		"pkcs1v15-sha256": {x509.SHA256WithRSA, crypto.SHA256, crypto.SHA256, x509.SHA256WithRSAPSS},
		"pkcs1v15-sha384": {x509.SHA384WithRSA, crypto.SHA384, crypto.SHA384, x509.SHA384WithRSAPSS},
		"pkcs1v15-sha512": {x509.SHA512WithRSA, crypto.SHA512, crypto.SHA512, x509.SHA512WithRSAPSS},
		"pss-sha256": {x509.SHA256WithRSAPSS, crypto.SHA256,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}, x509.SHA256WithRSA},
		"pss-sha384": {x509.SHA384WithRSAPSS, crypto.SHA384,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384}, x509.SHA384WithRSA},
		"pss-sha512": {x509.SHA512WithRSAPSS, crypto.SHA512,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}, x509.SHA512WithRSA},
	}
}

// TestBackend_Verify_RSA proves RSA signatures made by the token verify through
// Backend.Verify under both padding schemes at three digest sizes, and that
// crypto/rsa agrees on every one of them.
//
// crypto/rsa is the oracle on the accepting side: a Verify that returned nil
// unconditionally would pass the positive assertions on its own, so each
// signature is independently checked against the public key the token exposes.
func TestBackend_Verify_RSA(t *testing.T) {
	b := newProvisionedBackend(t, "verify-rsa")

	attrs := rsaKeyAttrs("verify-rsa-key", 2048)
	generated, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	public, ok := generated.(crypto.Signer).Public().(*rsa.PublicKey)
	require.True(t, ok, "an RSA key must expose an *rsa.PublicKey")

	for name, tc := range rsaSignatureCases() {
		t.Run(name, func(t *testing.T) {
			digest := digestFor(t, tc.hash, []byte("rsa verify payload"))

			signing := rsaKeyAttrs(attrs.CN, 2048)
			signature, err := b.Sign(signing, digest, tc.opts)
			require.NoError(t, err, "the token must sign under %s", tc.algorithm)

			// Oracle: the signature is valid under this scheme independently of
			// anything Backend.Verify does.
			if _, isPSS := tc.opts.(*rsa.PSSOptions); isPSS {
				require.NoError(t, rsa.VerifyPSS(public, tc.hash, digest, signature,
					&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: tc.hash}),
					"oracle: crypto/rsa must accept the token's PSS signature")
			} else {
				require.NoError(t, rsa.VerifyPKCS1v15(public, tc.hash, digest, signature),
					"oracle: crypto/rsa must accept the token's PKCS#1 v1.5 signature")
			}

			verifying := rsaKeyAttrs(attrs.CN, 2048)
			verifying.SignatureAlgorithm = tc.algorithm
			verifying.Hash = tc.hash
			require.NoError(t, b.Verify(verifying, digest, signature))

			t.Run("wrong-padding-scheme-is-rejected", func(t *testing.T) {
				mismatched := rsaKeyAttrs(attrs.CN, 2048)
				mismatched.SignatureAlgorithm = tc.mismatched
				err := b.Verify(mismatched, digest, signature)
				require.Error(t, err,
					"a %s signature must not verify as %s: the two paddings are different agreements",
					tc.algorithm, tc.mismatched)
			})

			t.Run("tampered-signature-is-rejected", func(t *testing.T) {
				tampered := make([]byte, len(signature))
				copy(tampered, signature)
				tampered[len(tampered)-1] ^= 0x01

				err := b.Verify(verifying, digest, tampered)
				require.Error(t, err)
				var msg *errs.Message
				require.ErrorAs(t, err, &msg)
				assert.Equal(t, "signature verification failed", msg.Msg)
			})

			t.Run("different-digest-is-rejected", func(t *testing.T) {
				other := digestFor(t, tc.hash, []byte("a different payload"))
				err := b.Verify(verifying, other, signature)
				require.Error(t, err)
			})
		})
	}
}

// TestBackend_Verify_RSA_Rejected proves Verify refuses every case where the
// attributes do not determine exactly one RSA scheme, naming the attribute at
// fault, instead of picking one. A wrong default here decides on the caller's
// behalf which scheme a signature is accepted under.
func TestBackend_Verify_RSA_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "verify-rsa-rejected")

	attrs := rsaKeyAttrs("verify-rsa-rejected-key", 2048)
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	digest := digestFor(t, crypto.SHA256, []byte("rsa verify payload"))
	signature, err := b.Sign(rsaKeyAttrs(attrs.CN, 2048), digest, crypto.SHA256)
	require.NoError(t, err)

	tests := []struct {
		name      string
		mutate    func(*types.KeyAttributes)
		digest    []byte
		wantInErr string
	}{
		{
			name:      "no signature algorithm",
			mutate:    func(ka *types.KeyAttributes) {},
			digest:    digest,
			wantInErr: "SignatureAlgorithm",
		},
		{
			name: "sha1 is not accepted",
			mutate: func(ka *types.KeyAttributes) {
				ka.SignatureAlgorithm = x509.SHA1WithRSA
			},
			digest:    digest,
			wantInErr: "unsupported RSA signature algorithm",
		},
		{
			name: "ecdsa algorithm on an rsa key",
			mutate: func(ka *types.KeyAttributes) {
				ka.SignatureAlgorithm = x509.ECDSAWithSHA256
			},
			digest:    digest,
			wantInErr: "unsupported RSA signature algorithm",
		},
		{
			name: "hash contradicts the signature algorithm",
			mutate: func(ka *types.KeyAttributes) {
				ka.SignatureAlgorithm = x509.SHA256WithRSA
				ka.Hash = crypto.SHA512
			},
			digest:    digest,
			wantInErr: "defined over",
		},
		{
			name: "digest is the wrong length for the algorithm",
			mutate: func(ka *types.KeyAttributes) {
				ka.SignatureAlgorithm = x509.SHA512WithRSA
			},
			digest:    digest,
			wantInErr: "byte digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifying := rsaKeyAttrs(attrs.CN, 2048)
			tt.mutate(verifying)

			err := b.Verify(verifying, tt.digest, signature)
			require.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
			assert.Contains(t, err.Error(), tt.wantInErr,
				"the error must say which attribute the caller has to correct")
		})
	}
}

// TestBackend_Get_NeverExportsPrivateKey pins the security contract of Get:
// even when the key exists, no private key material may be returned. A
// regression here would leak HSM-resident key material through the storage
// interface.
func TestBackend_Get_NeverExportsPrivateKey(t *testing.T) {
	b := newProvisionedBackend(t, "get-no-export")

	attrs := rsaKeyAttrs("get-rsa", 2048)
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	data, err := b.Get(attrs, types.FSExtPrivatePKCS8)
	require.ErrorIs(t, err, backend.ErrNotSupported)
	assert.Contains(t, err.Error(), "PKCS#11 private keys cannot be exported")
	assert.Nil(t, data, "no bytes may be returned for a private key")
}

// TestBackend_Get_IsUnsupportedForEveryExtension proves Get answers the same
// way for a key that exists, a key that does not, and every extension: the
// operation is unsupported, not conditionally supported.
//
// The absent-key case is the one that matters. Reporting backend.ErrKeyNotFound
// there would tell a caller that the key is the problem and that Get would have
// worked had the key existed, which is false for every key on a token. It would
// also mean paying for a token lookup on a call that cannot succeed.
func TestBackend_Get_IsUnsupportedForEveryExtension(t *testing.T) {
	b := newProvisionedBackend(t, "get-unsupported")

	present := rsaKeyAttrs("get-present", 2048)
	_, err := b.GenerateKey(context.Background(), present)
	require.NoError(t, err)

	extensions := map[string]types.FSExtension{
		"private-pkcs8":     types.FSExtPrivatePKCS8,
		"private-pkcs8-pem": types.FSExtPrivatePKCS8PEM,
		"public-pkcs1":      types.FSExtPublicPKCS1,
	}
	for name, extension := range extensions {
		t.Run("key-present-"+name, func(t *testing.T) {
			data, err := b.Get(present, extension)
			require.ErrorIs(t, err, backend.ErrNotSupported)
			assert.Nil(t, data)
		})

		t.Run("key-absent-"+name, func(t *testing.T) {
			data, err := b.Get(rsaKeyAttrs("get-absent", 2048), extension)
			require.ErrorIs(t, err, backend.ErrNotSupported)
			assert.NotErrorIs(t, err, backend.ErrKeyNotFound,
				"an unsupported operation must not be reported as a missing key")
			assert.Nil(t, data)
		})
	}
}

// TestBackend_Get_Rejected proves an uninitialized backend is reported as such
// rather than as an unsupported operation, so a caller can tell a missing
// Login from a capability the backend does not have.
func TestBackend_Get_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "get-rejected")

	fresh := &Backend{config: b.config}
	data, err := fresh.Get(rsaKeyAttrs("absent", 2048), types.FSExtPublicPKCS1)
	require.ErrorIs(t, err, ErrNotInitialized)
	assert.Nil(t, data)
}

// TestBackend_Save_NeverStoresKeyMaterial pins the counterpart contract of
// Save: key material may only be created by the HSM, never injected through
// the storage interface.
func TestBackend_Save_NeverStoresKeyMaterial(t *testing.T) {
	b := newProvisionedBackend(t, "save-rejected")

	err := b.Save(rsaKeyAttrs("save-rsa", 2048), []byte("private key bytes"), types.FSExtPrivatePKCS8, true)
	require.ErrorIs(t, err, backend.ErrNotSupported)
	assert.Contains(t, err.Error(), "use GenerateKey methods to create keys on HSM")

	fresh := &Backend{config: b.config}
	require.ErrorIs(t,
		fresh.Save(rsaKeyAttrs("save-rsa", 2048), nil, types.FSExtPrivatePKCS8, true),
		ErrNotInitialized)
}

// TestBackend_RotateKey_NotSupported proves rotation is refused even when the
// named key exists. Silently succeeding would let a caller believe a
// compromised key had been replaced.
func TestBackend_RotateKey_NotSupported(t *testing.T) {
	b := newProvisionedBackend(t, "rotate")

	attrs := ecdsaKeyAttrs("rotate-key", elliptic.P256())
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	before, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err)

	require.ErrorIs(t, b.RotateKey(context.Background(), attrs), backend.ErrOperationNotSupported)

	after, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, before.Public(), after.Public(),
		"a refused rotation must leave the existing key untouched")

	fresh := &Backend{config: b.config}
	require.ErrorIs(t, fresh.RotateKey(context.Background(), attrs), backend.ErrOperationNotSupported)
}

// TestBackend_DeleteKey_RemovesBothObjects proves DeleteKey destroys the
// private and the public object, verified by searching the token directly.
//
// Leaving the public half behind would make the key appear to still exist to
// findKeyPairByID, and leaving the private half behind would leave usable key
// material on the device after a revocation.
func TestBackend_DeleteKey_RemovesBothObjects(t *testing.T) {
	b := newProvisionedBackend(t, "delete-key")
	session := openIntrospectionSession(t, b)

	attrs := ecdsaKeyAttrs("delete-me", elliptic.P256())
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	id := []byte(createKeyID(attrs))
	require.Equal(t, 1, countObjects(t, b, session, pkcs11.CKO_PRIVATE_KEY, id))
	require.Equal(t, 1, countObjects(t, b, session, pkcs11.CKO_PUBLIC_KEY, id))

	require.NoError(t, b.DeleteKey(context.Background(), attrs))

	assert.Equal(t, 0, countObjects(t, b, session, pkcs11.CKO_PRIVATE_KEY, id),
		"the private key object must be gone from the token")
	assert.Equal(t, 0, countObjects(t, b, session, pkcs11.CKO_PUBLIC_KEY, id),
		"the public key object must be gone from the token")

	signer, err := b.Signer(context.Background(), attrs)
	require.ErrorIs(t, err, backend.ErrKeyNotFound, "the deleted key must no longer resolve")
	assert.Nil(t, signer)
}

// TestBackend_Delete_AliasMatchesDeleteKey proves the storage-interface alias
// performs the same destruction as DeleteKey.
func TestBackend_Delete_AliasMatchesDeleteKey(t *testing.T) {
	b := newProvisionedBackend(t, "delete-alias")
	session := openIntrospectionSession(t, b)

	attrs := rsaKeyAttrs("delete-alias-key", 2048)
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	id := []byte(createKeyID(attrs))
	require.Equal(t, 1, countObjects(t, b, session, pkcs11.CKO_PRIVATE_KEY, id))

	require.NoError(t, b.Delete(attrs))
	assert.Equal(t, 0, countObjects(t, b, session, pkcs11.CKO_PRIVATE_KEY, id))
	assert.Equal(t, 0, countObjects(t, b, session, pkcs11.CKO_PUBLIC_KEY, id))
}

// TestBackend_DeleteKey_Rejected proves deletion of a key that is not present
// is reported as a missing key rather than silently succeeding, which would
// let an operator believe a key had been destroyed.
func TestBackend_DeleteKey_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "delete-rejected")

	t.Run("key-not-found", func(t *testing.T) {
		err := b.DeleteKey(context.Background(), ecdsaKeyAttrs("never-created", elliptic.P256()))
		require.ErrorIs(t, err, backend.ErrKeyNotFound)
		assert.Contains(t, err.Error(), "never-created")
	})

	t.Run("invalid-piv-slot", func(t *testing.T) {
		attrs := ecdsaKeyAttrs("piv-delete", elliptic.P256())
		attrs.PIVSlot = "not-a-slot"

		require.ErrorIs(t, b.DeleteKey(context.Background(), attrs), ErrInvalidKeyAttributes)
	})

	t.Run("not-initialized", func(t *testing.T) {
		fresh := &Backend{config: b.config}
		require.ErrorIs(t,
			fresh.DeleteKey(context.Background(), ecdsaKeyAttrs("x", elliptic.P256())),
			ErrNotInitialized)
	})
}

// TestBackend_FindObjectsByClassAndID proves the object search returns every
// matching handle and reports an empty result, not an error, when nothing
// matches. deleteKeyInSession relies on that distinction to decide between
// "already gone" and "device failure".
func TestBackend_FindObjectsByClassAndID(t *testing.T) {
	b := newProvisionedBackend(t, "find-objects")
	session := openIntrospectionSession(t, b)

	attrs := ecdsaKeyAttrs("find-objects-key", elliptic.P256())
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	id := []byte(createKeyID(attrs))

	private, err := b.findObjectsByClassAndID(session, pkcs11.CKO_PRIVATE_KEY, id)
	require.NoError(t, err)
	assert.Len(t, private, 1)

	public, err := b.findObjectsByClassAndID(session, pkcs11.CKO_PUBLIC_KEY, id)
	require.NoError(t, err)
	assert.Len(t, public, 1)
	assert.NotEqual(t, private[0], public[0], "the two halves must be distinct objects")

	t.Run("no-match", func(t *testing.T) {
		objs, err := b.findObjectsByClassAndID(session, pkcs11.CKO_PRIVATE_KEY, []byte("no-such-id"))
		require.NoError(t, err, "an empty result is not an error")
		assert.Empty(t, objs)
	})

	t.Run("device-error", func(t *testing.T) {
		broken := &Backend{config: b.config, p11ctx: b.p11ctx}
		_, err := broken.findObjectsByClassAndID(pkcs11.SessionHandle(0), pkcs11.CKO_PRIVATE_KEY, id)
		require.Error(t, err, "an invalid session handle must be reported, not ignored")
		var wrapped *errs.Wrapped
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to init find objects", wrapped.Msg)
	})
}

// TestBackend_GenerateSecretKey_AttributesMatchRequest proves an AES key
// generated on the token carries the size that was asked for and the
// protection attributes the backend promises.
//
// CKA_SENSITIVE and CKA_EXTRACTABLE are the whole point of putting the key in
// an HSM: if either flipped, the key could be read out in the clear
// (PKCS#11 v3.2, section 4.9 secret key objects).
func TestBackend_GenerateSecretKey_AttributesMatchRequest(t *testing.T) {
	b := newProvisionedBackend(t, "secret-key-attrs")
	session := openIntrospectionSession(t, b)

	for _, bits := range []int{128, 192, 256} {
		t.Run(pkcs11AESName(bits), func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:        pkcs11AESName(bits),
				KeyType:   backend.KEY_TYPE_ENCRYPTION,
				StoreType: types.StorePKCS11,
			}

			handle, err := b.GenerateSecretKey(attrs, bits)
			require.NoError(t, err)
			require.NotZero(t, handle)

			read, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil),
				pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
				pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			})
			require.NoError(t, err)

			assert.Equal(t, byte(pkcs11.CKO_SECRET_KEY), read[0].Value[0], "CKA_CLASS must be CKO_SECRET_KEY")
			assert.Equal(t, byte(pkcs11.CKK_AES), read[1].Value[0], "CKA_KEY_TYPE must be CKK_AES")
			assert.Equal(t, byte(bits/8), read[2].Value[0], "CKA_VALUE_LEN must be the requested size in bytes")
			assert.Equal(t, byte(1), read[3].Value[0], "an HSM secret key must be CKA_SENSITIVE")
			assert.Equal(t, byte(0), read[4].Value[0], "an HSM secret key must not be CKA_EXTRACTABLE")
			assert.Equal(t, createKeyID(attrs), string(read[5].Value))

			found, err := b.FindSecretKey(attrs)
			require.NoError(t, err)
			assert.Equal(t, handle, found, "FindSecretKey must return the handle that was generated")
		})
	}
}

// TestBackend_GenerateSecretKey_Rejected proves sizes outside FIPS 197 and an
// uninitialized backend are refused. Accepting an unsupported size would let
// the token silently choose one.
//
// 192 is deliberately absent from this list: FIPS 197 defines AES-192 and
// CKM_AES_KEY_GEN accepts it, so refusing it here rejected a size the token
// advertises through CK_MECHANISM_INFO's key-size range.
func TestBackend_GenerateSecretKey_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "secret-key-rejected")

	attrs := &types.KeyAttributes{CN: "bad-aes", StoreType: types.StorePKCS11}

	for _, bits := range []int{0, 64, 160, 512, -128} {
		t.Run(pkcs11AESName(bits), func(t *testing.T) {
			handle, err := b.GenerateSecretKey(attrs, bits)
			require.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
			assert.Zero(t, handle)
		})
	}

	t.Run("not-initialized", func(t *testing.T) {
		fresh := &Backend{config: b.config}
		handle, err := fresh.GenerateSecretKey(attrs, 256)
		require.ErrorIs(t, err, ErrNotInitialized)
		assert.Zero(t, handle)
	})
}

// TestBackend_FindSecretKey_Rejected proves a secret key that was never
// generated is reported as missing rather than returning handle 0, which a
// caller could mistake for a valid object.
func TestBackend_FindSecretKey_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "find-secret-rejected")

	attrs := &types.KeyAttributes{CN: "no-such-secret", StoreType: types.StorePKCS11}

	handle, err := b.FindSecretKey(attrs)
	require.ErrorIs(t, err, backend.ErrKeyNotFound)
	assert.Zero(t, handle)

	fresh := &Backend{config: b.config}
	handle, err = fresh.FindSecretKey(attrs)
	require.ErrorIs(t, err, ErrNotInitialized)
	assert.Zero(t, handle)
}

// TestBackend_ListKeys_RoundTripsToSigner proves the attributes ListKeys
// reports can be handed straight back to Signer.
//
// This is the contract the API and CLI layers depend on: they enumerate keys
// and then act on the entries they were given. If ListKeys reported a CN or
// algorithm that resolveKeyID cannot turn back into the same CKA_ID, every
// listed key would be unusable.
func TestBackend_ListKeys_RoundTripsToSigner(t *testing.T) {
	b := newProvisionedBackend(t, "list-keys")

	generated := map[string]x509.PublicKeyAlgorithm{
		"list-rsa":     x509.RSA,
		"list-ecdsa":   x509.ECDSA,
		"list-ed25519": x509.Ed25519,
	}
	attrsByCN := map[string]*types.KeyAttributes{
		"list-rsa":     rsaKeyAttrs("list-rsa", 2048),
		"list-ecdsa":   ecdsaKeyAttrs("list-ecdsa", elliptic.P256()),
		"list-ed25519": ed25519KeyAttrs("list-ed25519"),
	}
	for cn := range generated {
		_, err := b.GenerateKey(context.Background(), attrsByCN[cn])
		require.NoError(t, err, "generating %s", cn)
	}

	listed, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, listed, len(generated), "every generated private key must be enumerated")

	seen := make(map[string]*types.KeyAttributes, len(listed))
	for _, ka := range listed {
		assert.Equal(t, types.StorePKCS11, ka.StoreType)
		seen[ka.CN] = ka
	}

	for cn, algorithm := range generated {
		ka, ok := seen[cn]
		require.True(t, ok, "ListKeys must report %q; got %v", cn, keysOf(seen))
		assert.Equal(t, algorithm, ka.KeyAlgorithm, "%s must be reported with its real algorithm", cn)

		signer, err := b.Signer(context.Background(), ka)
		require.NoError(t, err, "the attributes ListKeys returned for %q must resolve back to the key", cn)

		reference, err := b.Signer(context.Background(), attrsByCN[cn])
		require.NoError(t, err)
		assert.Equal(t, reference.Public(), signer.Public(),
			"the round-tripped attributes must resolve the same key")
	}
}

// TestBackend_ListKeys_ReturnsEveryKeyPastTheFirstBatch proves ListKeys drives
// C_FindObjects to exhaustion instead of reporting the first batch as the whole
// token.
//
// The token is deliberately filled past findObjectsBatchSize, because a search
// that stops after one call is indistinguishable from a correct one on any
// smaller token: it returns a plausible, complete-looking list that is missing
// every key past the batch boundary. An operator auditing keys, or a rotation
// job enumerating them, would never see the difference.
//
// The oracle is the set of CNs the test provisioned, not the length ListKeys
// happens to return.
func TestBackend_ListKeys_ReturnsEveryKeyPastTheFirstBatch(t *testing.T) {
	b := newProvisionedBackend(t, "list-paginated")

	// One full batch plus a partial one, so the loop must run at least twice
	// and must also terminate on the short batch.
	total := findObjectsBatchSize + 5

	provisioned := make(map[string]bool, total)
	for i := 0; i < total; i++ {
		attrs := ecdsaKeyAttrs(fmt.Sprintf("paged-%04d", i), elliptic.P256())
		_, err := b.GenerateKey(context.Background(), attrs)
		require.NoError(t, err, "provisioning key %d", i)
		provisioned[attrs.CN] = true
	}

	listed, err := b.ListKeys(context.Background())
	require.NoError(t, err)

	seen := make(map[string]bool, len(listed))
	for _, ka := range listed {
		assert.False(t, seen[ka.CN], "ListKeys reported %q twice", ka.CN)
		seen[ka.CN] = true
	}

	var missing []string
	for cn := range provisioned {
		if !seen[cn] {
			missing = append(missing, cn)
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing, "ListKeys must report every provisioned key; %d of %d missing", len(missing), total)
	assert.Len(t, listed, total, "ListKeys must report exactly the provisioned keys")
}

// TestBackend_findAllObjects_Rejected proves the search helper reports a
// failing session rather than returning an empty result, which a caller would
// read as "this token holds nothing".
func TestBackend_findAllObjects_Rejected(t *testing.T) {
	owner := newProvisionedBackend(t, "find-all-rejected")

	attrs := ecdsaKeyAttrs("find-all-key", elliptic.P256())
	_, err := owner.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	broken := staleSessionBackend(t, owner)

	handles, err := broken.findAllObjects(pkcs11.SessionHandle(0), []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	})
	require.Error(t, err, "an unusable session must not be reported as an empty token")
	assert.Empty(t, handles)
}

// TestDecodeKeyType_CoversEveryGeneratedKeyType proves the CKA_KEY_TYPE
// dispatch used by ListKeys knows every key type this backend can put on a
// token, including the post-quantum ones.
//
// A key type missing from the table enumerates with no algorithm at all, and an
// entry with no algorithm makes resolveKeyID compute a different CKA_ID than
// the one the key was created under -- so operations such as DeleteKey would be
// routed at the wrong object, or at none.
func TestDecodeKeyType_CoversEveryGeneratedKeyType(t *testing.T) {
	tests := []struct {
		name          string
		keyType       uint
		label         string
		wantCN        string
		wantAlgorithm x509.PublicKeyAlgorithm
		wantQuantum   types.QuantumAlgorithm
	}{
		{
			name:          "rsa",
			keyType:       pkcs11.CKK_RSA,
			label:         "web-server.rsa",
			wantCN:        "web-server",
			wantAlgorithm: x509.RSA,
		},
		{
			name:          "ecdsa",
			keyType:       pkcs11.CKK_EC,
			label:         "web-server.ecdsa",
			wantCN:        "web-server",
			wantAlgorithm: x509.ECDSA,
		},
		{
			name:          "ed25519",
			keyType:       CKK_EC_EDWARDS,
			label:         "web-server.ed25519",
			wantCN:        "web-server",
			wantAlgorithm: x509.Ed25519,
		},
		{
			name:        "ml-dsa",
			keyType:     CKK_ML_DSA,
			label:       "pq-signer.ml-dsa-65",
			wantCN:      "pq-signer",
			wantQuantum: types.QuantumAlgorithmMLDSA65,
		},
		{
			name:        "ml-kem",
			keyType:     CKK_ML_KEM,
			label:       "pq-kem.ml-kem-768",
			wantCN:      "pq-kem",
			wantQuantum: types.QuantumAlgorithmMLKEM768,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ka := &types.KeyAttributes{StoreType: types.StorePKCS11}
			decodeKeyType(ka, tt.keyType, tt.label)

			assert.Equal(t, tt.wantCN, ka.CN)
			assert.Equal(t, tt.wantAlgorithm, ka.KeyAlgorithm)

			if tt.wantQuantum == "" {
				assert.Nil(t, ka.QuantumAttributes, "a classical key must not report a quantum algorithm")
				return
			}
			require.NotNil(t, ka.QuantumAttributes, "a post-quantum key must report its parameter set")
			assert.Equal(t, tt.wantQuantum, ka.QuantumAttributes.Algorithm)
		})
	}
}

// TestDecodeKeyType_UnrecognizedInput proves a key this backend did not create
// is reported as an opaque name rather than as a key of some invented
// algorithm. Guessing here would hand the caller attributes that resolve to a
// CKA_ID no object has.
func TestDecodeKeyType_UnrecognizedInput(t *testing.T) {
	t.Run("unknown-key-type", func(t *testing.T) {
		ka := &types.KeyAttributes{}
		decodeKeyType(ka, pkcs11.CKK_DES3, "legacy-des3-key")

		assert.Equal(t, "legacy-des3-key", ka.CN)
		assert.Equal(t, x509.UnknownPublicKeyAlgorithm, ka.KeyAlgorithm)
		assert.Nil(t, ka.QuantumAttributes)
	})

	t.Run("quantum-key-type-with-a-foreign-label", func(t *testing.T) {
		ka := &types.KeyAttributes{}
		decodeKeyType(ka, CKK_ML_DSA, "written-by-another-tool")

		assert.Equal(t, "written-by-another-tool", ka.CN)
		assert.Nil(t, ka.QuantumAttributes,
			"an unparsable label must not be reported as a known parameter set")
	})

	t.Run("quantum-key-type-with-an-unknown-parameter-set", func(t *testing.T) {
		ka := &types.KeyAttributes{}
		decodeKeyType(ka, CKK_ML_DSA, "pq.ml-dsa-1024")

		assert.Equal(t, "pq.ml-dsa-1024", ka.CN)
		assert.Nil(t, ka.QuantumAttributes,
			"a parameter set this stack does not implement must not be reported as supported")
	})
}

// TestQuantumKeyID_RoundTripsThroughListKeys proves a post-quantum key
// generated by this backend can be enumerated and then acted on.
//
// It walks the exact path ListKeys does -- the CKA_LABEL written by
// generateQuantumKey, decoded by the same dispatch ListKeys uses, then handed
// back to resolveKeyID -- and requires the CKA_ID to come out identical to the
// one the key was created under. Generation puts the same value in CKA_ID and
// CKA_LABEL precisely so this holds; a label carrying the bare CN would decode
// to a CN that resolves to a different CKA_ID and leave every listed PQC key
// unaddressable.
//
// The token leg is not exercised here because SoftHSM2 rejects CKK_ML_DSA
// objects outright (CKR_ATTRIBUTE_VALUE_INVALID), so no PQC key can be put on
// the test token at all.
func TestQuantumKeyID_RoundTripsThroughListKeys(t *testing.T) {
	b := newProvisionedBackend(t, "quantum-roundtrip")

	algorithms := []types.QuantumAlgorithm{
		types.QuantumAlgorithmMLDSA44,
		types.QuantumAlgorithmMLDSA65,
		types.QuantumAlgorithmMLDSA87,
		types.QuantumAlgorithmMLKEM512,
		types.QuantumAlgorithmMLKEM768,
		types.QuantumAlgorithmMLKEM1024,
	}
	keyTypes := map[types.QuantumAlgorithm]uint{}
	for _, algorithm := range algorithms {
		if algorithm.IsSignature() {
			keyTypes[algorithm] = CKK_ML_DSA
			continue
		}
		keyTypes[algorithm] = CKK_ML_KEM
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			generated := &types.KeyAttributes{
				CN:                "pq-round-trip",
				StoreType:         types.StorePKCS11,
				QuantumAttributes: &types.QuantumAttributes{Algorithm: algorithm},
			}

			// What generateQuantumKey writes to both CKA_ID and CKA_LABEL.
			label := createQuantumKeyID(generated)

			listed := &types.KeyAttributes{StoreType: types.StorePKCS11}
			decodeKeyType(listed, keyTypes[algorithm], label)

			assert.Equal(t, generated.CN, listed.CN, "the enumerated CN must be the CN the key was created with")
			require.NotNil(t, listed.QuantumAttributes)
			assert.Equal(t, algorithm, listed.QuantumAttributes.Algorithm)

			createdID, err := b.resolveKeyID(generated)
			require.NoError(t, err)
			listedID, err := b.resolveKeyID(listed)
			require.NoError(t, err)
			assert.Equal(t, string(createdID), string(listedID),
				"the attributes ListKeys reports must resolve to the CKA_ID the key lives under")
			assert.Equal(t, label, string(listedID))
		})
	}
}

// attributeValue returns the value of the named attribute in a template.
func attributeValue(t *testing.T, template []*pkcs11.Attribute, attributeType uint) []byte {
	t.Helper()

	for _, attr := range template {
		if attr.Type == attributeType {
			return attr.Value
		}
	}
	t.Fatalf("template has no attribute 0x%08x", attributeType)
	return nil
}

// TestQuantumKeyTemplates_LabelMatchesID proves a generated post-quantum key
// carries the same composite identifier in CKA_ID and CKA_LABEL, which is what
// makes TestQuantumKeyID_RoundTripsThroughListKeys hold for a key that is
// actually on a token.
//
// Every other generation path in this backend writes the same value to both;
// the templates are asserted directly because SoftHSM2 rejects CKK_ML_DSA and
// CKK_ML_KEM objects outright (CKR_ATTRIBUTE_VALUE_INVALID), so a post-quantum
// key cannot be generated on the test token to be read back.
func TestQuantumKeyTemplates_LabelMatchesID(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:                "pq-template",
		StoreType:         types.StorePKCS11,
		QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithmMLDSA65},
	}
	id := createQuantumKeyID(attrs)
	require.Equal(t, "pq-template.ml-dsa-65", id)

	public, private := quantumKeyTemplates(CKK_ML_DSA, []byte(id))

	for name, template := range map[string][]*pkcs11.Attribute{"public": public, "private": private} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, id, string(attributeValue(t, template, pkcs11.CKA_ID)))
			assert.Equal(t, id, string(attributeValue(t, template, pkcs11.CKA_LABEL)),
				"CKA_LABEL must carry the same identifier as CKA_ID, or ListKeys cannot report a resolvable CN")
		})
	}

	t.Run("private-key-stays-on-the-token", func(t *testing.T) {
		assert.Equal(t, []byte{1}, attributeValue(t, private, pkcs11.CKA_SENSITIVE),
			"a post-quantum private key must not be readable off the token")
		assert.Equal(t, []byte{1}, attributeValue(t, private, pkcs11.CKA_PRIVATE))
		assert.Equal(t, []byte{1}, attributeValue(t, private, pkcs11.CKA_TOKEN))
	})
}

// TestQuantumKeyIDToCN_Rejected proves the label parser refuses labels it
// cannot account for instead of manufacturing an algorithm from them.
func TestQuantumKeyIDToCN_Rejected(t *testing.T) {
	tests := []string{
		"",
		"no-separator",
		"trailing-dot.",
		"key.rsa",
		"key.ml-dsa-1024",
		"key.ML-DSA-65",
	}

	for _, label := range tests {
		t.Run(label, func(t *testing.T) {
			cn, algorithm, ok := quantumKeyIDToCN(label)
			assert.False(t, ok, "%q is not a quantum key ID this backend wrote", label)
			assert.Empty(t, cn)
			assert.Empty(t, string(algorithm))
		})
	}
}

// TestBackend_ListKeys_Rejected proves ListKeys reports an empty token as an
// empty list and an unauthenticated backend as an error.
func TestBackend_ListKeys_Rejected(t *testing.T) {
	t.Run("empty-token", func(t *testing.T) {
		b := newProvisionedBackend(t, "list-empty")

		listed, err := b.ListKeys(context.Background())
		require.NoError(t, err, "a token with no keys is not an error")
		assert.Empty(t, listed)
	})

	t.Run("not-initialized", func(t *testing.T) {
		b := newProvisionedBackend(t, "list-uninitialized")

		fresh := &Backend{config: b.config}
		listed, err := fresh.ListKeys(context.Background())
		require.ErrorIs(t, err, ErrNotInitialized)
		assert.Nil(t, listed)
	})
}

// TestBackend_findKey_RealToken proves the internal label lookup returns the same key
// the public API does, and reports the two distinct failure modes.
func TestBackend_findKey_RealToken(t *testing.T) {
	b := newProvisionedBackend(t, "find-key")

	attrs := ecdsaKeyAttrs("find-key-target", elliptic.P256())
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	signer, err := b.findKey(attrs)
	require.NoError(t, err)

	reference, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, reference.Public(), signer.Public())

	t.Run("key-not-found", func(t *testing.T) {
		signer, err := b.findKey(ecdsaKeyAttrs("absent", elliptic.P256()))
		require.ErrorIs(t, err, backend.ErrKeyNotFound)
		assert.Nil(t, signer)
	})

	t.Run("not-initialized", func(t *testing.T) {
		fresh := &Backend{config: b.config}
		signer, err := fresh.findKey(attrs)
		require.ErrorIs(t, err, ErrNotInitialized)
		assert.Nil(t, signer)
	})
}

// TestFindKeyPairByID_UnknownKeyType proves a key whose CKA_KEY_TYPE the
// backend does not model is rejected instead of being handed back as an RSA
// or ECDSA signer.
//
// The test creates a real Diffie-Hellman key pair (CKK_DH), which SoftHSM
// supports and this backend deliberately does not. Mis-typing a key here
// would mean signing with the wrong mechanism, so the failure has to be loud.
func TestFindKeyPairByID_UnknownKeyType(t *testing.T) {
	b := newProvisionedBackend(t, "unknown-key-type")

	// RFC 2409 second Oakley group (1024-bit MODP), used only as valid DH
	// domain parameters; nothing is derived from it.
	prime := mustHexBytes(t,
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
			"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
			"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF")

	id := []byte("dh-key-pair")
	publicTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DH),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_PRIME, prime),
		pkcs11.NewAttribute(pkcs11.CKA_BASE, []byte{0x02}),
	}
	privateTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_DH),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	require.NoError(t, b.Pool().WithSession(func(session pkcs11.SessionHandle) error {
		_, _, genErr := b.p11ctx.GenerateKeyPair(
			session,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_DH_PKCS_KEY_PAIR_GEN, nil)},
			publicTemplate,
			privateTemplate,
		)
		return genErr
	}))

	signer, err := findKeyPairByID(b.Pool(), id)
	require.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
	assert.Contains(t, err.Error(), "unknown key type")
	assert.Nil(t, signer, "an unmodelled key type must never yield a signer")
}

// TestFindKeyPairByID_Missing proves a CKA_ID with no objects behind it
// returns no signer and no error, which is how the callers distinguish "not
// present" from "device failure".
func TestFindKeyPairByID_Missing(t *testing.T) {
	b := newProvisionedBackend(t, "find-pair-missing")

	signer, err := findKeyPairByID(b.Pool(), []byte("nothing-here"))
	require.NoError(t, err)
	assert.Nil(t, signer)
}

// TestFindKeyPairByID_DeviceError proves a failing device is reported rather
// than being reduced to "key not found", which would hide an outage behind a
// benign-looking result.
func TestFindKeyPairByID_DeviceError(t *testing.T) {
	b := newProvisionedBackend(t, "find-pair-device-error")

	pool := b.Pool()
	pool.Close()

	signer, err := findKeyPairByID(pool, []byte("any-id"))
	require.ErrorIs(t, err, ErrSessionPoolClosed)
	assert.Nil(t, signer)
}

// TestBackend_ResolveKeyID proves each CKA_ID derivation rule in turn.
//
// The PIV cases are checked against pivpkcs11.PIVSlotToCKAID, the mapping the
// PIV certificate storage uses, so the two layers cannot drift apart and
// address different slots for the same key.
func TestBackend_ResolveKeyID(t *testing.T) {
	generic := &Backend{config: &Config{Library: "/usr/lib/softhsm/libsofthsm2.so"}}

	t.Run("explicit-piv-slot", func(t *testing.T) {
		for _, slot := range []pivcert.PIVSlot{
			pivcert.PIVSlotAuthentication,
			pivcert.PIVSlotDigitalSignature,
			pivcert.PIVSlotKeyManagement,
			pivcert.PIVSlotCardAuthentication,
			pivcert.PIVSlotAttestation,
			pivcert.PIVSlotRetired1,
			pivcert.PIVSlotRetired20,
		} {
			want, ok := pivpkcs11.PIVSlotToCKAID(slot)
			require.True(t, ok, "slot %s must have a CKA_ID mapping", slot)

			attrs := &types.KeyAttributes{CN: "piv", PIVSlot: string(slot)}
			got, err := generic.resolveKeyID(attrs)
			require.NoError(t, err)
			assert.Equal(t, []byte{want}, got, "slot %s", slot)
		}
	})

	t.Run("generic-token", func(t *testing.T) {
		attrs := rsaKeyAttrs("generic-key", 2048)
		got, err := generic.resolveKeyID(attrs)
		require.NoError(t, err)
		assert.Equal(t, []byte("generic-key.rsa"), got)
	})

	t.Run("yubikey-config-slot", func(t *testing.T) {
		slot := 0x9c
		piv := &Backend{config: &Config{Library: "/usr/lib/libykcs11.so", Slot: &slot}}

		got, err := piv.resolveKeyID(rsaKeyAttrs("ignored-cn", 2048))
		require.NoError(t, err)
		assert.Equal(t, []byte{0x02}, got,
			"a YubiKey PIV backend addresses keys by configured slot, not by CN")
	})

	t.Run("invalid-piv-slot", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "piv", PIVSlot: "99"}
		got, err := generic.resolveKeyID(attrs)
		require.ErrorIs(t, err, ErrInvalidKeyAttributes)
		assert.Contains(t, err.Error(), "invalid PIV slot: 99")
		assert.Nil(t, got)
	})
}

// TestCreateSlotID_AgreesWithPIVMapping proves the slot-number to CKA_ID
// translation used for YubiKey PIV agrees with pivpkcs11.PIVSlotToCKAID for
// every slot that mapping defines.
//
// The two tables are consulted by different layers for the same key -- the
// backend from Config.Slot and the PIV certificate storage from the slot
// name -- so any divergence puts a key and its certificate on different
// CKA_IDs.
func TestCreateSlotID_AgreesWithPIVMapping(t *testing.T) {
	slots := map[uint]pivcert.PIVSlot{
		0x9a: pivcert.PIVSlotAuthentication,
		0x9c: pivcert.PIVSlotDigitalSignature,
		0x9d: pivcert.PIVSlotKeyManagement,
		0x9e: pivcert.PIVSlotCardAuthentication,
		0xf9: pivcert.PIVSlotAttestation,
		0x82: pivcert.PIVSlotRetired1,
		0x88: pivcert.PIVSlotRetired7,
		0x95: pivcert.PIVSlotRetired20,
	}

	for number, slot := range slots {
		want, ok := pivpkcs11.PIVSlotToCKAID(slot)
		require.True(t, ok, "slot %s must have a CKA_ID mapping", slot)
		assert.Equal(t, []byte{want}, createSlotID(number),
			"createSlotID(0x%02x) must agree with the PIV slot mapping for %s", number, slot)
	}
}

// TestCreateSlotID_UnknownSlot proves a slot number outside the PIV mapping
// falls back to its raw byte value rather than silently colliding with a
// mapped slot.
func TestCreateSlotID_UnknownSlot(t *testing.T) {
	for _, number := range []uint{0x00, 0x01, 0x7f, 0xab} {
		assert.Equal(t, []byte{byte(number)}, createSlotID(number),
			"unmapped slot 0x%02x keeps its raw value", number)
	}
}

// TestCreateKeyID_InvertedByListKeys proves createKeyID and the CN/algorithm
// pair ListKeys reports are exact inverses, which is what makes an
// enumerated key addressable.
func TestCreateKeyID_InvertedByListKeys(t *testing.T) {
	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		wantKeyID string
	}{
		{"rsa", rsaKeyAttrs("svc", 2048), "svc.rsa"},
		{"ecdsa", ecdsaKeyAttrs("svc", elliptic.P256()), "svc.ecdsa"},
		{"ed25519", ed25519KeyAttrs("svc"), "svc.ed25519"},
		{"unknown-algorithm", &types.KeyAttributes{CN: "svc"}, "svc."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantKeyID, createKeyID(tt.attrs))
		})
	}
}

// TestPkcs11MLDSASigner_SignRejectedByToken proves the post-quantum signer
// reports a mechanism the token does not implement instead of returning an
// empty signature. SoftHSM2 advertises no ML-DSA mechanism, so C_SignInit
// must fail.
func TestPkcs11MLDSASigner_SignRejectedByToken(t *testing.T) {
	b := newProvisionedBackend(t, "mldsa-unsupported")

	signer := &pkcs11MLDSASigner{
		pool:      b.Pool(),
		algorithm: "ML-DSA-65",
		family:    quantumFamilyMLDSA,
	}

	signature, err := signer.Sign(rand.Reader, []byte("message"), crypto.Hash(0))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pkcs11: ML-DSA-65 SignInit")
	assert.Nil(t, signature)
}

// TestBackend_GenerateQuantumKey_Rejected proves quantum key generation is
// refused when the token does not advertise the mechanism, rather than
// attempting a generation the device will mishandle.
func TestBackend_GenerateQuantumKey_Rejected(t *testing.T) {
	b := newProvisionedBackend(t, "quantum-rejected")
	require.False(t, b.supportsMLDSA, "SoftHSM2 advertises no ML-DSA mechanism")
	require.False(t, b.supportsMLKEM, "SoftHSM2 advertises no ML-KEM mechanism")

	tests := []struct {
		name      string
		algorithm string
		detail    string
	}{
		{"ml-dsa", "ML-DSA-65", "token does not support ML-DSA"},
		{"ml-kem", "ML-KEM-768", "token does not support ML-KEM"},
		{"unknown", "FALCON-512", "unsupported quantum algorithm: FALCON-512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:                "quantum-key",
				StoreType:         types.StorePKCS11,
				QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithm(tt.algorithm)},
			}

			key, err := b.GenerateKey(context.Background(), attrs)
			require.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
			assert.Contains(t, err.Error(), tt.detail)
			assert.Nil(t, key)
		})
	}

	t.Run("not-initialized", func(t *testing.T) {
		fresh := &Backend{config: b.config}
		attrs := &types.KeyAttributes{
			CN:                "quantum-key",
			QuantumAttributes: &types.QuantumAttributes{Algorithm: types.QuantumAlgorithm("ML-DSA-65")},
		}
		key, err := fresh.GenerateKey(context.Background(), attrs)
		require.ErrorIs(t, err, ErrNotInitialized)
		assert.Nil(t, key)
	})
}

// pkcs11AESName renders an AES key size for use as a subtest and CN name.
func pkcs11AESName(bits int) string {
	return "aes-" + strconv.Itoa(bits)
}

// keysOf returns the keys of a map for use in failure messages.
func keysOf(m map[string]*types.KeyAttributes) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// mustHexBytes decodes a hex string that is a compile-time constant of the
// test, failing the test if it is malformed.
func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()

	value, ok := new(big.Int).SetString(s, 16)
	require.True(t, ok, "test constant must be valid hex")

	return value.Bytes()
}

// staleSessionBackend returns a Backend whose pool holds a session handle the
// token has already closed, simulating a device that disappeared mid-flight
// (a removed smart card, a restarted HSM daemon).
//
// Every Cryptoki call made with that handle fails with
// CKR_SESSION_HANDLE_INVALID, which is exactly the condition the operations
// must report rather than translate into "key not found".
func staleSessionBackend(t *testing.T, owner *Backend) *Backend {
	t.Helper()

	slot, err := owner.resolveSlot()
	require.NoError(t, err)

	pool, err := NewSessionPool(owner.p11ctx, slot, secretValueString(owner.config.PIN), 1)
	require.NoError(t, err)
	t.Cleanup(func() {
		// The session this helper hands back is deliberately closed out from
		// under the pool by the caller to simulate a vanished token, so
		// Close's drain legitimately fails to close it too. That is the
		// condition under test, not a defect.
		if closeErr := pool.Close(); closeErr != nil {
			t.Logf("pool.Close: %v", closeErr)
		}
	})

	var stale pkcs11.SessionHandle
	require.NoError(t, pool.WithSession(func(session pkcs11.SessionHandle) error {
		stale = session
		return nil
	}))
	require.NoError(t, owner.p11ctx.CloseSession(stale))

	broken := &Backend{config: owner.config}
	broken.SetSessionPool(pool)

	return broken
}

// TestBackend_OperationsSurfaceLostSession proves every token operation
// reports a lost session as a failure.
//
// The assertion that matters is the negative one: none of these may come back
// as backend.ErrKeyNotFound. A caller that sees "key not found" for a key that
// exists will generate a replacement, which on an HSM means the original
// private key is orphaned and everything signed with it becomes unverifiable.
func TestBackend_OperationsSurfaceLostSession(t *testing.T) {
	owner := newProvisionedBackend(t, "lost-session")

	attrs := ecdsaKeyAttrs("lost-session-key", elliptic.P256())
	_, err := owner.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	broken := staleSessionBackend(t, owner)

	digest := sha256.Sum256([]byte("payload"))
	secretAttrs := &types.KeyAttributes{CN: "lost-secret", StoreType: types.StorePKCS11}

	operations := map[string]func() error{
		"GenerateRandom": func() error { _, err := broken.GenerateRandom(16); return err },
		// Get is absent on purpose: it is unsupported for every key and never
		// reaches the token, so it has no session to lose.
		"ListKeys":          func() error { _, err := broken.ListKeys(context.Background()); return err },
		"Signer":            func() error { _, err := broken.Signer(context.Background(), attrs); return err },
		"findKey":           func() error { _, err := broken.findKey(attrs); return err },
		"Verify":            func() error { return broken.Verify(attrs, digest[:], []byte("signature")) },
		"DeleteKey":         func() error { return broken.DeleteKey(context.Background(), attrs) },
		"GenerateRSA":       func() error { _, err := broken.GenerateRSA(rsaKeyAttrs("lost-rsa", 2048)); return err },
		"GenerateECDSA":     func() error { _, err := broken.GenerateECDSA(ecdsaKeyAttrs("lost-ecdsa", elliptic.P256())); return err },
		"GenerateEd25519":   func() error { _, err := broken.GenerateEd25519(ed25519KeyAttrs("lost-ed25519")); return err },
		"GenerateSecretKey": func() error { _, err := broken.GenerateSecretKey(secretAttrs, 256); return err },
		"FindSecretKey":     func() error { _, err := broken.FindSecretKey(secretAttrs); return err },
	}

	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			err := operation()
			require.Error(t, err, "a lost session must not be silently tolerated")
			assert.NotErrorIs(t, err, backend.ErrKeyNotFound,
				"a device failure must never be reported as a missing key")
		})
	}
}

// TestBackend_DeleteKeyInSession_DestroyFailureIsReported proves a
// C_DestroyObject that the token refuses is surfaced, and that the key is
// left intact and usable.
//
// A read-only session is used because it is the simplest way to make a real
// token refuse the destroy (CKR_SESSION_READ_ONLY, PKCS#11 v3.2 section 5.7).
// Reporting success here would tell an operator that a compromised key had
// been destroyed when it is still on the device.
func TestBackend_DeleteKeyInSession_DestroyFailureIsReported(t *testing.T) {
	b := newProvisionedBackend(t, "destroy-refused")
	readOnly := openIntrospectionSession(t, b)

	attrs := ecdsaKeyAttrs("destroy-refused-key", elliptic.P256())
	_, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	err = b.deleteKeyInSession(readOnly, []byte(createKeyID(attrs)), attrs.CN)
	require.Error(t, err)

	var wrapped *errs.Wrapped
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to destroy private key", wrapped.Msg)
	require.ErrorIs(t, err, pkcs11.Error(pkcs11.CKR_SESSION_READ_ONLY))

	signer, err := b.Signer(context.Background(), attrs)
	require.NoError(t, err, "the key must survive a refused deletion")
	assert.NotNil(t, signer.Public())
}

// TestBackend_DeleteKey_SORouteVerifiesUnderUserLogin is a regression test for
// a delete that reported success while the private key was still on the token.
//
// A YubiKey-PIV configuration routes C_DestroyObject through a CKU_SO session.
// A Security Officer session cannot see CKA_PRIVATE objects, so the
// post-destroy check performed inside that session found nothing and read that
// as "the key is gone" -- while the private key was untouched and only the
// public half had been destroyed. Removal is now re-verified under the
// restored CKU_USER login, where private objects are visible.
func TestBackend_DeleteKey_SORouteVerifiesUnderUserLogin(t *testing.T) {
	owner := newProvisionedBackend(t, "so-delete-verify")

	attrs := ecdsaKeyAttrs("so-delete-key", elliptic.P256())
	_, err := owner.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	// A PIV-flavoured configuration sharing the same token: only the library
	// path decides whether the SO route is taken.
	piv := &Backend{config: &Config{
		Library: "/usr/lib/libykcs11.so",
		SOPIN:   owner.config.SOPIN,
		PIN:     owner.config.PIN,
	}}
	piv.SetSessionPool(owner.Pool())
	require.True(t, piv.config.IsYubiKeyPIV())

	err = piv.DeleteKey(context.Background(), attrs)
	require.ErrorIs(t, err, hardware.ErrDeleteNotSupportedOnToken,
		"a private key the token kept must never be reported as deleted")

	// Oracle: ask the token, under a user login, whether the key is still there.
	// The introspection session is opened after the delete because an open
	// read-only session blocks the CKU_SO login the delete needs.
	session := openIntrospectionSession(t, owner)
	assert.Equal(t, 1, countObjects(t, owner, session, pkcs11.CKO_PRIVATE_KEY, []byte(createKeyID(attrs))),
		"the private key is still present, which is why the delete had to fail")
}

// TestBackend_ListKeys_ReportsPIVSlot proves a key stored under a one-byte PIV
// CKA_ID is enumerated with its PIV slot, and that those attributes resolve
// back to the same key.
//
// PIV keys are addressed by slot rather than by name, so an entry without
// PIVSlot would be unusable no matter what CN it carried.
func TestBackend_ListKeys_ReportsPIVSlot(t *testing.T) {
	b := newProvisionedBackend(t, "list-piv-slot")

	attrs := ecdsaKeyAttrs("piv-slot-key", elliptic.P256())
	attrs.PIVSlot = string(pivcert.PIVSlotAuthentication)

	generated, err := b.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	ckaID, err := b.resolveKeyID(attrs)
	require.NoError(t, err)
	require.Len(t, ckaID, 1, "a PIV key is addressed by a single CKA_ID byte")

	listed, err := b.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, listed, 1)

	assert.Equal(t, string(pivcert.PIVSlotAuthentication), listed[0].PIVSlot,
		"CKA_ID 0x%02x must be reported as its PIV slot", ckaID[0])
	assert.Equal(t, x509.ECDSA, listed[0].KeyAlgorithm)

	signer, err := b.Signer(context.Background(), listed[0])
	require.NoError(t, err, "the enumerated PIV attributes must resolve back to the key")
	assert.Equal(t, generated.(crypto.Signer).Public(), signer.Public())
}

// TestBackend_GetDecrypterByID_KeyCannotDecrypt proves a key that exists but
// cannot decrypt is rejected by type rather than reported as missing, so the
// caller learns it picked the wrong key instead of the wrong name.
func TestBackend_GetDecrypterByID_KeyCannotDecrypt(t *testing.T) {
	b := newProvisionedBackend(t, "decrypter-wrong-type")

	// No key algorithm, so the CKA_ID matches what GetDecrypterByID derives.
	attrs := &types.KeyAttributes{
		CN:        "ecdsa-cannot-decrypt",
		KeyType:   backend.KEY_TYPE_ENCRYPTION,
		StoreType: types.StorePKCS11,
	}
	_, err := b.GenerateECDSA(attrs)
	require.NoError(t, err)

	decrypter, err := b.GetDecrypterByID("ecdsa-cannot-decrypt")
	require.ErrorIs(t, err, backend.ErrInvalidKeyType)
	assert.Contains(t, err.Error(), "does not implement crypto.Decrypter")
	assert.Nil(t, decrypter)
}

// TestBackend_GenerateRSAWithSize_DefaultKeySize proves an unspecified RSA
// size falls back to 2048 bits, and that a size below the floor is refused
// rather than silently raised (go-xkms#1204).
func TestBackend_GenerateRSAWithSize_DefaultKeySize(t *testing.T) {
	b := newProvisionedBackend(t, "rsa-default-size")

	t.Run("256 is refused", func(t *testing.T) {
		_, err := b.GenerateRSAWithSize(rsaKeyAttrs("rsa-default-256", 256), 256)
		var sizeErr *types.RSAKeySizeError
		require.ErrorAs(t, err, &sizeErr)
	})

	for _, requested := range []int{0} {
		t.Run(strconv.Itoa(requested), func(t *testing.T) {
			attrs := rsaKeyAttrs("rsa-default-"+strconv.Itoa(requested), requested)

			signer, err := b.GenerateRSAWithSize(attrs, requested)
			require.NoError(t, err)

			pub, ok := signer.Public().(*rsa.PublicKey)
			require.True(t, ok)
			assert.Equal(t, 2048, pub.N.BitLen(),
				"an unusable requested size must fall back to 2048 bits, never below")
		})
	}
}

// TestBackend_GenerateECDSAWithCurve_DefaultCurve proves a nil curve falls
// back to P-256 rather than reaching the token with an empty EC_PARAMS.
func TestBackend_GenerateECDSAWithCurve_DefaultCurve(t *testing.T) {
	b := newProvisionedBackend(t, "ecdsa-default-curve")

	attrs := ecdsaKeyAttrs("ecdsa-default", nil)
	signer, err := b.GenerateECDSAWithCurve(attrs, nil)
	require.NoError(t, err)

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P256().Params().Name, pub.Curve.Params().Name)
}

// TestBackend_Signer_OrphanedPrivateKeyIsRejected proves a private key whose
// public half is missing from the token yields an error, never a signer.
//
// A signer built without its public key would report a nil or zero public key
// while still signing, so a certificate or SSH authorization derived from it
// would be bound to the wrong key. The token itself is the oracle: the public
// object is destroyed directly, then the lookup is attempted.
func TestBackend_Signer_OrphanedPrivateKeyIsRejected(t *testing.T) {
	b := newProvisionedBackend(t, "orphaned-private")

	tests := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{"rsa", rsaKeyAttrs("orphan-rsa", 2048)},
		{"ecdsa", ecdsaKeyAttrs("orphan-ecdsa", elliptic.P256())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := b.GenerateKey(context.Background(), tt.attrs)
			require.NoError(t, err)

			id := []byte(createKeyID(tt.attrs))
			require.NoError(t, b.Pool().WithSession(func(session pkcs11.SessionHandle) error {
				objects, findErr := b.findObjectsByClassAndID(session, pkcs11.CKO_PUBLIC_KEY, id)
				if findErr != nil {
					return findErr
				}
				require.Len(t, objects, 1)
				return b.p11ctx.DestroyObject(session, objects[0])
			}))

			signer, err := b.Signer(context.Background(), tt.attrs)
			require.Error(t, err, "a key with no public half must not produce a signer")
			assert.Nil(t, signer)
		})
	}
}

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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SoftHSM2 2.6.1 implements CKM_RSA_PKCS_OAEP for SHA-1 only and rejects any
// other hash with CKR_ARGUMENTS_BAD, so every test that has to round-trip
// through the token's OAEP implementation uses the SHA-1 wrapping algorithms.
// The SHA-256 algorithms are still exercised wherever the arithmetic happens in
// Go (GetImportParameters, WrapKey), which is where this package owns the code.
const (
	tokenOAEPAlgorithm   = backend.WrappingAlgorithmRSAES_OAEP_SHA_1
	tokenHybridAlgorithm = backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1
)

// offlineBackend returns a Backend that has never been initialized, for
// exercising the guard clauses that must fire before any token is touched.
func offlineBackend() *Backend {
	return &Backend{config: &Config{
		Library:     "/usr/lib/test.so",
		TokenLabel:  "test-token",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}}
}

// aesAttributes describes a 256-bit AES key for the import/export ceremony.
func aesAttributes(cn string, exportable bool) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		KeyType:            backend.KEY_TYPE_ENCRYPTION,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		StoreType:          backend.STORE_PKCS11,
		Exportable:         exportable,
	}
}

// randomAESKey returns 32 bytes of fresh key material.
func randomAESKey(t *testing.T) []byte {
	t.Helper()

	material := make([]byte, 32)
	_, err := rand.Read(material)
	require.NoError(t, err)

	return material
}

// openWritableSession opens a read/write session on the backend's own PKCS#11
// context so a test can create the token objects a scenario needs, and closes
// it when the test ends. openIntrospectionSession is read-only, and
// C_CreateObject on such a session fails with CKR_SESSION_READ_ONLY.
func openWritableSession(t *testing.T, b *Backend) pkcs11.SessionHandle {
	t.Helper()

	require.NotNil(t, b.p11ctx, "a logged-in backend always holds a PKCS#11 context")

	slot, err := b.resolveSlot()
	require.NoError(t, err)

	session, err := b.p11ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.p11ctx.CloseSession(session)) })

	return session
}

// findImportedKey returns the handle of the key object ImportKey created for
// attrs, looked up the way the rest of the backend addresses keys.
func findImportedKey(t *testing.T, b *Backend, session pkcs11.SessionHandle, attrs *types.KeyAttributes) pkcs11.ObjectHandle {
	t.Helper()

	class, err := keyObjectClass(attrs)
	require.NoError(t, err)

	return findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(createKeyID(attrs))),
	})
}

// readBoolAttributes reads the named CK_BBOOL attributes off an object and
// returns their values in request order.
func readBoolAttributes(t *testing.T, b *Backend, session pkcs11.SessionHandle, handle pkcs11.ObjectHandle, attrTypes ...uint) []bool {
	t.Helper()

	template := make([]*pkcs11.Attribute, 0, len(attrTypes))
	for _, attrType := range attrTypes {
		template = append(template, pkcs11.NewAttribute(attrType, nil))
	}

	values, err := b.p11ctx.GetAttributeValue(session, handle, template)
	require.NoError(t, err)
	require.Len(t, values, len(attrTypes))

	flags := make([]bool, 0, len(values))
	for _, value := range values {
		require.NotEmpty(t, value.Value, "a CK_BBOOL attribute always has a value")
		flags = append(flags, value.Value[0] != 0)
	}

	return flags
}

// importAESKey runs the full ceremony — GetImportParameters, WrapKey, ImportKey
// — for a 256-bit AES key and returns the plaintext material the token now
// holds, so a caller can use it as the oracle for whatever comes back out.
func importAESKey(t *testing.T, b *Backend, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) []byte {
	t.Helper()

	ctx := context.Background()

	params, err := b.GetImportParameters(ctx, attrs, algorithm)
	require.NoError(t, err)

	material := randomAESKey(t)

	wrapped, err := b.WrapKey(ctx, material, params)
	require.NoError(t, err)

	require.NoError(t, b.ImportKey(ctx, attrs, wrapped))

	return material
}

// createSecretKeyFixture puts an AES key of known value on the token with the
// exact CKA_SENSITIVE / CKA_EXTRACTABLE combination a test needs, using the
// identifiers the backend addresses keys by.
//
// ImportKey deliberately refuses to create a non-sensitive key, so the tests
// covering plaintext export have to build their precondition directly with
// C_CreateObject.
func createSecretKeyFixture(t *testing.T, b *Backend, attrs *types.KeyAttributes, material []byte, sensitive, extractable bool) {
	t.Helper()

	session := openWritableSession(t, b)
	keyID := []byte(createKeyID(attrs))

	_, err := b.p11ctx.CreateObject(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, material),
	})
	require.NoError(t, err, "the fixture key must be creatable on the token")
}

// decryptInHSM decrypts a blob with the token's wrapping private key using
// RSA-OAEP/SHA-1.
//
// This is the only way to inspect the output of ExportKey: the wrapping key
// pair is generated inside the HSM with CKA_EXTRACTABLE false, so the private
// half can never be handed to crypto/rsa. Decrypting with the same private key
// the export wrapped to, then comparing against material the test chose itself,
// still proves the exported blob carries exactly that key and nothing else.
func decryptInHSM(t *testing.T, b *Backend, blob []byte) []byte {
	t.Helper()

	session := openIntrospectionSession(t, b)

	wrappingPrivate := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(wrappingKeyLabel)),
	})

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(
		pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, pkcs11.CKZ_DATA_SPECIFIED, []byte{}))

	require.NoError(t, b.p11ctx.DecryptInit(session, []*pkcs11.Mechanism{mechanism}, wrappingPrivate))

	plaintext, err := b.p11ctx.Decrypt(session, blob)
	require.NoError(t, err)

	return plaintext
}

// errStorageUnavailable is the failure a failingKeyStorage reports, so a test
// can assert the exact cause survived whatever the backend wrapped it in.
var errStorageUnavailable = errors.New("storage: unavailable")

// failingKeyStorage is a storage.Backend whose Put always fails. It stands in
// for the metadata store being unreachable at the moment an import has already
// unwrapped key material onto the token, which is the window the import's
// rollback exists to close.
type failingKeyStorage struct {
	storage.Backend
}

// Put reports errStorageUnavailable without writing anything.
func (s *failingKeyStorage) Put(ctx context.Context, key string, value []byte) error {
	return errStorageUnavailable
}

// findAllObjects returns every object handle matching the template, running a
// complete find cycle. findSingleObject requires exactly one match; this is for
// the assertions that care about none, or about how many.
func findAllObjects(t *testing.T, b *Backend, session pkcs11.SessionHandle, template []*pkcs11.Attribute) []pkcs11.ObjectHandle {
	t.Helper()

	require.NoError(t, b.p11ctx.FindObjectsInit(session, template))
	defer func() { require.NoError(t, b.p11ctx.FindObjectsFinal(session)) }()

	var all []pkcs11.ObjectHandle
	for {
		handles, _, err := b.p11ctx.FindObjects(session, 16)
		require.NoError(t, err)
		if len(handles) == 0 {
			return all
		}
		all = append(all, handles...)
	}
}

// countSessionSecretKeys reports how many session-only secret key objects the
// token currently holds, which is how a test observes whether the ephemeral
// key-encryption key of a hybrid import was cleaned up.
func countSessionSecretKeys(t *testing.T, b *Backend, session pkcs11.SessionHandle) int {
	t.Helper()

	return len(findAllObjects(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
	}))
}

// wrapUnderKEK produces exactly the blob the second stage of a hybrid import
// consumes: material wrapped under a caller-chosen AES key-encryption key with
// CKM_AES_KEY_WRAP_PAD.
//
// The wrap is done by the token rather than in Go because this package has no
// RFC 5649 implementation to wrap with — pkg/crypto/wrapping exports RFC 3394
// AES-KW only — and because a blob the token produced is the blob the token
// will accept.
func wrapUnderKEK(t *testing.T, b *Backend, session pkcs11.SessionHandle, kek, material []byte) []byte {
	t.Helper()

	kekHandle, err := b.p11ctx.CreateObject(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, kek),
	})
	require.NoError(t, err, "the fixture key-encryption key must be creatable")

	targetHandle, err := b.p11ctx.CreateObject(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, material),
	})
	require.NoError(t, err, "the fixture target key must be creatable")

	blob, err := b.p11ctx.WrapKey(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)},
		kekHandle, targetHandle)
	require.NoError(t, err)

	return blob
}

// assertWiped fails unless every byte of buf is zero.
//
// This is the assertion that distinguishes a real zeroization test from one
// that only checks a return value: it reads the buffer the call was handed,
// after the call, and so fails if the wipe is ever dropped.
func assertWiped(t *testing.T, buf []byte, msg string) {
	t.Helper()

	require.NotEmpty(t, buf, "an empty buffer would make this assertion vacuous")
	assert.Equal(t, make([]byte, len(buf)), buf, msg)
}

// TestGetImportParameters tests retrieving import parameters from the PKCS#11 backend.
func TestGetImportParameters(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-params")

	attrs := &types.KeyAttributes{
		CN:            "test-import-key",
		KeyType:       backend.KEY_TYPE_TLS,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}

	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			params, err := b.GetImportParameters(context.Background(), attrs, algorithm)
			require.NoError(t, err)
			require.NotNil(t, params)

			publicKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
			require.True(t, ok, "the wrapping key of a PKCS#11 import is always RSA")
			assert.Equal(t, wrappingKeySize, publicKey.N.BitLen(),
				"the wrapping key must be the %d-bit key this backend generates", wrappingKeySize)

			assert.Equal(t, []byte(wrappingKeyLabel), params.ImportToken,
				"the import token is the label ImportKey looks the wrapping key up by")
			assert.Equal(t, algorithm, params.Algorithm)
			assert.Equal(t, "RSA_2048", params.KeySpec)

			// A PKCS#11 wrapping key lives in the token indefinitely, so unlike
			// the cloud KMS backends there is no import-token expiry to honour.
			assert.Nil(t, params.ExpiresAt)
		})
	}
}

// TestGetImportParameters_ReturnsTheTokensOwnWrappingKey proves that the public
// key handed to the caller really is the public half of the private key held in
// the token, rather than a detached key pair generated on the side.
//
// The oracle is the token itself: material encrypted under the returned public
// key must decrypt, inside the HSM, with the private key ImportKey later uses
// for C_UnwrapKey. A regression that returned any other public key would leave
// every wrapped blob undecryptable by the token.
func TestGetImportParameters_ReturnsTheTokensOwnWrappingKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-ownkey")

	attrs := aesAttributes("wrapping-key-identity", false)

	params, err := b.GetImportParameters(context.Background(), attrs, tokenOAEPAlgorithm)
	require.NoError(t, err)

	publicKey, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	require.True(t, ok)

	probe := randomAESKey(t)

	// Encrypt under the published public key, using the same OAEP parameters
	// the import path uses, then let the token decrypt it.
	offline := offlineBackend()
	wrapped, err := offline.WrapKey(context.Background(), probe, &backend.ImportParameters{
		WrappingPublicKey: publicKey,
		Algorithm:         tokenOAEPAlgorithm,
		ImportToken:       params.ImportToken,
	})
	require.NoError(t, err)

	assert.Equal(t, probe, decryptInHSM(t, b, wrapped.WrappedKey),
		"the returned public key must be the public half of the token's wrapping key")
}

// TestGetImportParameters_ReusesTheStoredWrappingKey verifies that repeated
// calls hand back one persistent token key rather than minting a fresh pair
// each time.
//
// A wrapping key that changed between the call that published the public key
// and the call that performs the unwrap would make every import fail, and would
// litter the token with orphaned 4096-bit key pairs.
func TestGetImportParameters_ReusesTheStoredWrappingKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-reuse")
	ctx := context.Background()

	attrs := aesAttributes("wrapping-key-reuse", false)

	first, err := b.GetImportParameters(ctx, attrs, tokenOAEPAlgorithm)
	require.NoError(t, err)
	second, err := b.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	require.NoError(t, err)

	firstKey, ok := first.WrappingPublicKey.(*rsa.PublicKey)
	require.True(t, ok)
	secondKey, ok := second.WrappingPublicKey.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Zero(t, firstKey.N.Cmp(secondKey.N), "both calls must return the same token wrapping key")

	// And exactly one private half exists on the token afterwards.
	session := openIntrospectionSession(t, b)
	require.NoError(t, b.p11ctx.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(wrappingKeyLabel)),
	}))
	handles, _, err := b.p11ctx.FindObjects(session, 8)
	require.NoError(t, err)
	require.NoError(t, b.p11ctx.FindObjectsFinal(session))
	assert.Len(t, handles, 1, "two calls must not leave two wrapping keys behind")
}

// TestGetImportParameters_InvalidInput asserts the specific error for each way
// the call can be malformed.
func TestGetImportParameters_InvalidInput(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-params-bad")
	ctx := context.Background()

	attrs := aesAttributes("bad-input", false)

	t.Run("uninitialized backend", func(t *testing.T) {
		_, err := offlineBackend().GetImportParameters(ctx, attrs, tokenOAEPAlgorithm)
		assert.ErrorIs(t, err, ErrNotInitialized)
	})

	t.Run("nil attributes", func(t *testing.T) {
		_, err := b.GetImportParameters(ctx, nil, tokenOAEPAlgorithm)
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := b.GetImportParameters(ctx, attrs, backend.WrappingAlgorithm("AES_GCM"))
		assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
	})

	t.Run("empty algorithm", func(t *testing.T) {
		_, err := b.GetImportParameters(ctx, attrs, backend.WrappingAlgorithm(""))
		assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
	})
}

// TestWrapKey tests wrapping key material for import.
//
// The oracle for the direct-OAEP algorithms is crypto/rsa: the blob must
// decrypt, with a private key this package never saw, to exactly the bytes that
// went in. Asserting only that WrapKey returned a non-empty slice would pass
// for a blob of the wrong key, or of noise.
func TestWrapKey(t *testing.T) {
	b := offlineBackend()

	wrappingKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	material := randomAESKey(t)

	wrapped, err := b.WrapKey(context.Background(), material, &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		ImportToken:       []byte(wrappingKeyLabel),
	})
	require.NoError(t, err)

	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, wrapped.Algorithm)
	assert.Equal(t, []byte(wrappingKeyLabel), wrapped.ImportToken,
		"the import token must survive wrapping; ImportKey finds the unwrapping key by it")
	assert.NotNil(t, wrapped.Metadata)

	recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrappingKey, wrapped.WrappedKey, nil)
	require.NoError(t, err, "the wrapped blob must be RSA-OAEP under the supplied public key")
	assert.Equal(t, material, recovered, "unwrapping must yield the original key material byte for byte")
}

// TestWrapKey_HybridCarriesAnEphemeralAESKey checks the framing of the hybrid
// blob that importKeyHybrid has to parse: a 4-byte big-endian length, the
// RSA-OAEP-wrapped ephemeral AES key, then the AES-KWP-wrapped material.
//
// crypto/rsa is the oracle for the first half — it must recover a 256-bit AES
// key. The second half is proven end to end by the token in
// TestImportKey_RoundTripsAESMaterial, whose AES-KWP implementation is
// independent of this codebase.
func TestWrapKey_HybridCarriesAnEphemeralAESKey(t *testing.T) {
	b := offlineBackend()

	wrappingKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	material := randomAESKey(t)

	wrapped, err := b.WrapKey(context.Background(), material, &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
		ImportToken:       []byte(wrappingKeyLabel),
	})
	require.NoError(t, err)

	require.Greater(t, len(wrapped.WrappedKey), 4)
	wrappedAESKeyLen := int(wrapped.WrappedKey[0])<<24 | int(wrapped.WrappedKey[1])<<16 |
		int(wrapped.WrappedKey[2])<<8 | int(wrapped.WrappedKey[3])

	assert.Equal(t, wrappingKey.Size(), wrappedAESKeyLen,
		"the RSA-OAEP section is exactly one modulus wide")
	require.Greater(t, len(wrapped.WrappedKey), 4+wrappedAESKeyLen,
		"the blob must carry AES-wrapped material after the wrapped AES key")

	ephemeral, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, wrappingKey,
		wrapped.WrappedKey[4:4+wrappedAESKeyLen], nil)
	require.NoError(t, err)
	assert.Len(t, ephemeral, 32, "the hybrid scheme wraps under a 256-bit ephemeral AES key")

	assert.NotContains(t, string(wrapped.WrappedKey), string(material),
		"wrapped output must never contain the plaintext key material")
}

// TestWrapKey_InvalidInput asserts the specific error for each malformed
// wrapping request.
func TestWrapKey_InvalidInput(t *testing.T) {
	b := offlineBackend()
	ctx := context.Background()

	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	validParams := &backend.ImportParameters{
		WrappingPublicKey: &wrappingKey.PublicKey,
		Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	}

	t.Run("nil key material", func(t *testing.T) {
		_, err := b.WrapKey(ctx, nil, validParams)
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("empty key material", func(t *testing.T) {
		_, err := b.WrapKey(ctx, []byte{}, validParams)
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("nil parameters", func(t *testing.T) {
		_, err := b.WrapKey(ctx, randomAESKey(t), nil)
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("non-RSA wrapping key", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		_, err = b.WrapKey(ctx, randomAESKey(t), &backend.ImportParameters{
			WrappingPublicKey: &ecKey.PublicKey,
			Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		})
		assert.ErrorIs(t, err, backend.ErrInvalidKeyType)
	})

	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := b.WrapKey(ctx, randomAESKey(t), &backend.ImportParameters{
			WrappingPublicKey: &wrappingKey.PublicKey,
			Algorithm:         backend.WrappingAlgorithm("AES_GCM"),
		})
		assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
	})

	t.Run("material larger than the modulus", func(t *testing.T) {
		// RSA-OAEP cannot carry more than k - 2*hLen - 2 bytes; the failure
		// must surface rather than produce a truncated blob.
		_, err := b.WrapKey(ctx, make([]byte, 4096), validParams)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to wrap key material")
	})
}

// TestUnwrapKey tests that UnwrapKey returns ErrNotSupported.
//
// Unwrapping for a PKCS#11 backend happens inside the token during ImportKey. A
// host-side implementation would have to hold the wrapping private key in
// process memory, which is exactly what an HSM exists to prevent.
func TestUnwrapKey(t *testing.T) {
	b := offlineBackend()

	_, err := b.UnwrapKey(context.Background(),
		&backend.WrappedKeyMaterial{
			WrappedKey: []byte("test"),
			Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		},
		&backend.ImportParameters{Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256})

	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

// TestUnwrapKey_NilArgumentsStillRefuse checks that the refusal does not depend
// on the arguments: no input may coax host-side unwrapping out of this backend.
func TestUnwrapKey_NilArgumentsStillRefuse(t *testing.T) {
	b := offlineBackend()

	_, err := b.UnwrapKey(context.Background(), nil, nil)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

// TestImportKey tests importing wrapped keys into the HSM.
func TestImportKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-import")

	attrs := aesAttributes("imported-test-key", false)
	importAESKey(t, b, attrs, tokenHybridAlgorithm)

	// The imported object must be addressable by the identifiers the rest of
	// the backend uses; an object the API cannot find again is not an import.
	session := openIntrospectionSession(t, b)
	handle := findImportedKey(t, b, session, attrs)

	label, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	})
	require.NoError(t, err)
	assert.Equal(t, createKeyID(attrs), string(label[0].Value),
		"an imported key is labelled the way GenerateSymmetricKey and ExportKeyMaterial address keys")
}

// TestImportKey_RoundTripsAESMaterial proves that C_UnwrapKey produced the
// caller's key and not merely some key.
//
// The oracle is crypto/cipher: the token encrypts a message under the key it
// unwrapped, and Go opens the AES-GCM ciphertext using the original 32 bytes.
// GCM authenticates, so a single wrong bit in the imported key makes Open fail.
func TestImportKey_RoundTripsAESMaterial(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-roundtrip-material")

	attrs := aesAttributes("roundtrip-aes-key", false)
	material := importAESKey(t, b, attrs, tokenHybridAlgorithm)

	assertTokenHoldsKey(t, b, attrs, material)
}

// TestImportKey_DirectOAEPRoundTripsAESMaterial covers the non-hybrid unwrap
// branch, where the token runs C_UnwrapKey with CKM_RSA_PKCS_OAEP directly on
// the wrapped material.
func TestImportKey_DirectOAEPRoundTripsAESMaterial(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-direct-oaep")

	attrs := aesAttributes("direct-oaep-key", false)
	material := importAESKey(t, b, attrs, tokenOAEPAlgorithm)

	assertTokenHoldsKey(t, b, attrs, material)
}

// assertTokenHoldsKey checks that the AES key the token holds under attrs is
// bit-for-bit the supplied material, by having the token encrypt and Go
// authenticate-and-decrypt with the material itself.
func assertTokenHoldsKey(t *testing.T, b *Backend, attrs *types.KeyAttributes, material []byte) {
	t.Helper()

	encrypter, err := b.SymmetricEncrypter(context.Background(), attrs)
	require.NoError(t, err, "an imported key must be reachable through the backend's own API")

	plaintext := []byte("the token holds the caller's key, not a key")
	encrypted, err := encrypter.Encrypt(plaintext, nil)
	require.NoError(t, err)

	block, err := aes.NewCipher(material)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	sealed := make([]byte, 0, len(encrypted.Ciphertext)+len(encrypted.Tag))
	sealed = append(sealed, encrypted.Ciphertext...)
	sealed = append(sealed, encrypted.Tag...)

	opened, err := gcm.Open(nil, encrypted.Nonce, sealed, nil)
	require.NoError(t, err, "AES-GCM must authenticate under the original key material")
	assert.Equal(t, plaintext, opened)
}

// TestImportKey_ExportablePolicyReachesTheToken is the regression test for an
// attribute that was accepted at the API and silently dropped: attrs.Exportable
// never reached the C_UnwrapKey template, so every imported key came back with
// whatever CKA_EXTRACTABLE the token happened to default to.
//
// PKCS#11 3.2 §5.18.4 makes that default CK_TRUE, and the §4.9 Common Secret
// Key Attributes table defaults CKA_SENSITIVE to CK_FALSE, so leaving the flags
// out means an imported key's protection level is decided by the token rather
// than by the caller.
func TestImportKey_ExportablePolicyReachesTheToken(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-exportable-flag")

	cases := []struct {
		name       string
		exportable bool
	}{
		{name: "exportable key may be wrapped out", exportable: true},
		{name: "sealed key may never leave", exportable: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := aesAttributes("exportable-"+tc.name, tc.exportable)
			importAESKey(t, b, attrs, tokenHybridAlgorithm)

			session := openIntrospectionSession(t, b)
			handle := findImportedKey(t, b, session, attrs)

			flags := readBoolAttributes(t, b, session, handle,
				pkcs11.CKA_SENSITIVE, pkcs11.CKA_EXTRACTABLE)

			assert.True(t, flags[0],
				"CKA_SENSITIVE is unconditional: an imported key never reveals plaintext")
			assert.Equal(t, tc.exportable, flags[1],
				"CKA_EXTRACTABLE must carry the caller's Exportable policy")
		})
	}
}

// TestImportKey_SealedKeyRefusesPlaintextExtraction asserts the negative
// security property directly against the token.
//
// The footnote to the PKCS#11 3.2 §4.9 attribute tables governs it: a key whose
// CKA_SENSITIVE is CK_TRUE, or whose CKA_EXTRACTABLE is CK_FALSE, must not have
// its value revealed in plaintext outside the token. An imported key satisfies
// both conditions, so reading CKA_VALUE has to fail — "the attribute happened to
// come back empty" is not good enough.
func TestImportKey_SealedKeyRefusesPlaintextExtraction(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-sealed")

	attrs := aesAttributes("sealed-aes-key", false)
	material := importAESKey(t, b, attrs, tokenHybridAlgorithm)

	session := openIntrospectionSession(t, b)
	handle := findImportedKey(t, b, session, attrs)

	values, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	require.Error(t, err, "a sensitive key must refuse CKA_VALUE, not return it")
	assert.Equal(t, pkcs11.Error(pkcs11.CKR_ATTRIBUTE_SENSITIVE), err)
	for _, value := range values {
		assert.NotEqual(t, material, value.Value, "the key material must never come back")
	}

	// The backend's own plaintext-export entry point must refuse it too.
	_, err = b.ExportKeyMaterial(context.Background(), attrs)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable)
}

// TestImportKey_RSAPrivateKeyIsTheSameKey imports a PKCS#8 RSA private key and
// proves cryptographically that the token holds that exact key.
//
// The oracle is a signature: the token signs with the key it unwrapped, and
// crypto/rsa verifies the signature against the public half of the key the test
// generated. Only the matching private key can produce a signature that
// verifies, so this catches an import that silently produced a different key.
func TestImportKey_RSAPrivateKeyIsTheSameKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-rsa-private")
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "imported-rsa-key",
		KeyType:       backend.KEY_TYPE_TLS,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		StoreType:     backend.STORE_PKCS11,
	}

	original, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(original)
	require.NoError(t, err)

	params, err := b.GetImportParameters(ctx, attrs, tokenHybridAlgorithm)
	require.NoError(t, err)
	wrapped, err := b.WrapKey(ctx, pkcs8, params)
	require.NoError(t, err)
	require.NoError(t, b.ImportKey(ctx, attrs, wrapped))

	session := openIntrospectionSession(t, b)
	handle := findImportedKey(t, b, session, attrs)

	modulus, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
	})
	require.NoError(t, err)
	assert.Zero(t, new(big.Int).SetBytes(modulus[0].Value).Cmp(original.PublicKey.N),
		"the imported private key must carry the original modulus")

	flags := readBoolAttributes(t, b, session, handle, pkcs11.CKA_SENSITIVE, pkcs11.CKA_EXTRACTABLE)
	assert.True(t, flags[0], "an imported private key is always sensitive")
	assert.False(t, flags[1], "attrs.Exportable was false, so the key must be sealed in the token")

	message := []byte("signed by the imported private key")
	require.NoError(t, b.p11ctx.SignInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, handle))
	signature, err := b.p11ctx.Sign(session, message)
	require.NoError(t, err)

	digest := sha256.Sum256(message)
	assert.NoError(t, rsa.VerifyPKCS1v15(&original.PublicKey, crypto.SHA256, digest[:], signature),
		"the token's signature must verify under the original public key")
}

// TestImportKey_ECDSAPrivateKeyIsTheSameKey is the ECDSA counterpart, covering
// the CKK_ECDSA branch of buildImportKeyTemplate.
//
// PKCS#11 returns an ECDSA signature as the raw r||s pair rather than the ASN.1
// SEQUENCE crypto/ecdsa produces, so the halves are split before verifying
// against the original public key.
func TestImportKey_ECDSAPrivateKeyIsTheSameKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-ec-private")
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "imported-ec-key",
		KeyType:       backend.KEY_TYPE_TLS,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		StoreType:     backend.STORE_PKCS11,
	}

	original, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(original)
	require.NoError(t, err)

	params, err := b.GetImportParameters(ctx, attrs, tokenHybridAlgorithm)
	require.NoError(t, err)
	wrapped, err := b.WrapKey(ctx, pkcs8, params)
	require.NoError(t, err)
	require.NoError(t, b.ImportKey(ctx, attrs, wrapped))

	session := openIntrospectionSession(t, b)
	handle := findImportedKey(t, b, session, attrs)

	flags := readBoolAttributes(t, b, session, handle, pkcs11.CKA_SENSITIVE, pkcs11.CKA_EXTRACTABLE)
	assert.True(t, flags[0], "an imported private key is always sensitive")
	assert.False(t, flags[1], "attrs.Exportable was false, so the key must be sealed in the token")

	digest := sha256.Sum256([]byte("signed by the imported EC key"))
	require.NoError(t, b.p11ctx.SignInit(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, handle))
	signature, err := b.p11ctx.Sign(session, digest[:])
	require.NoError(t, err)
	require.Len(t, signature, 64, "a P-256 CKM_ECDSA signature is r||s over 32-byte halves")

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	assert.True(t, ecdsa.Verify(&original.PublicKey, digest[:], r, s),
		"the token's signature must verify under the original public key")
}

// TestImportExport_AuthenticateAndReleaseTheToken checks the session hygiene of
// the two operations that open their own PKCS#11 session.
//
// Both log in with C_Login when the token is not already authenticated, and
// both must log out again on the way out. A leaked authenticated session is a
// privilege that outlives the operation: C_Login state is shared by every
// session an application holds on that token (PKCS#11 3.2 §5.6.1), so failing
// to release it leaves the whole process authenticated to the HSM.
func TestImportExport_AuthenticateAndReleaseTheToken(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-login-cycle")
	ctx := context.Background()

	attrs := aesAttributes("login-cycle-key", true)

	params, err := b.GetImportParameters(ctx, attrs, tokenHybridAlgorithm)
	require.NoError(t, err)
	material := randomAESKey(t)
	wrapped, err := b.WrapKey(ctx, material, params)
	require.NoError(t, err)

	// Drop the application's authenticated state so ImportKey has to establish
	// it itself. C_Logout applies to every session on the token.
	session := openWritableSession(t, b)
	require.NoError(t, b.p11ctx.Logout(session))

	require.NoError(t, b.ImportKey(ctx, attrs, wrapped),
		"ImportKey must authenticate to the token on its own")

	exported, err := b.ExportKey(ctx, attrs, tokenOAEPAlgorithm)
	require.NoError(t, err, "ExportKey must authenticate to the token on its own")

	// A successful C_Login here proves neither operation left the application
	// authenticated; a leaked session would answer CKR_USER_ALREADY_LOGGED_IN.
	require.NoError(t, b.p11ctx.Login(session, pkcs11.CKU_USER, b.config.PIN),
		"import and export must log out again when they are done")

	assert.Equal(t, material, decryptInHSM(t, b, exported.WrappedKey))
}

// TestImportKey_InvalidInput asserts the specific error for each way an import
// can be malformed, including blobs a hostile caller could supply.
func TestImportKey_InvalidInput(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-import-bad")
	ctx := context.Background()

	attrs := aesAttributes("bad-import", false)

	params, err := b.GetImportParameters(ctx, attrs, tokenHybridAlgorithm)
	require.NoError(t, err)
	valid, err := b.WrapKey(ctx, randomAESKey(t), params)
	require.NoError(t, err)

	t.Run("uninitialized backend", func(t *testing.T) {
		assert.ErrorIs(t, offlineBackend().ImportKey(ctx, attrs, valid), ErrNotInitialized)
	})

	t.Run("nil attributes", func(t *testing.T) {
		assert.ErrorIs(t, b.ImportKey(ctx, nil, valid), backend.ErrInvalidAttributes)
	})

	t.Run("nil wrapped material", func(t *testing.T) {
		assert.ErrorIs(t, b.ImportKey(ctx, attrs, nil), backend.ErrInvalidAttributes)
	})

	t.Run("unknown key algorithm", func(t *testing.T) {
		unknown := &types.KeyAttributes{
			CN:                 "unknown-algorithm",
			KeyType:            backend.KEY_TYPE_ENCRYPTION,
			SymmetricAlgorithm: types.SymmetricAlgorithm("chacha20-poly1305"),
		}
		assert.ErrorIs(t, b.ImportKey(ctx, unknown, valid), backend.ErrInvalidAlgorithm)
	})

	t.Run("unsupported wrapping algorithm", func(t *testing.T) {
		err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
			WrappedKey:  valid.WrappedKey,
			Algorithm:   backend.WrappingAlgorithm("AES_GCM"),
			ImportToken: valid.ImportToken,
		})
		assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
	})

	// The import token selects the private key the unwrap runs under, so an
	// unrecognized one is refused outright rather than looked up on the token.
	t.Run("unknown import token", func(t *testing.T) {
		err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
			WrappedKey:  valid.WrappedKey,
			Algorithm:   valid.Algorithm,
			ImportToken: []byte("no-such-wrapping-key"),
		})
		assert.ErrorIs(t, err, ErrImportTokenMismatch)
	})

	t.Run("absent import token", func(t *testing.T) {
		err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
			WrappedKey: valid.WrappedKey,
			Algorithm:  valid.Algorithm,
		})
		assert.ErrorIs(t, err, ErrImportTokenMismatch)
	})

	// The rejection must not repeat the caller's bytes back into the error,
	// which is where they would reach an operator's logs verbatim.
	t.Run("rejection does not echo the supplied token", func(t *testing.T) {
		err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
			WrappedKey:  valid.WrappedKey,
			Algorithm:   valid.Algorithm,
			ImportToken: []byte("injected\nlog line"),
		})
		require.ErrorIs(t, err, ErrImportTokenMismatch)
		assert.NotContains(t, err.Error(), "injected")
	})

	t.Run("truncated hybrid blob", func(t *testing.T) {
		err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
			WrappedKey:  []byte{0x00, 0x01},
			Algorithm:   valid.Algorithm,
			ImportToken: valid.ImportToken,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped key too short for hybrid format")
	})

	t.Run("hybrid blob claiming more data than it carries", func(t *testing.T) {
		err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
			WrappedKey:  []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00},
			Algorithm:   valid.Algorithm,
			ImportToken: valid.ImportToken,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped key corrupted: insufficient data")
	})

	t.Run("tampered RSA-OAEP section", func(t *testing.T) {
		// Flipping a bit in the OAEP section must be caught by OAEP's own
		// integrity check rather than importing an attacker-influenced key.
		tampered := append([]byte{}, valid.WrappedKey...)
		tampered[10] ^= 0xFF

		err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
			WrappedKey:  tampered,
			Algorithm:   valid.Algorithm,
			ImportToken: valid.ImportToken,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt AES key")
	})

	t.Run("tampered AES-KWP section", func(t *testing.T) {
		// AES-KWP carries an integrity check value, so corrupting the key
		// material must fail the unwrap instead of yielding a mangled key.
		tampered := append([]byte{}, valid.WrappedKey...)
		tampered[len(tampered)-1] ^= 0xFF

		err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
			WrappedKey:  tampered,
			Algorithm:   valid.Algorithm,
			ImportToken: valid.ImportToken,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unwrap target key with AES-KWP")
	})

	// A blob of zeroes is not a valid OAEP ciphertext under either hash, so
	// C_UnwrapKey must reject it rather than derive a key from padding noise.
	for _, algorithm := range []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	} {
		t.Run("direct OAEP blob that is not OAEP: "+string(algorithm), func(t *testing.T) {
			err := b.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{
				WrappedKey:  make([]byte, wrappingKeySize/8),
				Algorithm:   algorithm,
				ImportToken: valid.ImportToken,
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to unwrap key with RSA-OAEP")
		})
	}

	t.Run("PKCS#11 library that cannot be loaded", func(t *testing.T) {
		// A backend whose session pool exists but whose low-level context has
		// not been built yet must report the load failure, not dereference nil.
		broken := offlineBackend()
		broken.pool = &SessionPool{}
		broken.config.Library = "/nonexistent/libsofthsm2.so"

		err := broken.ImportKey(ctx, attrs, valid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load PKCS#11 library")
	})
}

// TestImportKeyHybrid_MalformedBlob exercises importKeyHybrid's own framing
// guards without going through a token, including the algorithm switch that
// selects the OAEP hash.
func TestImportKeyHybrid_MalformedBlob(t *testing.T) {
	b := offlineBackend()
	attrs := aesAttributes("hybrid-guards", false)

	cases := []struct {
		name      string
		wrapped   *backend.WrappedKeyMaterial
		wantError string
	}{
		{
			name:      "empty blob",
			wrapped:   &backend.WrappedKeyMaterial{Algorithm: tokenHybridAlgorithm},
			wantError: "wrapped key too short for hybrid format",
		},
		{
			name:      "length prefix only",
			wrapped:   &backend.WrappedKeyMaterial{WrappedKey: []byte{0, 0, 0, 9}, Algorithm: tokenHybridAlgorithm},
			wantError: "wrapped key corrupted: insufficient data",
		},
		{
			name: "algorithm the hybrid path does not implement",
			wrapped: &backend.WrappedKeyMaterial{
				WrappedKey: []byte{0, 0, 0, 1, 0xAA},
				Algorithm:  backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
			},
			wantError: backend.ErrInvalidAlgorithm.Error(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.importKeyHybrid(0, attrs, tc.wrapped, 0, nil, nil, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantError)
		})
	}

	// A length prefix of 0xFFFFFFFF used to wrap around when the bounds check
	// computed 4+length in uint32, letting the slice expression below it panic
	// on caller-supplied bytes. The check must reject the blob instead.
	t.Run("length prefix that overflows a uint32 bounds check", func(t *testing.T) {
		for _, prefix := range [][]byte{
			{0xFF, 0xFF, 0xFF, 0xFF, 0x00},
			{0xFF, 0xFF, 0xFF, 0xFD, 0x00, 0x00, 0x00},
			{0x00, 0x00, 0x00, 0x00},
		} {
			_, err := b.importKeyHybrid(0, attrs,
				&backend.WrappedKeyMaterial{WrappedKey: prefix, Algorithm: tokenHybridAlgorithm},
				0, nil, nil, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "wrapped key corrupted: insufficient data")
		}
	})
}

// TestImportKeyHybrid_SelectsTheOAEPHash covers the hash selection for both
// hybrid algorithms. The unwrapping key handle is invalid, so the call fails at
// C_DecryptInit — which is exactly the point: the algorithm must be resolved
// and the failure reported, never assumed.
func TestImportKeyHybrid_SelectsTheOAEPHash(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-hybrid-hash")
	attrs := aesAttributes("hybrid-hash", false)

	session := openIntrospectionSession(t, b)

	for _, algorithm := range []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	} {
		t.Run(string(algorithm), func(t *testing.T) {
			_, err := b.importKeyHybrid(session, attrs, &backend.WrappedKeyMaterial{
				WrappedKey: []byte{0, 0, 0, 2, 0xAA, 0xBB, 0xCC},
				Algorithm:  algorithm,
			}, pkcs11.ObjectHandle(0), nil, nil, nil)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to init decrypt for AES key")
		})
	}
}

// TestUnwrapWithEphemeralKEK_WipesTheHostSideKEK proves the plaintext
// key-encryption key does not survive a successful hybrid unwrap in host
// memory.
//
// The KEK is the only plaintext key material the whole ceremony puts outside
// the token, and it is the key that protects the material being imported, so a
// copy left for the garbage collector is readable until collection and can
// reach swap or a core dump. The assertion reads the caller's buffer after the
// call rather than checking the returned error, which is the only way to see a
// missing wipe.
func TestUnwrapWithEphemeralKEK_WipesTheHostSideKEK(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-kek-wipe")
	session := openWritableSession(t, b)

	attrs := aesAttributes("kek-wipe", false)
	kek := randomAESKey(t)
	blob := wrapUnderKEK(t, b, session, kek, randomAESKey(t))

	keyID := []byte(createKeyID(attrs))
	template, err := b.buildImportKeyTemplate(attrs, keyID, keyID)
	require.NoError(t, err)

	owned := append([]byte(nil), kek...)
	require.NotEqual(t, make([]byte, len(owned)), owned,
		"the buffer under test must start out non-zero, or the assertion below proves nothing")

	handle, err := b.unwrapWithEphemeralKEK(session, owned, blob, template)
	require.NoError(t, err)
	require.NotZero(t, handle, "the target key must actually have been unwrapped")

	assertWiped(t, owned, "the plaintext key-encryption key must not survive the call in host memory")
}

// TestUnwrapWithEphemeralKEK_WipesTheKEKOnEveryFailurePath covers the paths
// where the wipe is normally forgotten. Each subtest drives a different stage
// of the unwrap into failure and then reads the caller's buffer.
func TestUnwrapWithEphemeralKEK_WipesTheKEKOnEveryFailurePath(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-kek-wipe-fail")
	session := openWritableSession(t, b)

	attrs := aesAttributes("kek-wipe-fail", false)
	kek := randomAESKey(t)
	blob := wrapUnderKEK(t, b, session, kek, randomAESKey(t))

	keyID := []byte(createKeyID(attrs))
	template, err := b.buildImportKeyTemplate(attrs, keyID, keyID)
	require.NoError(t, err)

	// The token rejects the key-encryption key object itself, so the failure
	// happens before the unwrap is ever reached.
	t.Run("token refuses the key-encryption key object", func(t *testing.T) {
		owned := []byte{1, 2, 3, 4, 5, 6, 7}

		_, err := b.unwrapWithEphemeralKEK(session, owned, blob, template)
		require.Error(t, err, "seven bytes is not a valid AES key length")
		assertWiped(t, owned, "a key-encryption key the token refused must still be wiped")
	})

	// The object is created and the unwrap fails, which is the path that runs
	// through the deferred cleanup rather than a straight-line return.
	t.Run("unwrap of a corrupted blob", func(t *testing.T) {
		corrupted := append([]byte(nil), blob...)
		corrupted[len(corrupted)-1] ^= 0xFF

		owned := append([]byte(nil), kek...)

		_, err := b.unwrapWithEphemeralKEK(session, owned, corrupted, template)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unwrap target key with AES-KWP")
		assertWiped(t, owned, "a key-encryption key must be wiped when the unwrap fails")
	})

	t.Run("key-encryption key that does not match the blob", func(t *testing.T) {
		owned := randomAESKey(t)

		_, err := b.unwrapWithEphemeralKEK(session, owned, blob, template)
		require.Error(t, err, "AES-KWP carries an integrity check, so the wrong KEK must fail")
		assertWiped(t, owned, "the wrong key-encryption key is still key material and must be wiped")
	})

	t.Run("target template the token will not accept", func(t *testing.T) {
		owned := append([]byte(nil), kek...)

		_, err := b.unwrapWithEphemeralKEK(session, owned, blob, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		})
		require.Error(t, err)
		assertWiped(t, owned, "a rejected target template must not strand the key-encryption key")
	})
}

// TestUnwrapWithEphemeralKEK_LeavesNoKeyEncryptionKeyOnTheToken proves the
// temporary token object is destroyed on the success path and on the failure
// path alike, so a hybrid import never accumulates key-encryption keys on a
// long-lived session.
func TestUnwrapWithEphemeralKEK_LeavesNoKeyEncryptionKeyOnTheToken(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-kek-cleanup")
	session := openWritableSession(t, b)

	attrs := aesAttributes("kek-cleanup", false)
	kek := randomAESKey(t)
	blob := wrapUnderKEK(t, b, session, kek, randomAESKey(t))

	keyID := []byte(createKeyID(attrs))
	template, err := b.buildImportKeyTemplate(attrs, keyID, keyID)
	require.NoError(t, err)

	// Measured after the fixtures exist, so only objects the call itself
	// creates can move the count.
	before := countSessionSecretKeys(t, b, session)

	_, err = b.unwrapWithEphemeralKEK(session, append([]byte(nil), kek...), blob, template)
	require.NoError(t, err)
	assert.Equal(t, before, countSessionSecretKeys(t, b, session),
		"the temporary key-encryption key must not outlive a successful unwrap")

	_, err = b.unwrapWithEphemeralKEK(session, randomAESKey(t), blob, template)
	require.Error(t, err)
	assert.Equal(t, before, countSessionSecretKeys(t, b, session),
		"the temporary key-encryption key must not outlive a failed unwrap either")
}

// TestEphemeralKEKTemplate_SealsTheKeyEncryptionKey pins the protection
// attributes of the temporary key-encryption key.
//
// PKCS#11 3.2 §4.9 Table 30: CKA_EXTRACTABLE means the key may be WRAPPED, not
// that its plaintext may be read; CKA_SENSITIVE is the attribute that stops the
// value being disclosed. The KEK needs neither capability, and the defaults for
// a key created by C_CreateObject run the wrong way on both counts —
// CKA_SENSITIVE defaults to CK_FALSE and CKA_EXTRACTABLE to CK_TRUE — so both
// must appear explicitly in the template.
func TestEphemeralKEKTemplate_SealsTheKeyEncryptionKey(t *testing.T) {
	kek := randomAESKey(t)
	expected := append([]byte(nil), kek...)

	values := make(map[uint][]byte)
	for _, attr := range ephemeralKEKTemplate(kek) {
		values[attr.Type] = attr.Value
	}

	assert.Equal(t, []byte{1}, values[pkcs11.CKA_SENSITIVE],
		"the key-encryption key must never be readable in plaintext")
	assert.Equal(t, []byte{0}, values[pkcs11.CKA_EXTRACTABLE],
		"the key-encryption key must not even be exportable in wrapped form")
	assert.Equal(t, []byte{0}, values[pkcs11.CKA_TOKEN],
		"the key-encryption key must be session-only so it cannot outlive the import")
	assert.Equal(t, []byte{1}, values[pkcs11.CKA_UNWRAP])
	assert.Equal(t, expected, values[pkcs11.CKA_VALUE])

	// The object exists to run one unwrap. Any further usage flag would widen
	// what a caller who reached the handle could do with it.
	assert.NotContains(t, values, uint(pkcs11.CKA_WRAP))
	assert.NotContains(t, values, uint(pkcs11.CKA_DECRYPT))
	assert.NotContains(t, values, uint(pkcs11.CKA_ENCRYPT))
}

// TestEphemeralKEKTemplate_TokenRefusesToDiscloseTheValue is the same claim
// checked against a real token rather than against the template: an object
// created from this template will not hand its value back.
func TestEphemeralKEKTemplate_TokenRefusesToDiscloseTheValue(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-kek-sealed")
	session := openWritableSession(t, b)

	handle, err := b.p11ctx.CreateObject(session, ephemeralKEKTemplate(randomAESKey(t)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.p11ctx.DestroyObject(session, handle)) })

	_, err = b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	require.Error(t, err, "a token honouring CKA_SENSITIVE must refuse to disclose the value")

	flags := readBoolAttributes(t, b, session, handle, pkcs11.CKA_SENSITIVE, pkcs11.CKA_EXTRACTABLE)
	assert.True(t, flags[0], "CKA_SENSITIVE must have reached the token")
	assert.False(t, flags[1], "CKA_EXTRACTABLE must have reached the token")
}

// TestImportKey_RefusesAnImportTokenNamingAnotherKey is the security case
// behind pinning the import token.
//
// The import token selects the private key that C_Decrypt and C_UnwrapKey run
// under, and it arrives from the caller — the REST and gRPC handlers pass
// ImportKeyRequest.ImportToken straight through. Left unchecked it lets a
// caller aim an RSA-OAEP decryption of ciphertext they chose at any private
// key on the token that permits decryption, and read the outcome off which
// stage of the import failed. The imported RSA key used here is such a key:
// buildImportKeyTemplate gives every imported RSA private key CKA_DECRYPT.
func TestImportKey_RefusesAnImportTokenNamingAnotherKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-token-pin")
	ctx := context.Background()

	victim := &types.KeyAttributes{
		CN:            "unrelated-rsa-key",
		KeyType:       backend.KEY_TYPE_TLS,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		StoreType:     backend.STORE_PKCS11,
	}

	original, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(original)
	require.NoError(t, err)

	params, err := b.GetImportParameters(ctx, victim, tokenHybridAlgorithm)
	require.NoError(t, err)
	victimWrapped, err := b.WrapKey(ctx, pkcs8, params)
	require.NoError(t, err)
	require.NoError(t, b.ImportKey(ctx, victim, victimWrapped))

	attrs := aesAttributes("aimed-at-another-key", false)
	wrapped, err := b.WrapKey(ctx, randomAESKey(t), params)
	require.NoError(t, err)

	// Aim the ceremony at the unrelated RSA key by name.
	wrapped.ImportToken = []byte(createKeyID(victim))

	err = b.ImportKey(ctx, attrs, wrapped)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrImportTokenMismatch)

	// The rejection must happen before the token is asked to decrypt anything.
	// A "failed to decrypt AES key" here would mean C_Decrypt had already run
	// under the unrelated key and the caller could tell success from failure.
	assert.NotContains(t, err.Error(), "failed to decrypt AES key")

	session := openIntrospectionSession(t, b)
	assert.NotZero(t, findImportedKey(t, b, session, victim),
		"a refused import must leave the key it was aimed at untouched")
}

// TestImportKey_RollsBackWhenMetadataCannotBeStored proves ImportKey is
// all-or-nothing past the unwrap.
//
// The unwrap has already succeeded by the time the metadata write is attempted,
// so without a rollback a storage failure would return an error while leaving
// key material on the token: unreachable through the metadata index the rest of
// the backend consults, and duplicated under the same CKA_ID by the caller's
// retry. PKCS#11 3.2 §5.1 requires a call to accomplish "either its entire
// goal, or nothing at all".
func TestImportKey_RollsBackWhenMetadataCannotBeStored(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-rollback")
	ctx := context.Background()

	attrs := aesAttributes("rollback-secret", false)

	params, err := b.GetImportParameters(ctx, attrs, tokenHybridAlgorithm)
	require.NoError(t, err)
	wrapped, err := b.WrapKey(ctx, randomAESKey(t), params)
	require.NoError(t, err)

	b.config.KeyStorage = &failingKeyStorage{Backend: storage.New()}

	err = b.ImportKey(ctx, attrs, wrapped)
	require.Error(t, err)
	assert.ErrorIs(t, err, errStorageUnavailable, "the underlying cause must survive")

	session := openIntrospectionSession(t, b)
	handles := findAllObjects(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(createKeyID(attrs))),
	})
	assert.Empty(t, handles, "a failed import must leave no key material on the token")
}

// TestImportKey_KeepsTheKeyWhenTheImportSucceeds is the counterpart to the
// rollback test: the rollback must be disarmed on success, or a working import
// would delete the key it just created.
func TestImportKey_KeepsTheKeyWhenTheImportSucceeds(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-rollback-commit")

	attrs := aesAttributes("committed-secret", false)
	importAESKey(t, b, attrs, tokenHybridAlgorithm)

	session := openIntrospectionSession(t, b)
	handles := findAllObjects(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(createKeyID(attrs))),
	})
	assert.Len(t, handles, 1, "a successful import leaves exactly one key object")
}

// TestExportKey tests exporting keys from the HSM.
func TestExportKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-export")

	attrs := &types.KeyAttributes{
		CN:            "non-extractable-key",
		KeyType:       backend.KEY_TYPE_TLS,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}

	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	// A key the caller never marked exportable is refused by policy, before the
	// token is consulted at all.
	_, err = b.ExportKey(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable)
}

// TestExportKey_RefusesAKeyTheTokenSealed is the defence-in-depth half: even
// when the caller's policy says the key may be exported, a key generated with
// CKA_EXTRACTABLE false must still be refused.
//
// PKCS#11 3.2 §5.18.3 makes this the token's rule — C_WrapKey answers
// CKR_KEY_UNEXTRACTABLE — and the backend must not paper over it.
func TestExportKey_RefusesAKeyTheTokenSealed(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-export-sealed")

	attrs := &types.KeyAttributes{
		CN:            "sealed-rsa-key",
		KeyType:       backend.KEY_TYPE_TLS,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}

	_, err := b.GenerateRSA(attrs)
	require.NoError(t, err)

	attrs.Exportable = true
	_, err = b.ExportKey(context.Background(), attrs, tokenOAEPAlgorithm)
	assert.ErrorIs(t, err, backend.ErrKeyNotExportable,
		"policy alone must not override CKA_EXTRACTABLE on the token")
}

// TestExportKey_WrappedBlobCarriesTheOriginalKey proves the export actually
// exports the key.
//
// The oracle: the blob is decrypted inside the HSM with the wrapping private
// key and compared against the material the test imported. A test that only
// checked "ExportKey returned no error and some bytes" would pass for a blob
// containing the wrong key.
//
// This is also the regression test for an export path that could never run. The
// wrapping-key lookup used to start a second C_FindObjectsInit while the first
// search was still open, which PKCS#11 3.2 §5.7.7 forbids — "at most one search
// operation may be active at a given time in a given session" — so every call
// failed with CKR_OPERATION_ACTIVE.
func TestExportKey_WrappedBlobCarriesTheOriginalKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-export-roundtrip")

	attrs := aesAttributes("exportable-aes-key", true)
	material := importAESKey(t, b, attrs, tokenHybridAlgorithm)

	exported, err := b.ExportKey(context.Background(), attrs, tokenOAEPAlgorithm)
	require.NoError(t, err)
	require.NotNil(t, exported)

	assert.Equal(t, tokenOAEPAlgorithm, exported.Algorithm)
	assert.Equal(t, []byte(wrappingKeyLabel), exported.ImportToken)
	assert.NotEqual(t, material, exported.WrappedKey, "the export must be wrapped, not plaintext")

	assert.Equal(t, material, decryptInHSM(t, b, exported.WrappedKey),
		"the exported blob must unwrap to the exact key material that was imported")
}

// TestExportKey_InvalidInput asserts the specific error for each malformed
// export request.
func TestExportKey_InvalidInput(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-export-bad")
	ctx := context.Background()

	t.Run("nil attributes", func(t *testing.T) {
		_, err := b.ExportKey(ctx, nil, tokenOAEPAlgorithm)
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("uninitialized backend", func(t *testing.T) {
		_, err := offlineBackend().ExportKey(ctx, aesAttributes("offline", true), tokenOAEPAlgorithm)
		assert.ErrorIs(t, err, ErrNotInitialized)
	})

	t.Run("unsupported key algorithm", func(t *testing.T) {
		_, err := b.ExportKey(ctx, &types.KeyAttributes{
			CN:                 "unsupported",
			SymmetricAlgorithm: types.SymmetricAlgorithm("chacha20-poly1305"),
			Exportable:         true,
		}, tokenOAEPAlgorithm)
		assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
	})

	t.Run("key not on the token", func(t *testing.T) {
		_, err := b.ExportKey(ctx, aesAttributes("never-created", true), tokenOAEPAlgorithm)
		assert.ErrorIs(t, err, backend.ErrKeyNotFound)
	})

	t.Run("unsupported wrapping algorithm", func(t *testing.T) {
		attrs := aesAttributes("export-bad-algorithm", true)
		importAESKey(t, b, attrs, tokenHybridAlgorithm)

		_, err := b.ExportKey(ctx, attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
		assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
	})

	t.Run("PKCS#11 library that cannot be loaded", func(t *testing.T) {
		broken := offlineBackend()
		broken.pool = &SessionPool{}
		broken.config.Library = "/nonexistent/libsofthsm2.so"

		_, err := broken.ExportKey(ctx, aesAttributes("broken-library", true), tokenOAEPAlgorithm)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load PKCS#11 library")
	})
}

// TestExportKey_WithoutAWrappingKey covers the branch where the token holds the
// key to export but no wrapping key has ever been created, so there is nothing
// to wrap it to.
func TestExportKey_WithoutAWrappingKey(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-no-wrapping-key")

	attrs := aesAttributes("orphan-export", true)
	createSecretKeyFixture(t, b, attrs, randomAESKey(t), false, true)

	_, err := b.ExportKey(context.Background(), attrs, tokenOAEPAlgorithm)
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrKeyNotFound)
	assert.Contains(t, err.Error(), "wrapping key not found in HSM")
}

// TestImportExportRoundTrip tests a complete import/export round trip.
//
// The key material is generated in the test, wrapped, imported into the token,
// exported back out in wrapped form, and finally recovered inside the HSM. The
// bytes at the end must equal the bytes at the start.
func TestImportExportRoundTrip(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-roundtrip")

	attrs := aesAttributes("roundtrip-exportable-key", true)
	material := importAESKey(t, b, attrs, tokenHybridAlgorithm)

	exported, err := b.ExportKey(context.Background(), attrs, tokenOAEPAlgorithm)
	require.NoError(t, err)

	assert.Equal(t, material, decryptInHSM(t, b, exported.WrappedKey))
}

// TestExportKeyMaterial_ReturnsTheExactMaterial covers the plaintext export
// path for a secret key the token is willing to reveal.
//
// The oracle is the fixture: the key was created with a value the test chose,
// so ExportKeyMaterial must return exactly those bytes.
func TestExportKeyMaterial_ReturnsTheExactMaterial(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-material")

	attrs := aesAttributes("extractable-secret", true)
	material := randomAESKey(t)
	createSecretKeyFixture(t, b, attrs, material, false, true)

	exported, err := b.ExportKeyMaterial(context.Background(), attrs)
	require.NoError(t, err)
	assert.Equal(t, material, exported)
}

// TestExportKeyMaterial_RefusesProtectedKeys asserts the rule from the footnote
// to the PKCS#11 3.2 §4.9 attribute tables: a key value must not be revealed in
// plaintext when CKA_SENSITIVE is CK_TRUE **or** CKA_EXTRACTABLE is CK_FALSE.
// Either flag alone is enough to refuse.
func TestExportKeyMaterial_RefusesProtectedKeys(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-material-refused")
	ctx := context.Background()

	cases := []struct {
		name        string
		sensitive   bool
		extractable bool
	}{
		{name: "sensitive but extractable", sensitive: true, extractable: true},
		{name: "not sensitive but unextractable", sensitive: false, extractable: false},
		{name: "sensitive and unextractable", sensitive: true, extractable: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := aesAttributes("protected-"+tc.name, true)
			material := randomAESKey(t)
			createSecretKeyFixture(t, b, attrs, material, tc.sensitive, tc.extractable)

			exported, err := b.ExportKeyMaterial(ctx, attrs)
			assert.ErrorIs(t, err, backend.ErrKeyNotExportable)
			assert.NotEqual(t, material, exported, "no protected key material may be returned")
		})
	}
}

// TestExportKeyMaterial_InvalidInput asserts the specific error for each way
// the plaintext export can be refused.
func TestExportKeyMaterial_InvalidInput(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-material-bad")
	ctx := context.Background()

	t.Run("uninitialized backend", func(t *testing.T) {
		_, err := offlineBackend().ExportKeyMaterial(ctx, aesAttributes("offline", true))
		assert.ErrorIs(t, err, ErrNotInitialized)
	})

	t.Run("nil attributes", func(t *testing.T) {
		_, err := b.ExportKeyMaterial(ctx, nil)
		assert.ErrorIs(t, err, backend.ErrInvalidAttributes)
	})

	t.Run("key not on the token", func(t *testing.T) {
		_, err := b.ExportKeyMaterial(ctx, aesAttributes("absent-secret", true))
		assert.ErrorIs(t, err, backend.ErrKeyNotFound)
	})

	t.Run("without a PKCS#11 context", func(t *testing.T) {
		offline := offlineBackend()
		offline.pool = &SessionPool{}

		_, err := offline.ExportKeyMaterial(ctx, aesAttributes("no-context", true))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PKCS#11 context not initialized")
	})

	// Raw export of an asymmetric private key is never allowed, whatever the
	// token would permit: the wrapped ExportKey path exists for that.
	for _, algorithm := range []x509.PublicKeyAlgorithm{x509.RSA, x509.ECDSA, x509.Ed25519, x509.DSA} {
		t.Run("asymmetric "+algorithm.String(), func(t *testing.T) {
			_, err := b.ExportKeyMaterial(ctx, &types.KeyAttributes{
				CN:           "asymmetric-key",
				KeyAlgorithm: algorithm,
				Exportable:   true,
			})
			assert.ErrorIs(t, err, backend.ErrAsymmetricKeyExportNotAllowed)
		})
	}
}

// TestFindOneObject covers the search helper that keeps consecutive lookups on
// one session legal.
func TestFindOneObject(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-findone")

	attrs := aesAttributes("findone-secret", true)
	createSecretKeyFixture(t, b, attrs, randomAESKey(t), false, true)

	session := openIntrospectionSession(t, b)
	keyID := []byte(createKeyID(attrs))

	t.Run("finds a matching object", func(t *testing.T) {
		handle, err := b.findOneObject(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		})
		require.NoError(t, err)
		assert.NotEqual(t, pkcs11.ObjectHandle(0), handle)
	})

	t.Run("reports CK_INVALID_HANDLE when nothing matches", func(t *testing.T) {
		handle, err := b.findOneObject(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("no-such-object")),
		})
		require.NoError(t, err, "an empty result is not an error")
		assert.Equal(t, pkcs11.ObjectHandle(0), handle)
	})

	// Regression for CKR_OPERATION_ACTIVE: PKCS#11 3.2 §5.7.7 allows at most
	// one active search per session, so a helper that leaves C_FindObjectsFinal
	// undone poisons every later search on the same session.
	t.Run("consecutive searches on one session", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			_, err := b.findOneObject(session, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
				pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
			})
			require.NoError(t, err, "search %d must not fail with CKR_OPERATION_ACTIVE", i)
		}
	})

	t.Run("invalid session handle", func(t *testing.T) {
		_, err := b.findOneObject(pkcs11.SessionHandle(0), []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to init object search")
	})
}

// TestVerifyImportedKeyIdentity covers the post-unwrap check that an imported
// key really carries the CKA_LABEL and CKA_ID the backend addresses it by.
func TestVerifyImportedKeyIdentity(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-identity")

	attrs := aesAttributes("identity-secret", true)
	createSecretKeyFixture(t, b, attrs, randomAESKey(t), false, true)

	session := openWritableSession(t, b)
	keyID := []byte(createKeyID(attrs))

	handle, err := b.findOneObject(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
	})
	require.NoError(t, err)

	t.Run("accepts an object that already carries its identity", func(t *testing.T) {
		assert.NoError(t, b.verifyImportedKeyIdentity(session, handle, keyID, keyID))
	})

	t.Run("repairs an object whose identity differs", func(t *testing.T) {
		renamed := []byte("renamed-identity")
		require.NoError(t, b.verifyImportedKeyIdentity(session, handle, renamed, renamed))

		found, err := b.findOneObject(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, renamed),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, renamed),
		})
		require.NoError(t, err)
		assert.Equal(t, handle, found, "the object must now answer to the new identity")
	})

	t.Run("reports an object it cannot address", func(t *testing.T) {
		err := b.verifyImportedKeyIdentity(session, pkcs11.ObjectHandle(0), keyID, keyID)
		assert.ErrorIs(t, err, ErrImportedKeyUnaddressable)
	})
}

// TestKeyObjectClass covers the mapping from key attributes to PKCS#11 object
// class that import and export must agree on.
func TestKeyObjectClass(t *testing.T) {
	cases := []struct {
		name      string
		attrs     *types.KeyAttributes
		wantClass uint
		wantError bool
	}{
		{
			name:      "RSA is a private key object",
			attrs:     &types.KeyAttributes{KeyAlgorithm: x509.RSA},
			wantClass: pkcs11.CKO_PRIVATE_KEY,
		},
		{
			name:      "ECDSA is a private key object",
			attrs:     &types.KeyAttributes{KeyAlgorithm: x509.ECDSA},
			wantClass: pkcs11.CKO_PRIVATE_KEY,
		},
		{
			name:      "AES-128 is a secret key object",
			attrs:     &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES128GCM},
			wantClass: pkcs11.CKO_SECRET_KEY,
		},
		{
			name:      "AES-192 is a secret key object",
			attrs:     &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES192GCM},
			wantClass: pkcs11.CKO_SECRET_KEY,
		},
		{
			name:      "AES-256 is a secret key object",
			attrs:     &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM},
			wantClass: pkcs11.CKO_SECRET_KEY,
		},
		{
			name:      "Ed25519 has no import representation",
			attrs:     &types.KeyAttributes{KeyAlgorithm: x509.Ed25519},
			wantError: true,
		},
		{
			name:      "an unknown symmetric algorithm is refused",
			attrs:     &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAlgorithm("chacha20-poly1305")},
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			class, err := keyObjectClass(tc.attrs)
			if tc.wantError {
				assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantClass, class)
		})
	}
}

// TestBuildImportKeyTemplate asserts that the C_UnwrapKey template always pins
// both protection flags rather than inheriting the token's defaults, which
// PKCS#11 3.2 §5.18.4 and §4.9 make permissive.
func TestBuildImportKeyTemplate(t *testing.T) {
	b := offlineBackend()
	keyID := []byte("template-key-id")

	// attributeValue returns the raw value of one attribute type in a template.
	attributeValue := func(template []*pkcs11.Attribute, attrType uint) ([]byte, bool) {
		for _, attribute := range template {
			if attribute.Type == attrType {
				return attribute.Value, true
			}
		}
		return nil, false
	}

	cases := []struct {
		name  string
		attrs *types.KeyAttributes
	}{
		{name: "RSA", attrs: &types.KeyAttributes{CN: "t", KeyAlgorithm: x509.RSA}},
		{name: "ECDSA", attrs: &types.KeyAttributes{CN: "t", KeyAlgorithm: x509.ECDSA}},
		{name: "AES", attrs: &types.KeyAttributes{CN: "t", SymmetricAlgorithm: types.SymmetricAES256GCM}},
	}

	for _, tc := range cases {
		for _, exportable := range []bool{false, true} {
			name := tc.name + " sealed"
			if exportable {
				name = tc.name + " exportable"
			}

			t.Run(name, func(t *testing.T) {
				tc.attrs.Exportable = exportable

				template, err := b.buildImportKeyTemplate(tc.attrs, keyID, keyID)
				require.NoError(t, err)

				sensitive, ok := attributeValue(template, pkcs11.CKA_SENSITIVE)
				require.True(t, ok, "CKA_SENSITIVE must never be left to the token")
				assert.Equal(t, []byte{1}, sensitive)

				extractable, ok := attributeValue(template, pkcs11.CKA_EXTRACTABLE)
				require.True(t, ok, "CKA_EXTRACTABLE must never be left to the token")
				if exportable {
					assert.Equal(t, []byte{1}, extractable)
				} else {
					assert.Equal(t, []byte{0}, extractable)
				}

				label, ok := attributeValue(template, pkcs11.CKA_LABEL)
				require.True(t, ok)
				assert.Equal(t, keyID, label)

				id, ok := attributeValue(template, pkcs11.CKA_ID)
				require.True(t, ok)
				assert.Equal(t, keyID, id)

				token, ok := attributeValue(template, pkcs11.CKA_TOKEN)
				require.True(t, ok, "an imported key is stored in the token, not the session")
				assert.Equal(t, []byte{1}, token)
			})
		}
	}

	t.Run("unsupported algorithm", func(t *testing.T) {
		_, err := b.buildImportKeyTemplate(&types.KeyAttributes{
			CN:                 "t",
			SymmetricAlgorithm: types.SymmetricAlgorithm("chacha20-poly1305"),
		}, keyID, keyID)
		assert.ErrorIs(t, err, backend.ErrInvalidAlgorithm)
	})
}

// TestDetermineKeySpec covers the key-spec string published in the import
// parameters, which tells the caller how to size the material it will wrap.
func TestDetermineKeySpec(t *testing.T) {
	cases := []struct {
		name  string
		attrs *types.KeyAttributes
		want  string
	}{
		{
			name:  "RSA with an explicit size",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{KeySize: 4096}},
			want:  "RSA_4096",
		},
		{
			name:  "RSA without attributes falls back to the default size",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.RSA},
			want:  "RSA_2048",
		},
		{
			name:  "RSA with a zero size falls back to the default size",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.RSA, RSAAttributes: &types.RSAAttributes{}},
			want:  "RSA_2048",
		},
		{
			name:  "ECDSA names the curve",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()}},
			want:  "EC_P-384",
		},
		{
			name:  "ECDSA without attributes falls back to P-256",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA},
			want:  "EC_P256",
		},
		{
			name:  "ECDSA with a nil curve falls back to P-256",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA, ECCAttributes: &types.ECCAttributes{}},
			want:  "EC_P256",
		},
		{
			name:  "AES-128",
			attrs: &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES128GCM},
			want:  "AES_128",
		},
		{
			name:  "AES-192",
			attrs: &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES192GCM},
			want:  "AES_192",
		},
		{
			name:  "AES-256",
			attrs: &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM},
			want:  "AES_256",
		},
		{
			name:  "anything else is unknown",
			attrs: &types.KeyAttributes{KeyAlgorithm: x509.Ed25519},
			want:  "UNKNOWN",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, determineKeySpec(tc.attrs))
		})
	}
}

// TestCapabilities verifies that ImportExport capability is enabled.
func TestCapabilities(t *testing.T) {
	caps := offlineBackend().Capabilities()

	assert.True(t, caps.Import, "Import capability should be true")
	assert.True(t, caps.Export, "Export capability should be true")
	assert.True(t, caps.SupportsImportExport(), "SupportsImportExport() should return true")
}

// Helper function to get SoftHSM library path
func getSoftHSMLibrary(t *testing.T) string {
	// Try common SoftHSM2 library paths
	paths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so", // macOS with Homebrew
		"/usr/lib64/pkcs11/libsofthsm2.so",         // RHEL/CentOS
	}

	for _, path := range paths {
		if fileExists(path) {
			return path
		}
	}

	return ""
}

// Helper function to check if file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestGenerateWrappingKeyPairAttributes verifies that the wrapping key pair
// is generated with the correct CKA_WRAP and CKA_UNWRAP attributes.
func TestGenerateWrappingKeyPairAttributes(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-wrapattrs")

	keyID := []byte("test-wrapping-key-attrs")
	signer, err := b.generateWrappingKeyPair(keyID)
	require.NoError(t, err)
	require.NotNil(t, signer)

	publicKey, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok, "the wrapping key pair is RSA")
	assert.Equal(t, wrappingKeySize, publicKey.N.BitLen())

	session := openIntrospectionSession(t, b)

	privKeyHandle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	})

	flags := readBoolAttributes(t, b, session, privKeyHandle,
		pkcs11.CKA_UNWRAP, pkcs11.CKA_DECRYPT, pkcs11.CKA_SIGN,
		pkcs11.CKA_SENSITIVE, pkcs11.CKA_EXTRACTABLE)

	assert.True(t, flags[0], "CKA_UNWRAP must be true: C_UnwrapKey requires it (PKCS#11 3.2 §5.18.4)")
	assert.True(t, flags[1], "CKA_DECRYPT must be true: the hybrid import decrypts the ephemeral AES key with it")
	assert.True(t, flags[2], "CKA_SIGN should be true")
	assert.True(t, flags[3], "CKA_SENSITIVE must be true")
	assert.False(t, flags[4], "CKA_EXTRACTABLE must be false: the wrapping key may never leave the token")
}

// TestGenerateWrappingKeyPairPublicKeyAttributes verifies that the public key
// also has the CKA_WRAP attribute set for wrapping operations.
func TestGenerateWrappingKeyPairPublicKeyAttributes(t *testing.T) {
	b := newProvisionedBackend(t, "importexport-pubattrs")

	keyID := []byte("test-wrapping-key-pub-attrs")
	_, err := b.generateWrappingKeyPair(keyID)
	require.NoError(t, err)

	session := openIntrospectionSession(t, b)

	pubKeyHandle := findSingleObject(t, b, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyID),
	})

	flags := readBoolAttributes(t, b, session, pubKeyHandle,
		pkcs11.CKA_WRAP, pkcs11.CKA_ENCRYPT, pkcs11.CKA_VERIFY)

	assert.True(t, flags[0], "CKA_WRAP must be true: C_WrapKey requires it (PKCS#11 3.2 §5.18.3)")
	assert.True(t, flags[1], "CKA_ENCRYPT should be true for the public key")
	assert.True(t, flags[2], "CKA_VERIFY should be true for the public key")
}

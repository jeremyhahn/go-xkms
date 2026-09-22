package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveBackend_EmptyNameReturnsDefault(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	b, err := svc.resolveBackend("")
	require.NoError(t, err)
	assert.NotNil(t, b)
}

func TestResolveBackend_ValidName(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	b, err := svc.resolveBackend("pkcs11")
	require.NoError(t, err)
	assert.NotNil(t, b)
}

func TestResolveBackend_InvalidName(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.resolveBackend("nonexistent")
	require.Error(t, err)
}

func TestResolveBackendWithName_EmptyDefault(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	b, name, err := svc.resolveBackendWithName("")
	require.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, "software", name)
}

func TestResolveBackendWithName_SpecificBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	b, name, err := svc.resolveBackendWithName("pkcs11")
	require.NoError(t, err)
	assert.NotNil(t, b)
	assert.Equal(t, "pkcs11", name)
}

func TestFindKeyAttrs_Found(t *testing.T) {
	software, _ := setupService(t)

	// Generate a key to populate the mock
	_, err := software.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:           "find-me",
		KeyAlgorithm: x509.ECDSA,
	})
	require.NoError(t, err)

	attrs, err := findKeyAttrs(context.Background(), software, "find-me")
	require.NoError(t, err)
	assert.Equal(t, "find-me", attrs.CN)
}

func TestFindKeyAttrs_NotFound(t *testing.T) {
	software, _ := setupService(t)

	_, err := findKeyAttrs(context.Background(), software, "does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAlgorithmString_SymmetricAlgorithm(t *testing.T) {
	attrs := &types.KeyAttributes{
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	result := algorithmString(attrs)
	assert.Equal(t, string(types.SymmetricAES256GCM), result)
}

func TestAlgorithmString_AsymmetricAlgorithm(t *testing.T) {
	attrs := &types.KeyAttributes{
		KeyAlgorithm: x509.ECDSA,
	}
	result := algorithmString(attrs)
	assert.Equal(t, "ECDSA", result)
}

func TestAlgorithmString_Unknown(t *testing.T) {
	attrs := &types.KeyAttributes{}
	result := algorithmString(attrs)
	assert.Equal(t, "", result)
}

func TestResolveHash_EmptyDefaultsToSHA256(t *testing.T) {
	h, err := ResolveHash("")
	require.NoError(t, err)
	assert.Equal(t, crypto.SHA256, h)
}

func TestResolveHash_NamedHashes(t *testing.T) {
	// Spelling is normalized: case, "-" and "_" are all equivalent.
	for _, name := range []string{"SHA-256", "sha256", "SHA_256"} {
		h, err := ResolveHash(name)
		require.NoError(t, err, name)
		assert.Equal(t, crypto.SHA256, h, name)
	}
	for _, name := range []string{"SHA-512", "SHA512", "sha512"} {
		h, err := ResolveHash(name)
		require.NoError(t, err, name)
		assert.Equal(t, crypto.SHA512, h, name)
	}
	h, err := ResolveHash("SHA384")
	require.NoError(t, err)
	assert.Equal(t, crypto.SHA384, h)
}

// A name the caller did supply but that does not resolve must be an error, not
// a substitution. Silently signing with SHA-256 when the caller asked for
// something else reports success for an operation that never happened.
func TestResolveHash_NamedButUnresolvableIsAnError(t *testing.T) {
	for _, name := range []string{"INVALID-HASH", "SHA-999", "MD5", "SHA-1", "MD4", "RIPEMD-160"} {
		h, err := ResolveHash(name)
		require.Error(t, err, name)
		assert.ErrorIs(t, err, ErrInvalidHashFunction, name)
		assert.Equal(t, crypto.Hash(0), h, name)
	}
}

// The weak-hash escape hatch has to reach this layer too, otherwise an
// operator who accepted the compliance gap still cannot do the legacy interop
// it was granted for.
func TestResolveHash_WeakHashesUnderPolicy(t *testing.T) {
	types.SetAllowWeakHashes(true)
	defer types.SetAllowWeakHashes(false)

	h, err := ResolveHash("SHA-1")
	require.NoError(t, err)
	assert.Equal(t, crypto.SHA1, h)
}

func TestPubKeyPEM_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemStr, err := pubKeyPEM(key)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")
	assert.Contains(t, pemStr, "END PUBLIC KEY")
}

func TestPubKeyPEM_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pemStr, err := pubKeyPEM(key)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")
}

func TestPubKeyPEM_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemStr, err := pubKeyPEM(priv)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")
	assert.Contains(t, pemStr, "END PUBLIC KEY")
}

// wrappedSigner implements crypto.Signer but is not any of the concrete
// key types (rsa, ecdsa, ed25519) so it exercises the crypto.Signer
// fallback branch in pubKeyPEM.
type wrappedSigner struct {
	signer crypto.Signer
}

var _ crypto.Signer = (*wrappedSigner)(nil)

func (w *wrappedSigner) Public() crypto.PublicKey {
	return w.signer.Public()
}

func (w *wrappedSigner) Sign(rng io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return w.signer.Sign(rng, digest, opts)
}

func TestPubKeyPEM_CryptoSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ws := &wrappedSigner{signer: key}
	pemStr, err := pubKeyPEM(ws)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")
}

func TestPubKeyPEM_Nil(t *testing.T) {
	_, err := pubKeyPEM(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil private key")
}

func TestPubKeyPEM_UnsupportedType(t *testing.T) {
	// An int is not a valid private key type
	_, err := pubKeyPEM(42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported private key type")
}

func TestDefaultBackendName(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	name := svc.defaultBackendName()
	assert.Equal(t, "software", name)
}

// --- parseCurveString tests ---

func TestParseCurveString_P224(t *testing.T) {
	c := parseCurveString("P-224")
	assert.Equal(t, elliptic.P224(), c)
}

func TestParseCurveString_P256(t *testing.T) {
	c := parseCurveString("P-256")
	assert.Equal(t, elliptic.P256(), c)
}

func TestParseCurveString_P384(t *testing.T) {
	c := parseCurveString("P-384")
	assert.Equal(t, elliptic.P384(), c)
}

func TestParseCurveString_P521(t *testing.T) {
	c := parseCurveString("P-521")
	assert.Equal(t, elliptic.P521(), c)
}

func TestParseCurveString_Unknown(t *testing.T) {
	c := parseCurveString("UNKNOWN")
	assert.Nil(t, c)
}

func TestParseCurveString_Empty(t *testing.T) {
	c := parseCurveString("")
	assert.Nil(t, c)
}

// --- ParseSymmetricAlgorithm tests ---

func TestParseSymmetricAlgorithm_AES(t *testing.T) {
	a := ParseSymmetricAlgorithm("AES-256-GCM")
	assert.NotEmpty(t, a)
}

func TestParseSymmetricAlgorithm_ChaCha(t *testing.T) {
	a := ParseSymmetricAlgorithm("ChaCha20-Poly1305")
	assert.NotEmpty(t, a)
}

func TestParseSymmetricAlgorithm_Symmetric(t *testing.T) {
	a := ParseSymmetricAlgorithm("symmetric")
	assert.NotEmpty(t, a)
}

func TestParseSymmetricAlgorithm_Secret(t *testing.T) {
	a := ParseSymmetricAlgorithm("secret")
	assert.NotEmpty(t, a)
}

func TestParseSymmetricAlgorithm_Unknown(t *testing.T) {
	a := ParseSymmetricAlgorithm("rsa")
	assert.Empty(t, a)
}

// --- buildKeyAttributes tests ---

func TestBuildKeyAttributes_RSA(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "rsa-key",
		Algorithm: "rsa",
		KeySize:   4096,
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, "rsa-key", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.RSAAttributes)
	assert.Equal(t, 4096, attrs.RSAAttributes.KeySize)
}

// TestBuildKeyAttributes_BackendAndStoreType pins go-xkms#312's producer
// contract: Backend carries the registry name verbatim, and StoreType is
// whatever the caller passes in as the resolved backend's Type() -- never
// derived from backendName here. A backend registered under a name that is
// not a store-type keyword (e.g. "token-a", a second PKCS#11 token) is the
// case that a name-derived StoreType got wrong before this field existed.
func TestBuildKeyAttributes_BackendAndStoreType(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "rsa-key",
		Algorithm: "rsa",
	}, "token-a", types.StorePKCS11)
	require.NoError(t, err)
	assert.Equal(t, "token-a", attrs.Backend)
	assert.Equal(t, types.StorePKCS11, attrs.StoreType)
}

func TestBuildKeyAttributes_RSA_DefaultSize(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "rsa-default",
		Algorithm: "rsa",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
}

func TestBuildKeyAttributes_ECDSA_P384(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "ec-key",
		Algorithm: "ecdsa",
		Curve:     "P-384",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.Equal(t, elliptic.P384(), attrs.ECCAttributes.Curve)
}

func TestBuildKeyAttributes_Ed25519(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "ed-key",
		Algorithm: "ed25519",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, x509.Ed25519, attrs.KeyAlgorithm)
}

func TestBuildKeyAttributes_Symmetric(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "sym-key",
		Algorithm: "AES-256-GCM",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.NotEmpty(t, attrs.SymmetricAlgorithm)
}

func TestBuildKeyAttributes_Exportable(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:      "export-key",
		Algorithm:  "ecdsa",
		Exportable: true,
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.True(t, attrs.Exportable)
}

func TestBuildKeyAttributes_ECAlias(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "ec-key",
		Algorithm: "ec",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
}

func TestBuildKeyAttributes_ECCAlias(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "ecc-key",
		Algorithm: "ecc",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
}

func TestBuildKeyAttributes_UnsupportedAlgorithm(t *testing.T) {
	_, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "bad-key",
		Algorithm: "quantum-lattice",
	}, "software", types.StoreSoftware)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
}

// TestBuildKeyAttributes_NoAlgorithmIsUnsupported verifies buildKeyAttributes
// no longer defaults an empty Algorithm to ECDSA P-256: GenerateKey now
// enforces Algorithm is non-empty before calling here (owner rule
// 2026-09-22, PR 2), so an empty value reaching this function is treated the
// same as any other unrecognized algorithm name.
func TestBuildKeyAttributes_NoAlgorithmIsUnsupported(t *testing.T) {
	_, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID: "default-key",
	}, "software", types.StoreSoftware)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
}

func TestBuildKeyAttributes_WithKeyType(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "typed-key",
		Algorithm: "ecdsa",
		KeyType:   "signing",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

func TestBuildKeyAttributes_DefaultKeyType(t *testing.T) {
	// No key type specified, should default to signing
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "no-type-key",
		Algorithm: "ecdsa",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

// --- buildImportKeyAttributes tests ---

// TestBuildImportKeyAttributes_Basic covers an asymmetric import request.
//
// ImportKeyRequest.KeyType names the ALGORITHM -- Algorithm is already the
// wrapping algorithm, so it is the only field that can -- and the key's purpose
// follows from it. The algorithm has to be recorded: types.KeyAttributes.ID()
// encodes it, so attributes that omit it store the key under an identifier
// ending in "unknown" that no other code path constructs.
func TestBuildImportKeyAttributes_Basic(t *testing.T) {
	attrs, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:   "import-key",
		KeyType: "ecdsa",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, "import-key", attrs.CN)
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.NotContains(t, attrs.ID(), "unknown")
}

// TestBuildImportKeyAttributes_WithKeyType covers every asymmetric algorithm
// name the field accepts, passing the backend name and its resolved
// StoreType (go-xkms#312: the latter is no longer derived from the former).
func TestBuildImportKeyAttributes_WithKeyType(t *testing.T) {
	algorithms := map[string]x509.PublicKeyAlgorithm{
		"rsa":     x509.RSA,
		"ecdsa":   x509.ECDSA,
		"ec":      x509.ECDSA,
		"ecc":     x509.ECDSA,
		"Ed25519": x509.Ed25519,
	}

	for name, want := range algorithms {
		t.Run(name, func(t *testing.T) {
			attrs, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
				KeyID:   "import-key",
				KeyType: name,
			}, "pkcs11", types.StorePKCS11)
			require.NoError(t, err)
			assert.Equal(t, "import-key", attrs.CN)
			assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
			assert.Equal(t, want, attrs.KeyAlgorithm)
		})
	}
}

// TestBuildImportKeyAttributes_BackendAndStoreType is the import-ceremony
// counterpart of TestBuildKeyAttributes_BackendAndStoreType: a backend
// registered under a non-keyword name must still stamp its real StoreType
// on the key it imports, not the "unknown" ParseStoreType(backendName) used
// to leave in its place (go-xkms#312).
func TestBuildImportKeyAttributes_BackendAndStoreType(t *testing.T) {
	attrs, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:   "import-key",
		KeyType: "rsa",
	}, "token-a", types.StorePKCS11)
	require.NoError(t, err)
	assert.Equal(t, "token-a", attrs.Backend)
	assert.Equal(t, types.StorePKCS11, attrs.StoreType)
}

// TestBuildImportKeyAttributes_PurposeNameIsNotAnAlgorithm pins that a purpose
// name is refused.
//
// "signing" used to be accepted and mapped to KeyTypeSigning with no algorithm
// at all, which is how an Ed25519 import came to be reported as an RSA key by
// ListKeys and how an RSA import came to fail inside the backend rather than at
// the request that caused it.
func TestBuildImportKeyAttributes_PurposeNameIsNotAnAlgorithm(t *testing.T) {
	for _, purpose := range []string{"signing", "tls", "encryption", "ca"} {
		t.Run(purpose, func(t *testing.T) {
			_, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
				KeyID:   "import-key",
				KeyType: purpose,
			}, "software", types.StoreSoftware)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidKeyType)
		})
	}
}

// TestBuildImportKeyAttributes_KeyTypeRequired pins that there is no default
// algorithm for an import: it cannot be recovered from the wrapped material at
// this layer, so a request that omits it is refused rather than answered with a
// key stored under an identifier that misdescribes it.
func TestBuildImportKeyAttributes_KeyTypeRequired(t *testing.T) {
	_, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID: "no-type-key",
	}, "pkcs11", types.StorePKCS11)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingRequiredField)
}

func TestBuildImportKeyAttributes_UnknownKeyType(t *testing.T) {
	_, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:   "unknown-type",
		KeyType: "unknown-type-xyz",
	}, "software", types.StoreSoftware)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidKeyType)
}

// TestBuildImportKeyAttributes_Symmetric proves an import request that names a
// symmetric key produces attributes a backend will actually import.
//
// types.KeyAttributes.IsSymmetric is SymmetricAlgorithm != "", and every
// backend's ImportKey dispatches on it, so attributes without it send raw AES
// bytes into x509.ParsePKCS8PrivateKey. Asserting KeyType alone would not
// catch that: the old code set KeyType and nothing else, and the import still
// failed. SymmetricAlgorithm is the field that decides.
func TestBuildImportKeyAttributes_Symmetric(t *testing.T) {
	sizes := map[int]types.SymmetricAlgorithm{
		128: types.SymmetricAES128GCM,
		192: types.SymmetricAES192GCM,
		256: types.SymmetricAES256GCM,
	}

	for _, keyType := range []string{"symmetric", "aes"} {
		for size, want := range sizes {
			t.Run(fmt.Sprintf("%s-%d", keyType, size), func(t *testing.T) {
				attrs, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
					KeyID:   "sym-import",
					KeyType: keyType,
					KeySize: size,
				}, "software", types.StoreSoftware)
				require.NoError(t, err)
				assert.Equal(t, types.KeyTypeSecret, attrs.KeyType)
				assert.Equal(t, want, attrs.SymmetricAlgorithm,
					"the symmetric algorithm is what makes IsSymmetric true and routes the import")
				assert.True(t, attrs.Exportable,
					"an imported secret key must be readable back, per v3.2 Table 30's CKA_EXTRACTABLE default")
			})
		}
	}
}

// TestBuildImportKeyAttributes_SymmetricSizeFromKeySizeNotAESKeySize pins which
// of the two size fields is authoritative.
//
// Both name the same quantity, but the gRPC ImportKeyRequest message carries
// key_size and has no aes_key_size field. Reading AESKeySize first would make
// one call produce a 256-bit key over gRPC and a 128-bit key over the unix
// socket, from a request that looked identical to the caller.
func TestBuildImportKeyAttributes_SymmetricSizeFromKeySizeNotAESKeySize(t *testing.T) {
	attrs, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:      "sym-import",
		KeyType:    "symmetric",
		KeySize:    128,
		AESKeySize: 256,
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricAES128GCM, attrs.SymmetricAlgorithm,
		"KeySize wins over AESKeySize, because only KeySize survives every transport")

	// AESKeySize is still honoured when it is the only size the caller sent,
	// which is what the REST and MCP request shapes populate.
	fallback, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:      "sym-import",
		KeyType:    "symmetric",
		AESKeySize: 192,
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricAES192GCM, fallback.SymmetricAlgorithm)
}

// TestBuildImportKeyAttributes_SymmetricInvalidSize proves an unsupported size
// is refused here rather than left to fail later as a PKCS#8 parse error.
//
// Returning attributes with no SymmetricAlgorithm would send the request down
// the asymmetric path, where the caller's real mistake -- an impossible key
// size -- is reported as "failed to parse PKCS8 private key". Refusing names
// the actual problem.
func TestBuildImportKeyAttributes_SymmetricInvalidSize(t *testing.T) {
	for _, size := range []int{1, 64, 127, 255, 512, -256} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			attrs, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
				KeyID:   "sym-import",
				KeyType: "symmetric",
				KeySize: size,
			}, "software", types.StoreSoftware)
			require.Error(t, err)
			assert.Nil(t, attrs, "a refused request must yield no attributes to act on")
			assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
		})
	}
}

// TestBuildImportKeyAttributes_SymmetricZeroSizeDefaults proves an omitted size
// selects AES-256, the same default UnwrapKeyByID applies through the shared
// unwrapSymmetricAlgorithms table. A caller importing a key it did not generate
// has no reason to know the size in advance.
func TestBuildImportKeyAttributes_SymmetricZeroSizeDefaults(t *testing.T) {
	attrs, err := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:   "sym-import",
		KeyType: "symmetric",
	}, "software", types.StoreSoftware)
	require.NoError(t, err)
	assert.Equal(t, types.SymmetricAES256GCM, attrs.SymmetricAlgorithm)
	assert.Equal(t, types.KeyTypeSecret, attrs.KeyType)
}

// --- attrsToKeyInfoList tests ---

func TestAttrsToKeyInfoList_Empty(t *testing.T) {
	result := attrsToKeyInfoList(nil, "software")
	assert.Empty(t, result)
}

func TestAttrsToKeyInfoList_MultipleKeys(t *testing.T) {
	attrs := []*types.KeyAttributes{
		{CN: "key-1", KeyAlgorithm: x509.ECDSA, KeyType: types.KeyTypeSigning},
		{CN: "key-2", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeSigning},
	}
	result := attrsToKeyInfoList(attrs, "software")
	assert.Len(t, result, 2)
	assert.Equal(t, "key-1", result[0].KeyID)
	assert.Equal(t, "software", result[0].Backend)
	assert.Equal(t, "key-2", result[1].KeyID)
}

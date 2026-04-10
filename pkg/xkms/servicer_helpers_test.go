package xkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	_, err := software.GenerateECDSA(&types.KeyAttributes{
		CN:           "find-me",
		KeyAlgorithm: x509.ECDSA,
	})
	require.NoError(t, err)

	attrs, err := findKeyAttrs(software, "find-me")
	require.NoError(t, err)
	assert.Equal(t, "find-me", attrs.CN)
}

func TestFindKeyAttrs_NotFound(t *testing.T) {
	software, _ := setupService(t)

	_, err := findKeyAttrs(software, "does-not-exist")
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

func TestParseHash_Empty(t *testing.T) {
	h := parseHash("")
	assert.Equal(t, crypto.SHA256, h)
}

func TestParseHash_SHA256(t *testing.T) {
	h := parseHash("SHA-256")
	assert.Equal(t, crypto.SHA256, h)
}

func TestParseHash_SHA512(t *testing.T) {
	// "SHA-512" is normalized to "SHA_512" by ParseHash which doesn't match "SHA512",
	// so it falls back to SHA-256. Use "SHA512" for an exact match.
	h := parseHash("SHA512")
	assert.Equal(t, crypto.SHA512, h)
}

func TestParseHash_SHA384(t *testing.T) {
	h := parseHash("SHA384")
	assert.Equal(t, crypto.SHA384, h)
}

func TestParseHash_Unrecognized(t *testing.T) {
	h := parseHash("INVALID-HASH")
	// Falls back to SHA-256
	assert.Equal(t, crypto.SHA256, h)
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

// --- parseSymmetricAlgorithm tests ---

func TestParseSymmetricAlgorithm_AES(t *testing.T) {
	a := parseSymmetricAlgorithm("AES-256-GCM")
	assert.NotEmpty(t, a)
}

func TestParseSymmetricAlgorithm_ChaCha(t *testing.T) {
	a := parseSymmetricAlgorithm("ChaCha20-Poly1305")
	assert.NotEmpty(t, a)
}

func TestParseSymmetricAlgorithm_Symmetric(t *testing.T) {
	a := parseSymmetricAlgorithm("symmetric")
	assert.NotEmpty(t, a)
}

func TestParseSymmetricAlgorithm_Secret(t *testing.T) {
	a := parseSymmetricAlgorithm("secret")
	assert.NotEmpty(t, a)
}

func TestParseSymmetricAlgorithm_Unknown(t *testing.T) {
	a := parseSymmetricAlgorithm("rsa")
	assert.Empty(t, a)
}

// --- buildKeyAttributes tests ---

func TestBuildKeyAttributes_RSA(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "rsa-key",
		Algorithm: "rsa",
		KeySize:   4096,
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, "rsa-key", attrs.CN)
	assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.RSAAttributes)
	assert.Equal(t, 4096, attrs.RSAAttributes.KeySize)
}

func TestBuildKeyAttributes_RSA_DefaultSize(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "rsa-default",
		Algorithm: "rsa",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
}

func TestBuildKeyAttributes_ECDSA_P384(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "ec-key",
		Algorithm: "ecdsa",
		Curve:     "P-384",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.Equal(t, elliptic.P384(), attrs.ECCAttributes.Curve)
}

func TestBuildKeyAttributes_Ed25519(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "ed-key",
		Algorithm: "ed25519",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, x509.Ed25519, attrs.KeyAlgorithm)
}

func TestBuildKeyAttributes_Symmetric(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "sym-key",
		Algorithm: "AES-256-GCM",
	}, "software")
	require.NoError(t, err)
	assert.NotEmpty(t, attrs.SymmetricAlgorithm)
}

func TestBuildKeyAttributes_Exportable(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:      "export-key",
		Algorithm:  "ecdsa",
		Exportable: true,
	}, "software")
	require.NoError(t, err)
	assert.True(t, attrs.Exportable)
}

func TestBuildKeyAttributes_ECAlias(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "ec-key",
		Algorithm: "ec",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
}

func TestBuildKeyAttributes_ECCAlias(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "ecc-key",
		Algorithm: "ecc",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
}

func TestBuildKeyAttributes_UnsupportedAlgorithm(t *testing.T) {
	_, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "bad-key",
		Algorithm: "quantum-lattice",
	}, "software")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedKeyAlgorithm)
}

func TestBuildKeyAttributes_DefaultECDSAP256(t *testing.T) {
	// No algorithm specified, should default to ECDSA P-256
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID: "default-key",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
	assert.Equal(t, elliptic.P256(), attrs.ECCAttributes.Curve)
}

func TestBuildKeyAttributes_WithKeyType(t *testing.T) {
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "typed-key",
		Algorithm: "ecdsa",
		KeyType:   "signing",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

func TestBuildKeyAttributes_DefaultKeyType(t *testing.T) {
	// No key type specified, should default to signing
	attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "no-type-key",
		Algorithm: "ecdsa",
	}, "software")
	require.NoError(t, err)
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

// --- buildImportKeyAttributes tests ---

func TestBuildImportKeyAttributes_Basic(t *testing.T) {
	attrs := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID: "import-key",
	}, "software")
	assert.Equal(t, "import-key", attrs.CN)
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

func TestBuildImportKeyAttributes_WithKeyType(t *testing.T) {
	attrs := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:   "import-key",
		KeyType: "signing",
	}, "software")
	assert.Equal(t, "import-key", attrs.CN)
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

func TestBuildImportKeyAttributes_DefaultKeyType(t *testing.T) {
	// No key type specified, should default to signing
	attrs := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID: "no-type-key",
	}, "pkcs11")
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
}

func TestBuildImportKeyAttributes_UnknownKeyType(t *testing.T) {
	// Unknown key type string should result in default (signing)
	attrs := buildImportKeyAttributes(&transport.ImportKeyRequest{
		KeyID:   "unknown-type",
		KeyType: "unknown-type-xyz",
	}, "software")
	assert.Equal(t, types.KeyTypeSigning, attrs.KeyType)
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

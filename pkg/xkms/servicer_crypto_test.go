package xkms

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Sign ---

func TestSign_ECDSA_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:            "sign-ecdsa",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	resp, err := svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-ecdsa",
		Data:    []byte("hello world"),
		Hash:    "SHA-256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Signature)
}

func TestSign_RSA_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(&types.KeyAttributes{
		CN:           "sign-rsa",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	})
	require.NoError(t, err)

	resp, err := svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-rsa",
		Data:    []byte("hello world"),
		Hash:    "SHA-256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Signature)
}

func TestSign_Ed25519_RoundTrip(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateEd25519(&types.KeyAttributes{
		CN:           "sign-ed25519",
		KeyAlgorithm: x509.Ed25519,
	})
	require.NoError(t, err)

	data := []byte("ed25519 round trip data")

	// Sign with Ed25519 (pure signing, no pre-hashing)
	signResp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-ed25519",
		Data:    data,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, signResp.Signature)
	assert.Equal(t, "Ed25519", signResp.Algorithm)

	// Verify with Ed25519
	verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "sign-ed25519",
		Data:      data,
		Signature: signResp.Signature,
	})
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid)
}

func TestVerify_Ed25519_InvalidSignature(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateEd25519(&types.KeyAttributes{
		CN:           "verify-ed25519-bad",
		KeyAlgorithm: x509.Ed25519,
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(context.Background(), &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "verify-ed25519-bad",
		Data:      []byte("data"),
		Signature: make([]byte, 64), // invalid signature (correct length for ed25519)
	})
	require.NoError(t, err)
	assert.False(t, verifyResp.Valid)
}

func TestVerify_RSA_InvalidSignature(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(&types.KeyAttributes{
		CN:            "verify-rsa-bad",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(context.Background(), &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "verify-rsa-bad",
		Data:      []byte("data"),
		Signature: []byte("bad-rsa-signature"),
		Hash:      "SHA-256",
	})
	// RSA verify with bad sig returns Valid=false with error message, no error
	require.NoError(t, err)
	assert.False(t, verifyResp.Valid)
	assert.NotEmpty(t, verifyResp.Message)
}

func TestSign_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Sign(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

func TestServicerSign_KeyNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "nonexistent",
		Data:    []byte("data"),
	})
	require.Error(t, err)
}

func TestSign_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "nonexistent",
		KeyID:   "key",
		Data:    []byte("data"),
	})
	require.Error(t, err)
}

// --- Verify ---

func TestVerify_ECDSA_RoundTrip(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:            "verify-ecdsa",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	data := []byte("round trip data")

	signResp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend: "software",
		KeyID:   "verify-ecdsa",
		Data:    data,
		Hash:    "SHA-256",
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "verify-ecdsa",
		Data:      data,
		Signature: signResp.Signature,
		Hash:      "SHA-256",
	})
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid)
}

func TestVerify_ECDSA_InvalidSignature(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:            "verify-bad",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(context.Background(), &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "verify-bad",
		Data:      []byte("data"),
		Signature: []byte("bad-signature"),
		Hash:      "SHA-256",
	})
	require.NoError(t, err)
	assert.False(t, verifyResp.Valid)
}

func TestVerify_RSA_RoundTrip(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateRSA(&types.KeyAttributes{
		CN:            "verify-rsa",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	data := []byte("rsa round trip")

	signResp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend: "software",
		KeyID:   "verify-rsa",
		Data:    data,
		Hash:    "SHA-256",
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "verify-rsa",
		Data:      data,
		Signature: signResp.Signature,
		Hash:      "SHA-256",
	})
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid)
}

func TestVerify_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Verify(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

// --- Encrypt / Decrypt ---

func TestEncrypt_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Encrypt(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

func TestDecrypt_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Decrypt(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

// --- EncryptAsym ---

func TestEncryptAsym_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.EncryptAsym(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

func TestEncryptAsym_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend:   "nonexistent",
		KeyID:     "key",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
}

func TestEncryptAsym_RSA_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(&types.KeyAttributes{
		CN:            "encrypt-rsa",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	resp, err := svc.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "encrypt-rsa",
		Plaintext: []byte("secret message"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestEncryptAsym_NonRSAKey(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:            "encrypt-ec",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	_, err = svc.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "encrypt-ec",
		Plaintext: []byte("secret"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEncryptionFailed))
}

// --- DeriveKey ---

func TestDeriveKey_HKDF_Success(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "hkdf",
		InputKeyMaterial: []byte("secret-input-key-material-32byte"),
		Salt:             []byte("salt-value"),
		Info:             []byte("context-info"),
		KeyLength:        32,
		Hash:             "SHA-256",
	})
	require.NoError(t, err)
	assert.Len(t, resp.DerivedKey, 32)
	assert.Equal(t, "hkdf", resp.Algorithm)
}

func TestDeriveKey_DefaultAlgorithm(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		InputKeyMaterial: []byte("key-material-for-derivation"),
		KeyLength:        16,
	})
	require.NoError(t, err)
	assert.Len(t, resp.DerivedKey, 16)
}

func TestDeriveKey_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.DeriveKey(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

func TestDeriveKey_UnsupportedAlgorithm(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "unsupported-kdf",
		InputKeyMaterial: []byte("ikm"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestDeriveKey_NoInputKeyMaterial(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm: "hkdf",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
}

func TestDeriveKey_DefaultKeyLength(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// KeyLength <= 0 defaults to 32
	resp, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "hkdf",
		InputKeyMaterial: []byte("key-material-for-derivation-test"),
	})
	require.NoError(t, err)
	assert.Len(t, resp.DerivedKey, 32)
}

func TestDeriveKey_SP800108Counter(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Algorithm:        "sp800-108-counter",
		InputKeyMaterial: []byte("secret-input-key-material-32byte"),
		Label:            []byte("test-label"),
		Context:          []byte("test-context"),
		KeyLength:        32,
	})
	require.NoError(t, err)
	assert.Len(t, resp.DerivedKey, 32)
}

// --- Stub operations ---

func TestDeriveKeyECDH_NotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestAttestKey_NotSupported(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.AttestKey(context.Background(), &transport.AttestKeyRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

// --- Additional crypto coverage ---

func TestEncrypt_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "nonexistent",
		KeyID:     "key",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
}

func TestServicerEncrypt_KeyNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "ghost-key",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
}

func TestEncrypt_BackendNotSymmetric(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:            "sym-test",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "sym-test",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEncryptionFailed))
}

func TestDecrypt_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "nonexistent",
		KeyID:      "key",
		Ciphertext: []byte("data"),
	})
	require.Error(t, err)
}

func TestServicerDecrypt_KeyNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "ghost-key",
		Ciphertext: []byte("data"),
	})
	require.Error(t, err)
}

func TestVerify_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Verify(context.Background(), &transport.VerifyRequest{
		Backend:   "nonexistent",
		KeyID:     "key",
		Data:      []byte("data"),
		Signature: []byte("sig"),
	})
	require.Error(t, err)
}

func TestServicerVerify_KeyNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Verify(context.Background(), &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "ghost-key",
		Data:      []byte("data"),
		Signature: []byte("sig"),
	})
	require.Error(t, err)
}

func TestEncryptAsym_KeyNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "ghost-key",
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
}

func TestServicerDecrypt_NonDecrypterKey(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// ECDSA keys don't implement crypto.Decrypter, so asymmetric decrypt
	// fallback should fail
	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:            "decrypt-ec",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "decrypt-ec",
		Ciphertext: []byte("ciphertext"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDecryptionFailed))
}

func TestSign_DefaultHash(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(&types.KeyAttributes{
		CN:            "sign-default-hash",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)

	resp, err := svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-default-hash",
		Data:    []byte("hello"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Signature)
}

// --- GenerateKey Ed25519 ---

func TestGenerateKey_Ed25519_Success(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "ed25519-key",
		Algorithm: "ed25519",
		Backend:   "software",
	})
	require.NoError(t, err)
	assert.Equal(t, "ed25519-key", resp.KeyID)
	assert.NotEmpty(t, resp.PublicKeyPEM)
	assert.Contains(t, resp.PublicKeyPEM, "BEGIN PUBLIC KEY")
}

// --- EncryptAsym RSA Decrypt error path ---

func TestDecryptAsym_RSA_OAEPMismatch(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateRSA(&types.KeyAttributes{
		CN:            "decrypt-oaep-mismatch",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	// Encrypt with OAEP padding via EncryptAsym
	encResp, err := svc.EncryptAsym(ctx, &transport.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "decrypt-oaep-mismatch",
		Plaintext: []byte("secret message"),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, encResp.Ciphertext)

	// Decrypt through Decrypt() passes nil opts (PKCS1v15 by default)
	// which is incompatible with OAEP-encrypted data, exercising the
	// asymmetric decrypt error path
	_, err = svc.Decrypt(ctx, &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "decrypt-oaep-mismatch",
		Ciphertext: encResp.Ciphertext,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDecryptionFailed))
}

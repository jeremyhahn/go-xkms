package xkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: used only to build a SHA-1 OAEP ciphertext the service must refuse
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Sign ---

func TestSign_ECDSA_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateEd25519(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateEd25519(context.Background(), &types.KeyAttributes{
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

// TestSign_Ed25519ctx_RoundTrip covers CKM_EDDSA's Ed25519ctx variant (RFC
// 8032 Table 73: phFlag=false, context present), threaded end to end from
// transport.SignRequest.Context through to the signature.
func TestSign_Ed25519ctx_RoundTrip(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateEd25519(ctx, &types.KeyAttributes{
		CN:           "sign-ed25519ctx",
		KeyAlgorithm: x509.Ed25519,
	})
	require.NoError(t, err)

	data := []byte("ed25519ctx round trip data")
	sigContext := []byte("app-context")

	signResp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-ed25519ctx",
		Data:    data,
		Context: sigContext,
	})
	if types.FIPSMode() {
		// Ed25519ctx (RFC 8032's context-string variant) is refused
		// outright under GODEBUG=fips140=only: FIPS 186-5 approves only
		// "pure" Ed25519 with no context or pre-hash. crypto/ed25519
		// reports this as a clean error, not a panic.
		require.Error(t, err)
		return
	}
	require.NoError(t, err)
	assert.NotEmpty(t, signResp.Signature)

	verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "sign-ed25519ctx",
		Data:      data,
		Signature: signResp.Signature,
		Context:   sigContext,
	})
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid)
}

// TestSign_Ed25519ph_RoundTrip covers CKM_EDDSA's Ed25519ph variant (RFC
// 8032 Table 73: phFlag=true). PKCS#11 passes the original, unhashed
// message even for this variant (v3.2 section 6.3.14 Table 74), so the
// backend's own SHA-512 pre-hash step must produce a signature that
// verifies against the same original message.
func TestSign_Ed25519ph_RoundTrip(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateEd25519(ctx, &types.KeyAttributes{
		CN:           "sign-ed25519ph",
		KeyAlgorithm: x509.Ed25519,
	})
	require.NoError(t, err)

	data := []byte("ed25519ph round trip data")

	signResp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-ed25519ph",
		Data:    data,
		PreHash: true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, signResp.Signature)

	verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "sign-ed25519ph",
		Data:      data,
		Signature: signResp.Signature,
		PreHash:   true,
	})
	require.NoError(t, err)
	assert.True(t, verifyResp.Valid)
}

// TestVerify_Ed25519ctx_WrongContextFails proves the context string is
// actually bound into the signature (RFC 8032), not merely accepted and
// discarded: a signature produced under one context must not verify
// against a different one.
func TestVerify_Ed25519ctx_WrongContextFails(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateEd25519(ctx, &types.KeyAttributes{
		CN:           "sign-ed25519ctx-mismatch",
		KeyAlgorithm: x509.Ed25519,
	})
	require.NoError(t, err)

	data := []byte("data")

	signResp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-ed25519ctx-mismatch",
		Data:    data,
		Context: []byte("context-a"),
	})
	if types.FIPSMode() {
		// Ed25519ctx is refused outright under GODEBUG=fips140=only; see
		// TestSign_Ed25519ctx_RoundTrip.
		require.Error(t, err)
		return
	}
	require.NoError(t, err)

	verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
		Backend:   "software",
		KeyID:     "sign-ed25519ctx-mismatch",
		Data:      data,
		Signature: signResp.Signature,
		Context:   []byte("context-b"),
	})
	require.NoError(t, err)
	assert.False(t, verifyResp.Valid)
}

// stubEd25519Signer wraps an ed25519.PrivateKey behind a distinct concrete
// type, so it implements crypto.Signer without being one -- simulating a
// hardware/cloud KMS-backed Ed25519 signer that has no notion of RFC 8032's
// context or pre-hash options, the way HSM/TPM/cloud KMS signers in this
// codebase are typed today.
type stubEd25519Signer struct {
	key ed25519.PrivateKey
}

func (s stubEd25519Signer) Public() crypto.PublicKey { return s.key.Public() }

func (s stubEd25519Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand, digest, opts)
}

// TestSignEd25519Variant_UnsupportedBackendRejected proves that a backend
// which cannot prove it supports CK_EDDSA_PARAMS's phFlag/context is
// refused outright rather than silently signing under plain Ed25519 --
// the exact defect this fix closes.
func TestSignEd25519Variant_UnsupportedBackendRejected(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, err = signEd25519Variant(stubEd25519Signer{key: priv}, []byte("data"), false, []byte("context"))
	require.Error(t, err)
}

// TestSignEd25519Variant_RoundTrip is a fast, pure-crypto unit test for the
// helper itself: an ed25519.PrivateKey signer must produce a signature
// verifyEd25519Variant accepts under the same phFlag/context.
func TestSignEd25519Variant_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	data := []byte("helper round trip data")

	sig, err := signEd25519Variant(priv, data, true, []byte("ctx"))
	require.NoError(t, err)

	assert.True(t, verifyEd25519Variant(pub, data, sig, true, []byte("ctx")))
	assert.False(t, verifyEd25519Variant(pub, data, sig, false, []byte("ctx")),
		"a phFlag mismatch between sign and verify must not validate")
}

func TestVerify_RSA_InvalidSignature(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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

// --- RSA-OAEP decrypt ---

// newOAEPTestKey generates an RSA key in the software backend and returns its
// public half, so a test can build a ciphertext with crypto/rsa independently
// of anything the service does.
func newOAEPTestKey(t *testing.T, software *mockKeyStore, cn string) *rsa.PublicKey {
	t.Helper()

	key, err := software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            cn,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	priv, ok := key.(*rsa.PrivateKey)
	require.True(t, ok, "software backend returned %T, want *rsa.PrivateKey", key)
	return &priv.PublicKey
}

// TestDecrypt_OAEPUnnamedHashMatchesTheEncryptHalf proves that an OAEP decrypt
// with no hash named uses the same digest the encrypt half uses when none is
// named, so a ciphertext this service produces is one it can read back.
//
// The oracle is crypto/rsa, not EncryptAsym: the ciphertext is built here with
// rsa.EncryptOAEP(sha256.New(), ...) against the key's public half. A decrypt
// that defaulted to any other digest returns a decryption error rather than the
// plaintext, and only a real SHA-256 OAEP ciphertext can distinguish the two.
//
// The default used to be SHA-1 on this side and SHA-256 on the encrypt side, so
// the round trip could not complete at all.
func TestDecrypt_OAEPUnnamedHashMatchesTheEncryptHalf(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	pub := newOAEPTestKey(t, software, "oaep-default-digest")
	plaintext := []byte("the message under oaep")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
	require.NoError(t, err)

	resp, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "oaep-default-digest",
		Ciphertext: ciphertext,
		Padding:    "oaep",
	})
	require.NoError(t, err, "an OAEP decrypt with no hash named must use the same digest the encrypt half defaults to")
	assert.Equal(t, plaintext, resp.Plaintext)
}

// TestDecrypt_OAEPHonoursAnExplicitStrongHash proves the named digest is the one
// actually used, rather than the default being applied regardless.
//
// Without this, the previous test would also pass for an implementation that
// ignored req.Hash entirely.
func TestDecrypt_OAEPHonoursAnExplicitStrongHash(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	pub := newOAEPTestKey(t, software, "oaep-explicit-digest")
	plaintext := []byte("the message under oaep")

	// SHA-512 is not the default, so a ciphertext under it can only be read by
	// an implementation that honoured the name on the request.
	ciphertext, err := rsa.EncryptOAEP(crypto.SHA512.New(), rand.Reader, pub, plaintext, nil)
	require.NoError(t, err)

	resp, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "oaep-explicit-digest",
		Ciphertext: ciphertext,
		Padding:    "oaep",
		Hash:       "SHA-512",
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, resp.Plaintext)

	// The same ciphertext with a different digest named must fail, which is
	// what proves the name reached rsa.OAEPOptions rather than being ignored.
	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "oaep-explicit-digest",
		Ciphertext: ciphertext,
		Padding:    "oaep",
		Hash:       "SHA-256",
	})
	require.Error(t, err, "a SHA-512 OAEP ciphertext decrypted under SHA-256 must fail; succeeding would mean the hash name is ignored")
}

// TestDecrypt_OAEPRejectsSHA1 proves the decrypt half applies the same weak-hash
// refusal as the encrypt half.
//
// The C ABI now rejects a missing CK_RSA_PKCS_OAEP_PARAMS, but a present
// structure with hashAlg = CKM_SHA_1 is spec-legal and used to travel all the
// way through: EncryptAsym refused SHA-1 OAEP while Decrypt performed it, so the
// policy held on one half of the operation only.
//
// A genuine SHA-1 OAEP ciphertext is built with crypto/rsa so the refusal is not
// confused with a ciphertext the key simply cannot decrypt: this input would
// decrypt cleanly if the gate were absent.
func TestDecrypt_OAEPRejectsSHA1(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	pub := newOAEPTestKey(t, software, "oaep-sha1-decrypt")
	plaintext := []byte("the message under oaep")

	ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plaintext, nil) //nolint:gosec // G505: the point of the test is that SHA-1 OAEP is refused
	if err != nil {
		// crypto/rsa itself refuses to run SHA-1 through OAEP under
		// GODEBUG=fips140=only, so there is no ciphertext this fixture can
		// build to exercise this package's own ErrWeakOAEPHash refusal in
		// that mode; the stdlib enforces the identical policy at the
		// point this test targets one layer up from.
		if types.FIPSMode() {
			return
		}
		require.NoError(t, err)
	}

	for _, name := range []string{"SHA-1", "sha1", "1"} {
		_, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
			Backend:    "software",
			KeyID:      "oaep-sha1-decrypt",
			Ciphertext: ciphertext,
			Padding:    "oaep",
			Hash:       name,
		})
		require.Error(t, err, "hash %q", name)
		assert.True(t, errors.Is(err, ErrWeakOAEPHash),
			"hash %q: want ErrWeakOAEPHash so the caller learns the digest is refused rather than that its ciphertext is corrupt, got %v", name, err)
	}
}

// TestDecrypt_OAEPRejectsTheNoneSentinel is the bad-input case for the hash
// field: "NONE" means "no digest", and OAEP cannot be performed without one.
//
// Accepting it would leave rsa.OAEPOptions carrying crypto.Hash(0), which panics
// inside crypto/rsa rather than returning an error a caller can act on.
func TestDecrypt_OAEPRejectsTheNoneSentinel(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	pub := newOAEPTestKey(t, software, "oaep-none-hash")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte("x"), nil)
	require.NoError(t, err)

	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "oaep-none-hash",
		Ciphertext: ciphertext,
		Padding:    "oaep",
		Hash:       "NONE",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidHashFunction), "want ErrInvalidHashFunction, got %v", err)
}

// TestAsymDecrypterOpts_MatchesTheEncryptGate pins the resolution table itself,
// including the padding names and the label, which the round-trip tests above
// cannot separate from a decryption failure.
func TestAsymDecrypterOpts_MatchesTheEncryptGate(t *testing.T) {
	// PKCS#1 v1.5 is the default and carries no options.
	for _, padding := range []string{"", "pkcs1v15", "PKCS1v15"} {
		opts, err := asymDecrypterOpts(&transport.DecryptRequest{Padding: padding})
		require.NoError(t, err, "padding %q", padding)
		assert.Nil(t, opts, "padding %q must decrypt as PKCS#1 v1.5 with no options", padding)
	}

	// An unnamed OAEP digest resolves to the same digest EncryptAsym uses when
	// none is named.
	opts, err := asymDecrypterOpts(&transport.DecryptRequest{Padding: "oaep", Label: []byte("l")})
	require.NoError(t, err)
	oaep, ok := opts.(*rsa.OAEPOptions)
	require.True(t, ok, "OAEP padding must yield *rsa.OAEPOptions, got %T", opts)
	assert.Equal(t, crypto.SHA256, oaep.Hash)
	assert.Equal(t, []byte("l"), oaep.Label, "the OAEP label must reach crypto/rsa; dropping it decrypts a different message")

	// An unresolvable digest is an error, not a substitution.
	_, err = asymDecrypterOpts(&transport.DecryptRequest{Padding: "oaep", Hash: "SHA-999"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidHashFunction), "want ErrInvalidHashFunction, got %v", err)

	// So is an unknown padding scheme.
	_, err = asymDecrypterOpts(&transport.DecryptRequest{Padding: "oaep2"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSignatureScheme), "want ErrInvalidSignatureScheme, got %v", err)
}

// --- ECDH with CKD_NULL (the raw shared secret) ---

// ecdhTestProvider is a types.KeyAgreementProvider that performs a genuine
// P-256 ECDH with crypto/ecdh and then hands the shared secret to the canonical
// types.KDFParams.Derive, exactly as every real backend's applyKDF does.
//
// It exists so a service-level test can reach the derivation path without a
// hardware token, while still exercising the real KDF selection: the secret is
// real, and Derive is the same function the software, TPM 2.0, PKCS#11 and
// phone backends all call.
type ecdhTestProvider struct {
	types.KeyProvider

	priv *ecdh.PrivateKey
}

func (p *ecdhTestProvider) DeriveKeyECDH(_ context.Context, _ *types.KeyAttributes, peerPublicKey []byte, kdfParams *types.KDFParams) ([]byte, error) {
	if kdfParams == nil {
		return nil, errors.New("kdf parameters are required")
	}
	if err := kdfParams.Validate(); err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, err
	}
	secret, err := p.priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	return kdfParams.Derive(secret)
}

func (p *ecdhTestProvider) SupportedCurves() []string { return []string{"P-256"} }

// newECDHTestBackend wires a "software" backend whose key provider performs a
// real P-256 ECDH, and returns the peer key the test controls plus the token's
// own public point, so the shared secret can be recomputed independently.
func newECDHTestBackend(t *testing.T) (peer *ecdh.PrivateKey, tokenPub *ecdh.PublicKey) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	symBackend, err := symmetric.NewBackend(&symmetric.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	tokenPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peer, err = ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:           "ecdh-base-key",
		KeyAlgorithm: x509.ECDSA,
		StoreType:    types.ParseStoreType("software"),
	}

	store := newMockKeyStore("software")
	store.backend = &ecdhTestProvider{KeyProvider: symBackend, priv: tokenPriv}
	store.keys[attrs.CN] = "placeholder"
	store.keyAttrs[attrs.CN] = attrs

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": store},
		DefaultBackend: "software",
	}))

	return peer, tokenPriv.PublicKey()
}

// TestDeriveKeyECDH_RawIsTheUnmodifiedSharedSecret proves the RAW KDF returns
// the ECDH shared secret itself rather than any function of it.
//
// This is PKCS#11's CKD_NULL, which TLS key exchange and OpenSSL's
// pkcs11-provider request, and it is the case a defaulted KDF quietly destroys:
// an unnamed algorithm resolves to HKDF, so a raw request expressed as "no
// algorithm" comes back as an HKDF expansion -- a well-formed key of exactly the
// right length that the peer cannot reproduce.
//
// The oracle is crypto/ecdh: the peer key is generated in the test, so the
// shared secret is computed independently of anything the service does. Only
// reproducing those exact bytes shows no derivation was applied.
func TestDeriveKeyECDH_RawIsTheUnmodifiedSharedSecret(t *testing.T) {
	peer, tokenPub := newECDHTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	secret, err := peer.ECDH(tokenPub)
	require.NoError(t, err)
	require.Len(t, secret, 32, "P-256 ECDH yields a 32-byte shared secret")

	resp, err := svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		Backend:       "software",
		KeyID:         "ecdh-base-key",
		PeerPublicKey: peer.PublicKey().Bytes(),
		KDFAlgorithm:  "RAW",
		KeyLength:     32,
	})
	require.NoError(t, err)
	assert.Equal(t, secret, resp.DerivedKey,
		"RAW must yield the unmodified ECDH shared secret; any difference means a KDF was applied that the caller did not ask for")

	// The same request without the RAW name must not produce the same bytes,
	// which is what proves the name selected the behaviour rather than the
	// derivation being a no-op for every algorithm.
	hkdfResp, err := svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		Backend:       "software",
		KeyID:         "ecdh-base-key",
		PeerPublicKey: peer.PublicKey().Bytes(),
		KeyLength:     32,
	})
	require.NoError(t, err)
	assert.NotEqual(t, resp.DerivedKey, hkdfResp.DerivedKey,
		"an unnamed KDF must still be HKDF; if it matched RAW, the default would be silently returning the raw secret")
}

// TestDeriveKeyECDH_RawTruncatesFromTheLeadingEnd proves a shorter CKA_VALUE_LEN
// takes the tail of the secret, which is what PKCS#11 v3.2 §6.3.17 specifies:
// "The truncation removes bytes from the leading end of the secret value."
//
// Taking the head instead would produce a key of the right length that a
// conformant peer cannot reproduce, and no length assertion could see it.
func TestDeriveKeyECDH_RawTruncatesFromTheLeadingEnd(t *testing.T) {
	peer, tokenPub := newECDHTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	secret, err := peer.ECDH(tokenPub)
	require.NoError(t, err)

	resp, err := svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		Backend:       "software",
		KeyID:         "ecdh-base-key",
		PeerPublicKey: peer.PublicKey().Bytes(),
		KDFAlgorithm:  "RAW",
		KeyLength:     16,
	})
	require.NoError(t, err)
	assert.Equal(t, secret[len(secret)-16:], resp.DerivedKey,
		"PKCS#11 v3.2 6.3.17 removes bytes from the leading end, so a 16-byte key is the tail of the secret")
	assert.NotEqual(t, secret[:16], resp.DerivedKey,
		"taking the head would be the wrong 16 bytes and would still look like a valid key")
}

// TestDeriveKeyECDH_RawRefusesInputsItCannotConsume is the bad-input half:
// CKD_NULL consumes nothing, so every KDF input supplied with it is refused
// rather than dropped.
//
// PKCS#11 v3.2's CK_ECDH1_DERIVE_PARAMS states that with CKD_NULL "pSharedData
// must be NULL and ulSharedDataLen must be zero". Accepting and discarding a
// shared info would give two parties who believe different shared info separates
// them the identical key.
func TestDeriveKeyECDH_RawRefusesInputsItCannotConsume(t *testing.T) {
	peer, _ := newECDHTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	base := func() *transport.DeriveKeyECDHRequest {
		return &transport.DeriveKeyECDHRequest{
			Backend:       "software",
			KeyID:         "ecdh-base-key",
			PeerPublicKey: peer.PublicKey().Bytes(),
			KDFAlgorithm:  "RAW",
			KeyLength:     32,
		}
	}

	for name, mutate := range map[string]func(*transport.DeriveKeyECDHRequest){
		"kdf_hash":  func(r *transport.DeriveKeyECDHRequest) { r.KDFHash = "SHA-256" },
		"kdf_salt":  func(r *transport.DeriveKeyECDHRequest) { r.KDFSalt = []byte("salt") },
		"kdf_info":  func(r *transport.DeriveKeyECDHRequest) { r.KDFInfo = []byte("shared info") },
		"kdf_label": func(r *transport.DeriveKeyECDHRequest) { r.KDFLabel = []byte("label") },
	} {
		req := base()
		mutate(req)
		_, err := svc.DeriveKeyECDH(context.Background(), req)
		require.Error(t, err, "%s supplied with RAW must be refused, not discarded", name)
		assert.True(t, errors.Is(err, ErrInvalidKeyAttributes), "%s: want ErrInvalidKeyAttributes, got %v", name, err)
	}

	// More key material than the secret holds cannot be produced without a KDF,
	// so it is an error rather than a short or padded key.
	req := base()
	req.KeyLength = 64
	_, err = svc.DeriveKeyECDH(context.Background(), req)
	require.Error(t, err, "RAW cannot stretch a 32-byte shared secret to 64 bytes")
}

// TestDeriveKeyECDH_KeyLengthExceedsMaximum proves a caller-chosen key_length
// above types.MaxDerivedKeyLength is refused as request validation before any
// backend or key lookup runs -- neither the named backend nor the named key
// need exist for this to be refused, which is itself part of what the fix
// proves: the request is rejected before ECDH or a KDF adapter ever sees it
// (go-xkms#1259).
func TestDeriveKeyECDH_KeyLengthExceedsMaximum(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	t.Run("one byte over the maximum", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
			Backend:       "software",
			KeyID:         "nonexistent-key",
			PeerPublicKey: []byte("not-a-real-point"),
			KeyLength:     types.MaxDerivedKeyLength + 1,
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
		var validation *ErrValidation
		require.True(t, errors.As(err, &validation), "want *ErrValidation, got %T", err)
	})

	t.Run("the go-xkms#1259 report's own value", func(t *testing.T) {
		_, err := svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
			Backend:       "software",
			KeyID:         "nonexistent-key",
			PeerPublicKey: []byte("not-a-real-point"),
			KeyLength:     100_000_000_000,
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
	})
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

// TestDeriveKey_KeyLengthExceedsMaximum proves a caller-chosen key_length
// above types.MaxDerivedKeyLength is refused as request validation before
// any KDF parameter assembly or base-key resolution, matching the classic
// go-xkms#1259 report: an unbounded key_length must never reach a
// pkg/crypto/kdf adapter, which would preallocate on the caller's behalf.
func TestDeriveKey_KeyLengthExceedsMaximum(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	t.Run("one byte over the maximum", func(t *testing.T) {
		_, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
			Algorithm:        "hkdf",
			InputKeyMaterial: []byte("secret-input-key-material-32byte"),
			KeyLength:        types.MaxDerivedKeyLength + 1,
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
		var validation *ErrValidation
		require.True(t, errors.As(err, &validation), "want *ErrValidation, got %T", err)
	})

	t.Run("the go-xkms#1259 report's own value", func(t *testing.T) {
		_, err := svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
			Algorithm:        "sp800-108-counter",
			InputKeyMaterial: []byte("secret-input-key-material-32byte"),
			Label:            []byte("test-label"),
			Context:          []byte("test-context"),
			KeyLength:        100_000_000_000,
		})
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidKeyAttributes))
	})
}

// --- Stub operations ---

func TestDeriveKeyECDH_BackendWithoutKeyAgreement(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdsa-key",
		Backend:       "software",
		PeerPublicKey: []byte("peer-public-key"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported))
}

func TestAttestKey_BackendWithoutAttestation(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.AttestKey(context.Background(), &transport.AttestKeyRequest{
		Backend: "software",
		KeyID:   "some-key",
	})
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

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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

// newCBCTestBackend wires a *mockKeyStore named "software" to a real
// pkg/keyprovider/symmetric Backend (in-memory storage), and pre-registers
// attrs for a generated AES-256 key under CN "cbc-key" in both the mock's
// own ListKeys registry (which findKeyAttrs reads) and the real backend
// (which SymmetricEncrypter reads) — the same attrs pointer in both places,
// since symmetric.Backend keys storage off attrs.ID().
func newCBCTestBackend(t *testing.T) (*mockKeyStore, *types.KeyAttributes, []byte) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	symBackend, err := symmetric.NewBackend(&symmetric.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	attrs := &types.KeyAttributes{
		CN:                 "cbc-key",
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.ParseStoreType("software"),
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	_, err = symBackend.GenerateSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)

	rawKey, err := symBackend.GetSymmetricKey(context.Background(), attrs)
	require.NoError(t, err)
	keyBytes, err := rawKey.Raw()
	require.NoError(t, err)

	store := newMockKeyStore("software")
	store.backend = symBackend
	store.keys[attrs.CN] = "placeholder" // ListKeys only needs the CN present
	store.keyAttrs[attrs.CN] = attrs

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": store},
		DefaultBackend: "software",
	}))

	return store, attrs, keyBytes
}

// TestEncrypt_CBC_UsesRealCBCNotGCM proves an EncryptRequest with Mode "cbc"
// routed through XKMSService.Encrypt is actually encrypted with AES-CBC, not
// silently run through the key's default AEAD (GCM) mode. A round trip
// through Encrypt+Decrypt alone would pass even if both sides silently
// agreed on the wrong cipher, so the oracle here is crypto/aes +
// crypto/cipher used directly: ciphertext the service produced is decrypted
// independently with a plain CBC decrypter and must recover the exact
// plaintext, and a ciphertext this test produces independently with a plain
// CBC encrypter must be recovered exactly by the service's Decrypt.
func TestEncrypt_CBC_UsesRealCBCNotGCM(t *testing.T) {
	_, _, keyBytes := newCBCTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	block, err := aes.NewCipher(keyBytes)
	require.NoError(t, err)

	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	// Unpadded CBC (Mode "cbc") requires block-aligned plaintext.
	plaintext := []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes = 2 blocks
	plaintext = plaintext[:32]

	// --- Encrypt direction: service output must decrypt under plain CBC. ---
	encResp, err := svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "cbc-key",
		Plaintext: plaintext,
		Mode:      "cbc",
		IV:        iv,
	})
	require.NoError(t, err)
	require.Equal(t, iv, encResp.IV)
	// GCM would append a 16-byte authentication tag; CBC output is exactly
	// the plaintext length.
	require.Len(t, encResp.Ciphertext, len(plaintext))

	oracleDecrypted := make([]byte, len(encResp.Ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(oracleDecrypted, encResp.Ciphertext)
	assert.Equal(t, plaintext, oracleDecrypted, "service Encrypt output must be recoverable with a plain CBC decrypter")

	// --- Decrypt direction: a ciphertext built with plain CBC must be
	// recovered exactly by the service. If the service instead tried GCM,
	// it would either fail the authentication tag check outright or read
	// this CBC ciphertext as ciphertext||tag and error on the split.
	oracleCiphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(oracleCiphertext, plaintext)

	decResp, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "cbc-key",
		Ciphertext: oracleCiphertext,
		Mode:       "cbc",
		IV:         iv,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResp.Plaintext)
}

// TestEncrypt_ECB_UsesRealECBNotGCM proves an EncryptRequest with Mode "ecb"
// routed through XKMSService.Encrypt is genuinely AES-ECB, closing the path
// that PKCS#11's CKM_AES_ECB travels.
//
// Before "ecb" existed as a mode, the mechanism reached this service with an
// empty Mode and was served by the key's default AEAD: two identical plaintext
// blocks came back as two different ciphertext blocks, the output did not
// match crypto/aes, and the nonce and tag needed to reverse it were discarded,
// so the token could not decrypt what it had just produced.
//
// The oracle is crypto/aes driven block by block, in both directions: the
// service's ciphertext must equal the oracle's, and a ciphertext this test
// enciphers independently must be recovered exactly by the service.
func TestEncrypt_ECB_UsesRealECBNotGCM(t *testing.T) {
	_, _, keyBytes := newCBCTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	block, err := aes.NewCipher(keyBytes)
	require.NoError(t, err)

	// Two identical blocks: the property that distinguishes ECB from every
	// chained or counter mode.
	oneBlock := bytes.Repeat([]byte{0xa5}, aes.BlockSize)
	plaintext := append(append([]byte{}, oneBlock...), oneBlock...)

	oracleCiphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(oracleCiphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}

	encResp, err := svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "cbc-key",
		Plaintext: plaintext,
		Mode:      "ecb",
	})
	require.NoError(t, err)

	assert.Equal(t, oracleCiphertext, encResp.Ciphertext,
		"service ECB output does not match crypto/aes")
	assert.Equal(t, encResp.Ciphertext[:aes.BlockSize], encResp.Ciphertext[aes.BlockSize:],
		"identical plaintext blocks did not encipher identically; this is not ECB")
	assert.Empty(t, encResp.IV, "ECB has no IV")
	assert.Empty(t, encResp.Nonce, "ECB has no nonce")
	assert.Empty(t, encResp.Tag, "ECB has no authentication tag")

	// Decrypt direction: the token must be able to reverse a ciphertext it
	// did not itself produce, which is what interoperability means and what
	// the AEAD substitution made impossible.
	decResp, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "cbc-key",
		Ciphertext: oracleCiphertext,
		Mode:       "ecb",
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResp.Plaintext)
}

// TestEncrypt_ECB_RejectsUnalignedPlaintext is the bad-input counterpart: ECB
// has no padding, so a plaintext that is not a whole number of AES blocks must
// be refused with a typed error rather than panicking inside crypto/cipher or
// being silently padded.
func TestEncrypt_ECB_RejectsUnalignedPlaintext(t *testing.T) {
	newCBCTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "cbc-key",
		Plaintext: bytes.Repeat([]byte{0x01}, aes.BlockSize+1),
		Mode:      "ecb",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, symmetric.ErrPlaintextNotBlockAligned))
}

// TestEncrypt_UnrecognizedMode_TypedErrorNotGCMFallback proves an
// unrecognized Mode string is rejected with symmetric.ErrUnsupportedCipherMode
// rather than silently encrypting under the key's default AEAD mode — the
// exact defect this task's Mode/IV wiring closes for the service layer.
func TestEncrypt_UnrecognizedMode_TypedErrorNotGCMFallback(t *testing.T) {
	newCBCTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "cbc-key",
		Plaintext: []byte("0123456789ABCDEF"),
		Mode:      "ofb", // not one of "", "cbc", "cbc-pad"
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, symmetric.ErrUnsupportedCipherMode))
}

// TestEncrypt_RSA_PKCS1v15_RoundTrip proves the asymmetric Encrypt fallback
// this task adds actually works: wrapping a key under an RSA KEK via
// Encrypt was previously impossible for every caller (the only branch
// required types.SymmetricKeyProvider). The oracle is Decrypt, the
// pre-existing and already-correct asymmetric path (PKCS#1 v1.5 by
// default): if Encrypt's new branch used a different scheme than Decrypt
// expects, this round trip would fail even though Encrypt itself reported
// success.
// TestEncrypt_RSA_PKCS1v15_Refused_Default is the failure test for the
// crypto audit's PKCS#1 v1.5 Encrypt finding: Encrypt's asymmetric fallback
// must refuse to run PKCS#1 v1.5 unless the operator has opted into
// crypto.allow_legacy_key_wrap. Without a symmetric backend and with no
// legacy opt-in, a caller who used to get a Bleichenbacher-oracle-shaped
// ciphertext back now gets a typed refusal that names EncryptAsym instead.
func TestEncrypt_RSA_PKCS1v15_Refused_Default(t *testing.T) {
	previous := types.AllowLegacyKeyWrap()
	types.SetAllowLegacyKeyWrap(false)
	t.Cleanup(func() { types.SetAllowLegacyKeyWrap(previous) })

	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "encrypt-rsa-pkcs1v15-refused",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "encrypt-rsa-pkcs1v15-refused",
		Plaintext: []byte("must not be PKCS#1 v1.5 encrypted"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLegacyWrapDisabled))
}

// TestEncrypt_RSA_PKCS1v15_RoundTrip is the success test: with
// crypto.allow_legacy_key_wrap enabled, Encrypt's asymmetric fallback still
// performs PKCS#1 v1.5 and Decrypt still reads it back.
func TestEncrypt_RSA_PKCS1v15_RoundTrip(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}

	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "encrypt-rsa-pkcs1v15",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	plaintext := []byte("wrap me under an RSA KEK")
	resp, err := svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "encrypt-rsa-pkcs1v15",
		Plaintext: plaintext,
	})
	if types.FIPSMode() {
		// This RPC's asymmetric fallback deliberately mirrors PKCS#11's
		// CKM_RSA_PKCS mechanism -- raw PKCS#1 v1.5 encryption, no OAEP
		// digest involved -- for the local-fallback KEK-wrap path (see
		// servicer_crypto.go's Encrypt). crypto/rsa refuses that
		// construction outright under GODEBUG=fips140=only.
		require.Error(t, err)
		return
	}
	require.NoError(t, err)
	require.NotEmpty(t, resp.Ciphertext)

	decResp, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "encrypt-rsa-pkcs1v15",
		Ciphertext: resp.Ciphertext,
	})
	require.NoError(t, err)
	assert.Equal(t, plaintext, decResp.Plaintext)
}

// TestEncrypt_RSA_PlaintextTooLarge proves the asymmetric Encrypt fallback
// rejects plaintext that does not fit PKCS#1 v1.5 padding for the key size,
// rather than silently truncating it. A 2048-bit (256-byte) RSA key can
// carry at most 256-11=245 bytes under PKCS#1 v1.5.
func TestEncrypt_RSA_PlaintextTooLarge(t *testing.T) {
	if !allowLegacyWrap(t) {
		return
	}

	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "encrypt-rsa-toolarge",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	oversized := make([]byte, 246)
	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     "encrypt-rsa-toolarge",
		Plaintext: oversized,
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

// TestEncryptAsym_SHA1OAEPRejected verifies that RSA-OAEP with SHA-1 is
// rejected with ErrWeakOAEPHash (F-14 security policy).
func TestEncryptAsym_SHA1OAEPRejected(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "oaep-sha1-reject-key",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	_, err = svc.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "oaep-sha1-reject-key",
		Plaintext: []byte("secret"),
		Hash:      "sha1",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWeakOAEPHash), "expected ErrWeakOAEPHash, got: %v", err)
}

// TestEncryptAsym_SHA256OAEPAccepted verifies that RSA-OAEP with SHA-256
// continues to succeed after the F-14 policy change.
func TestEncryptAsym_SHA256OAEPAccepted(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "oaep-sha256-accept-key",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	resp, err := svc.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "oaep-sha256-accept-key",
		Plaintext: []byte("secret"),
		Hash:      "sha256",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Ciphertext)
}

func TestServicerDecrypt_NonDecrypterKey(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// ECDSA keys don't implement crypto.Decrypter, so asymmetric decrypt
	// fallback should fail
	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateECDSA(context.Background(), &types.KeyAttributes{
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

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "decrypt-oaep-mismatch",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	// Decrypt passes nil opts, so the backend uses PKCS#1 v1.5. Feed it a
	// ciphertext whose plaintext block cannot be valid v1.5, and the refusal is
	// certain.
	//
	// This test used to encrypt with OAEP and rely on the v1.5 unpadding of the
	// resulting block failing. That is only PROBABLE, not certain: RSA-decrypting
	// an OAEP ciphertext under v1.5 yields an essentially random block, and a
	// random block satisfies v1.5's leading 0x00 0x02 roughly 1 time in 65,536.
	// When it did, no error was returned and the test failed with "An error is
	// expected but got nil", reddening CI for whichever PR was in the queue
	// (go-xkms#345). A fresh key and fresh OAEP padding per run made it
	// unreproducible on demand.
	//
	// The second byte is the whole game: RFC 8017 §7.2.2 requires an encryption
	// block to begin 0x00 0x02, so 0x01 here can never unpad. Encrypting the
	// block raw (c = m^e mod n) is what makes the plaintext the decrypter sees
	// exactly the block chosen here rather than something random.
	privKey, err := software.GetKey(ctx, &types.KeyAttributes{CN: "decrypt-oaep-mismatch"})
	require.NoError(t, err)
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	require.True(t, ok, "the mock keystore returns the generated key")

	modulusLen := rsaKey.Size()
	block := make([]byte, modulusLen)
	block[0] = 0x00
	block[1] = 0x01 // v1.5 demands 0x02 for an encryption block
	for i := 2; i < modulusLen; i++ {
		block[i] = 0xAB
	}
	// rawEncrypt applies the public operation directly, so the plaintext the
	// decrypter sees is the block chosen here rather than something random.
	// m < n holds in both uses below because each block's leading byte is zero.
	rawEncrypt := func(block []byte) []byte {
		c := new(big.Int).Exp(
			new(big.Int).SetBytes(block),
			big.NewInt(int64(rsaKey.E)),
			rsaKey.N,
		)
		return c.FillBytes(make([]byte, modulusLen))
	}

	_, err = svc.Decrypt(ctx, &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "decrypt-oaep-mismatch",
		Ciphertext: rawEncrypt(block),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDecryptionFailed))

	// The counterweight: a correctly v1.5-padded block must still decrypt.
	// Without it the refusal above could pass by rejecting everything, which is
	// exactly how a decrypt path that always errored would slip through.
	//
	// The block is assembled here rather than via rsa.EncryptPKCS1v15, which is
	// deprecated: 0x00 0x02, then non-zero padding, then a 0x00 separator, then
	// the message (RFC 8017 §7.2.1). Building it keeps both halves of this test
	// on the same raw-encrypt path, so the only difference between the refused
	// block and the accepted one is the byte under test.
	message := []byte("secret message")
	valid := make([]byte, modulusLen)
	valid[0] = 0x00
	valid[1] = 0x02
	for i := 2; i < modulusLen-len(message)-1; i++ {
		valid[i] = 0xFF // padding must be non-zero
	}
	valid[modulusLen-len(message)-1] = 0x00
	copy(valid[modulusLen-len(message):], message)

	decResp, err := svc.Decrypt(ctx, &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "decrypt-oaep-mismatch",
		Ciphertext: rawEncrypt(valid),
	})
	if types.FIPSMode() {
		// The counterweight itself needs PKCS#1 v1.5 decryption to
		// succeed, which crypto/rsa refuses outright under
		// GODEBUG=fips140=only (see TestEncrypt_RSA_PKCS1v15_RoundTrip);
		// there is no valid v1.5 block this fixture can decrypt in that
		// mode.
		require.Error(t, err)
		return
	}
	require.NoError(t, err)
	assert.Equal(t, message, decResp.Plaintext)
}

// --- Backend capability refusal classification (ErrOperationNotSupported) ---
//
// TPM2_Sign builds its own DigestInfo and rejects a caller-supplied one, and
// TPM2_RSA_Decrypt is refused outright on a sign-only key. pkg/backend/tpm2
// raises tpm2backend.ErrUnsupportedOperation for both. Other backends (PKCS#11's
// Decrypter/RotateKey, Azure Key Vault, GCP KMS, AWS KMS, Vault, software) join
// the one sentinel most of them share, backend.ErrOperationNotSupported, into
// their own errors for the same kind of refusal. Both must reach the caller as
// xkms.ErrOperationNotSupported, which is what lets the gRPC layer answer
// codes.Unimplemented and the PKCS#11 module answer CKR_FUNCTION_NOT_SUPPORTED
// instead of a generic fault. The tests below reproduce each shape without a
// real TPM or HSM, and each has a negative counterpart proving an unrelated
// failure keeps its original classification.

// refusingSigner is a crypto.Signer whose Sign call always fails with err,
// standing in for a hardware backend's Sign method discovering a capability
// boundary (or any other fault) mid-operation.
type refusingSigner struct {
	pub crypto.PublicKey
	err error
}

func (s *refusingSigner) Public() crypto.PublicKey { return s.pub }

func (s *refusingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

// signerOverrideBackend wraps a Backend and substitutes the crypto.Signer its
// Signer method returns, so a test can make a real key's Sign call fail with
// an injected error without a real TPM or HSM.
type signerOverrideBackend struct {
	Backend
	signer crypto.Signer
}

func (b *signerOverrideBackend) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return b.signer, nil
}

// TestSign_ClassifiesTPM2RawSigningCapabilityRefusalAsNotSupported reproduces
// TPM2_Sign's refusal of a caller-supplied DigestInfo: pkg/backend/tpm2 joins
// that refusal onto tpm2backend.ErrUnsupportedOperation. Swapping in a signer
// that fails the same way, on a real RSA key, proves the service layer
// classifies it as ErrOperationNotSupported without needing a TPM.
func TestSign_ClassifiesTPM2RawSigningCapabilityRefusalAsNotSupported(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	priv, err := software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "sign-rsa-refuse",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)
	realSigner, ok := priv.(crypto.Signer)
	require.True(t, ok)

	require.NoError(t, RegisterServiceBackend("software", &signerOverrideBackend{
		Backend: software,
		signer:  &refusingSigner{pub: realSigner.Public(), err: tpm2backend.ErrUnsupportedOperation},
	}))

	_, err = svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-rsa-refuse",
		Data:    []byte("hello world"),
		Hash:    "SHA-256",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported),
		"a TPM2 raw-signing capability refusal must classify as ErrOperationNotSupported so it reaches gRPC as codes.Unimplemented and the PKCS#11 module as CKR_FUNCTION_NOT_SUPPORTED, got: %v", err)
}

// TestSign_UnrelatedSigningFailureIsNotClassifiedAsNotSupported is the
// mutation guard: a fault that is not a known capability sentinel (a severed
// HSM session, say) must keep its original ErrSigningFailed classification.
// Classifying every signing failure as "not supported" would be worse than
// today's generic fault, because a caller who retries a real fault believing
// the operation is categorically impossible will retry forever.
func TestSign_UnrelatedSigningFailureIsNotClassifiedAsNotSupported(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	priv, err := software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "sign-rsa-fault",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)
	realSigner, ok := priv.(crypto.Signer)
	require.True(t, ok)

	require.NoError(t, RegisterServiceBackend("software", &signerOverrideBackend{
		Backend: software,
		signer:  &refusingSigner{pub: realSigner.Public(), err: errors.New("hsm session lost")},
	}))

	_, err = svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "sign-rsa-fault",
		Data:    []byte("hello world"),
		Hash:    "SHA-256",
	})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrOperationNotSupported),
		"an unrelated fault must not be classified as a capability refusal, got: %v", err)
	assert.True(t, errors.Is(err, ErrSigningFailed))
}

// decrypterRefusalBackend wraps a Backend and makes Decrypter itself refuse
// with an injected error, standing in for PKCS#11's Backend.Decrypter, which
// returns backend.ErrOperationNotSupported when a key's signer does not also
// implement crypto.Decrypter (e.g. a sign-only key).
type decrypterRefusalBackend struct {
	Backend
	err error
}

func (b *decrypterRefusalBackend) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, b.err
}

// TestDecrypt_ClassifiesCapabilityRefusalGettingDecrypterAsNotSupported
// reproduces PKCS#11's real Backend.Decrypter refusal (backend.go: "key does
// not support decryption") for a sign-only key.
func TestDecrypt_ClassifiesCapabilityRefusalGettingDecrypterAsNotSupported(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "decrypt-refuse-get",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	require.NoError(t, RegisterServiceBackend("software", &decrypterRefusalBackend{
		Backend: software,
		err:     backend.ErrOperationNotSupported,
	}))

	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "decrypt-refuse-get",
		Ciphertext: []byte("irrelevant"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported),
		"a backend.ErrOperationNotSupported refusal getting a decrypter must classify as ErrOperationNotSupported, got: %v", err)
}

// refusingDecrypter is a crypto.Decrypter whose Decrypt call always fails
// with err, standing in for a hardware backend's Decrypt method discovering a
// capability boundary (or any other fault) mid-operation.
type refusingDecrypter struct {
	pub crypto.PublicKey
	err error
}

func (d *refusingDecrypter) Public() crypto.PublicKey { return d.pub }

func (d *refusingDecrypter) Decrypt(io.Reader, []byte, crypto.DecrypterOpts) ([]byte, error) {
	return nil, d.err
}

// decrypterOverrideBackend wraps a Backend and substitutes the
// crypto.Decrypter its Decrypter method returns, so a test can make a real
// key's Decrypt call fail with an injected error without a real TPM or HSM.
type decrypterOverrideBackend struct {
	Backend
	decrypter crypto.Decrypter
}

func (b *decrypterOverrideBackend) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return b.decrypter, nil
}

// TestDecrypt_ClassifiesTPM2CapabilityRefusalDuringDecryptAsNotSupported
// reproduces TPM2_RSA_Decrypt's refusal on a sign-only key, discovered inside
// the decrypt call itself rather than while resolving the decrypter.
func TestDecrypt_ClassifiesTPM2CapabilityRefusalDuringDecryptAsNotSupported(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	priv, err := software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "decrypt-tpm2-refuse",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)
	realSigner, ok := priv.(crypto.Signer)
	require.True(t, ok)

	require.NoError(t, RegisterServiceBackend("software", &decrypterOverrideBackend{
		Backend:   software,
		decrypter: &refusingDecrypter{pub: realSigner.Public(), err: tpm2backend.ErrUnsupportedOperation},
	}))

	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "decrypt-tpm2-refuse",
		Ciphertext: []byte("irrelevant"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported),
		"a TPM2 raw-decrypt capability refusal must classify as ErrOperationNotSupported, got: %v", err)
}

// TestDecrypt_UnrelatedDecryptionFailureIsNotClassifiedAsNotSupported is the
// mutation guard for the decrypt path: an unrelated fault must keep its
// original ErrDecryptionFailed classification rather than becoming
// ErrOperationNotSupported.
func TestDecrypt_UnrelatedDecryptionFailureIsNotClassifiedAsNotSupported(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	priv, err := software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "decrypt-fault",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)
	realSigner, ok := priv.(crypto.Signer)
	require.True(t, ok)

	require.NoError(t, RegisterServiceBackend("software", &decrypterOverrideBackend{
		Backend:   software,
		decrypter: &refusingDecrypter{pub: realSigner.Public(), err: errors.New("hsm session lost")},
	}))

	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "decrypt-fault",
		Ciphertext: []byte("irrelevant"),
	})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrOperationNotSupported),
		"an unrelated fault must not be classified as a capability refusal, got: %v", err)
	assert.True(t, errors.Is(err, ErrDecryptionFailed))
}

// encryptRefusalEncrypter wraps a working types.SymmetricEncrypter and makes
// Encrypt fail with an injected error, standing in for hardware that refuses
// an encryption mode or parameter combination it does not implement.
type encryptRefusalEncrypter struct {
	types.SymmetricEncrypter
	err error
}

func (e *encryptRefusalEncrypter) Encrypt(_ []byte, _ *types.EncryptOptions) (*types.EncryptedData, error) {
	return nil, e.err
}

// encryptRefusalProvider wraps a working types.SymmetricKeyProvider and
// returns an encryptRefusalEncrypter from SymmetricEncrypter, so a test can
// make a real symmetric key's Encrypt call fail with an injected error.
type encryptRefusalProvider struct {
	types.SymmetricKeyProvider
	err error
}

func (p *encryptRefusalProvider) SymmetricEncrypter(ctx context.Context, attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
	real, err := p.SymmetricKeyProvider.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, err
	}
	return &encryptRefusalEncrypter{SymmetricEncrypter: real, err: p.err}, nil
}

// TestEncrypt_ClassifiesSymmetricBackendCapabilityRefusalAsNotSupported
// proves a symmetric backend's backend.ErrOperationNotSupported refusal
// (the sentinel Azure Key Vault, GCP KMS, AWS KMS, Vault and the software
// backend all join into their own errors for exactly this) reaches the
// caller as ErrOperationNotSupported.
func TestEncrypt_ClassifiesSymmetricBackendCapabilityRefusalAsNotSupported(t *testing.T) {
	store, attrs, _ := newCBCTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	realProvider, ok := store.backend.(types.SymmetricKeyProvider)
	require.True(t, ok)
	store.backend = &encryptRefusalProvider{SymmetricKeyProvider: realProvider, err: backend.ErrOperationNotSupported}

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     attrs.CN,
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported),
		"a backend.ErrOperationNotSupported refusal from a symmetric encrypter must classify as ErrOperationNotSupported, got: %v", err)
}

// TestEncrypt_UnrelatedEncryptionFailureIsNotClassifiedAsNotSupported is the
// mutation guard for the symmetric encrypt path.
func TestEncrypt_UnrelatedEncryptionFailureIsNotClassifiedAsNotSupported(t *testing.T) {
	store, attrs, _ := newCBCTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	realProvider, ok := store.backend.(types.SymmetricKeyProvider)
	require.True(t, ok)
	store.backend = &encryptRefusalProvider{SymmetricKeyProvider: realProvider, err: errors.New("hsm session lost")}

	_, err = svc.Encrypt(context.Background(), &transport.EncryptRequest{
		Backend:   "software",
		KeyID:     attrs.CN,
		Plaintext: []byte("data"),
	})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrOperationNotSupported),
		"an unrelated fault must not be classified as a capability refusal, got: %v", err)
	assert.True(t, errors.Is(err, ErrEncryptionFailed))
}

// derivationRefusalProvider wraps a working types.SymmetricKeyDeriver and
// makes DeriveFromSymmetricKey fail with an injected error, standing in for a
// backend that discovers, while running the KDF, that it is a genuine
// capability boundary rather than a fault.
type derivationRefusalProvider struct {
	types.SymmetricKeyDeriver
	err error
}

func (p *derivationRefusalProvider) DeriveFromSymmetricKey(context.Context, *types.KeyAttributes, *kdf.KDFParams) ([]byte, error) {
	return nil, p.err
}

// TestDeriveKey_ClassifiesStoredKeyBackendCapabilityRefusalAsNotSupported
// proves the reclassification reaches through deriveBaseKeyMaterial's own
// ErrOperationWrap{Sentinel: ErrOperationFailed}: DeriveKey must still detect
// the capability sentinel in the wrapped error's chain and report
// ErrOperationNotSupported, not the generic key-derivation failure
// deriveFromStoredKey otherwise reports.
func TestDeriveKey_ClassifiesStoredKeyBackendCapabilityRefusalAsNotSupported(t *testing.T) {
	store, attrs, _ := newCBCTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	realDeriver, ok := store.backend.(types.SymmetricKeyDeriver)
	require.True(t, ok)
	store.backend = &derivationRefusalProvider{SymmetricKeyDeriver: realDeriver, err: tpm2backend.ErrUnsupportedOperation}

	_, err = svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend: "software",
		KeyID:   attrs.CN,
		Hash:    "SHA-256",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrOperationNotSupported),
		"a capability refusal deriving from a stored key must classify as ErrOperationNotSupported, got: %v", err)
}

// TestDeriveKey_UnrelatedDerivationFailureIsNotClassifiedAsNotSupported is
// the mutation guard for the stored-key derivation path.
func TestDeriveKey_UnrelatedDerivationFailureIsNotClassifiedAsNotSupported(t *testing.T) {
	store, attrs, _ := newCBCTestBackend(t)
	svc, err := Get()
	require.NoError(t, err)

	realDeriver, ok := store.backend.(types.SymmetricKeyDeriver)
	require.True(t, ok)
	store.backend = &derivationRefusalProvider{SymmetricKeyDeriver: realDeriver, err: errors.New("hsm session lost")}

	_, err = svc.DeriveKey(context.Background(), &transport.DeriveKeyRequest{
		Backend: "software",
		KeyID:   attrs.CN,
		Hash:    "SHA-256",
	})
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrOperationNotSupported),
		"an unrelated fault must not be classified as a capability refusal, got: %v", err)
}

// TestEncryptAsym_OAEPLabelRoundTrips pins RFC 8017's encoding parameter L
// through both halves of an OAEP operation.
//
// The label is a PKCS#11 caller's CK_RSA_PKCS_OAEP_PARAMS.pSourceData. Decrypt
// has always forwarded it; EncryptAsym had nowhere to put it and encrypted
// under nil, so the two halves used different labels and no round trip that
// named a label could ever close. Nothing reported the substitution: the
// encryption returned CKR_OK and the ciphertext was simply undecryptable, by
// this token and by any peer.
func TestEncryptAsym_OAEPLabelRoundTrips(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = software.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:            "oaep-label",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	const label = "tenant-42"
	plaintext := []byte("secret message")

	encrypted, err := svc.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{
		Backend:   "software",
		KeyID:     "oaep-label",
		Plaintext: plaintext,
		Hash:      "SHA-256",
		Label:     []byte(label),
	})
	require.NoError(t, err)

	decrypted, err := svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "oaep-label",
		Ciphertext: encrypted.Ciphertext,
		Padding:    "oaep",
		Hash:       "SHA-256",
		Label:      []byte(label),
	})
	require.NoError(t, err, "an OAEP round trip under one label must close")
	assert.Equal(t, plaintext, decrypted.Plaintext)

	// The label is bound into the ciphertext, so decrypting under a different
	// one must fail. Without this, an implementation that ignored the label on
	// both halves would satisfy the assertion above.
	_, err = svc.Decrypt(context.Background(), &transport.DecryptRequest{
		Backend:    "software",
		KeyID:      "oaep-label",
		Ciphertext: encrypted.Ciphertext,
		Padding:    "oaep",
		Hash:       "SHA-256",
		Label:      []byte("a-different-label"),
	})
	require.Error(t, err, "the label must be authenticated, not merely carried")
}

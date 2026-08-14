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

package xkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// rsaPublicKeyFor returns the public half of a generated RSA key so a test can
// check a signature against crypto/rsa rather than against XKMSService.Verify.
// Verifying with the service's own inverse cannot distinguish "signed the
// right bytes" from "signed the wrong bytes consistently".
func rsaPublicKeyFor(t *testing.T, store *mockKeyStore, cn string) *rsa.PublicKey {
	t.Helper()
	signer, err := store.Signer(context.Background(), &types.KeyAttributes{CN: cn})
	require.NoError(t, err)
	pub, ok := signer.Public().(*rsa.PublicKey)
	require.True(t, ok, "expected an RSA public key")
	return pub
}

// TestSign_PSS_DataIsDigest_SignsTheSuppliedDigest is the service-layer half of
// the CKM_RSA_PKCS_PSS double-hash fix.
//
// SignRequest.Hash names the digest -- RSASSA-PSS needs it for MGF1 and the
// salt length (RFC 8017 section 9.1) -- while DataIsDigest says the data is
// already that digest and must not be hashed (PKCS#11 v3.2 section 6.1.10).
// Before the split, naming the hash was read as an instruction to apply it.
func TestSign_PSS_DataIsDigest_SignsTheSuppliedDigest(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateRSA(ctx, &types.KeyAttributes{
		CN:            "pss-prehashed",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	message := []byte("the application hashed this itself")
	digest := sha256.Sum256(message)

	resp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend:      "software",
		KeyID:        "pss-prehashed",
		Data:         digest[:],
		Hash:         "SHA-256",
		Padding:      "pss",
		SaltLength:   32,
		DataIsDigest: true,
	})
	require.NoError(t, err)

	pub := rsaPublicKeyFor(t, software, "pss-prehashed")
	opts := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}

	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], resp.Signature, opts); err != nil {
		t.Errorf("signature does not verify over the supplied digest: %v", err)
	}

	doubleHashed := sha256.Sum256(digest[:])
	if err := rsa.VerifyPSS(pub, crypto.SHA256, doubleHashed[:], resp.Signature, opts); err == nil {
		t.Fatal("signature verifies over SHA-256(digest): the service hashed the digest again")
	}
}

// TestSign_PSS_WithoutDataIsDigest_HashesTheMessage is the complement: with the
// flag clear, the service must hash. Both behaviours have to be reachable, or
// the flag has merely moved the bug rather than fixed it.
func TestSign_PSS_WithoutDataIsDigest_HashesTheMessage(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateRSA(ctx, &types.KeyAttributes{
		CN:            "pss-hashes",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	message := []byte("let the service hash this")

	resp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend:    "software",
		KeyID:      "pss-hashes",
		Data:       message,
		Hash:       "SHA-256",
		Padding:    "pss",
		SaltLength: 32,
	})
	require.NoError(t, err)

	pub := rsaPublicKeyFor(t, software, "pss-hashes")
	opts := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}
	digest := sha256.Sum256(message)

	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], resp.Signature, opts); err != nil {
		t.Fatalf("signature does not verify over SHA-256(message): %v", err)
	}
}

// TestVerify_PSS_DataIsDigest_RoundTrip proves Sign and Verify read the flag
// the same way. If they disagree, a signature this service produced is
// reported invalid by this service, which is the worst possible failure mode
// because it looks like key or data corruption.
func TestVerify_PSS_DataIsDigest_RoundTrip(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateRSA(ctx, &types.KeyAttributes{
		CN:            "pss-roundtrip",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("round trip"))

	signResp, err := svc.Sign(ctx, &transport.SignRequest{
		Backend:      "software",
		KeyID:        "pss-roundtrip",
		Data:         digest[:],
		Hash:         "SHA-256",
		Padding:      "pss",
		SaltLength:   32,
		DataIsDigest: true,
	})
	require.NoError(t, err)

	verifyResp, err := svc.Verify(ctx, &transport.VerifyRequest{
		Backend:      "software",
		KeyID:        "pss-roundtrip",
		Data:         digest[:],
		Signature:    signResp.Signature,
		Hash:         "SHA-256",
		Padding:      "pss",
		SaltLength:   32,
		DataIsDigest: true,
	})
	require.NoError(t, err)
	require.True(t, verifyResp.Valid, "PSS signature over a supplied digest did not verify")

	// A verify that forgets the flag hashes the digest again and must report
	// the signature invalid rather than silently accepting it.
	mismatched, err := svc.Verify(ctx, &transport.VerifyRequest{
		Backend:    "software",
		KeyID:      "pss-roundtrip",
		Data:       digest[:],
		Signature:  signResp.Signature,
		Hash:       "SHA-256",
		Padding:    "pss",
		SaltLength: 32,
	})
	require.NoError(t, err)
	require.False(t, mismatched.Valid, "a verify that re-hashed the digest accepted the signature")
}

// TestSign_DataIsDigest_WrongDigestLengthRejected is the bad-input case.
//
// DataIsDigest plus a named hash is an assertion that these bytes are that
// function's output, and the length is the part of the assertion the service
// can check. Refusing here is more useful than letting crypto/rsa report the
// same condition from inside a signing routine, and for ECDSA -- which
// truncates whatever it is handed (SEC 1 v2.0 section 4.1.3) -- it is the
// difference between an error and a valid signature over the wrong bytes.
func TestSign_DataIsDigest_WrongDigestLengthRejected(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateRSA(ctx, &types.KeyAttributes{
		CN:            "prehash-badlen",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	// 20 bytes is a SHA-1 digest, not the SHA-256 the request names.
	_, err = svc.Sign(ctx, &transport.SignRequest{
		Backend:      "software",
		KeyID:        "prehash-badlen",
		Data:         make([]byte, 20),
		Hash:         "SHA-256",
		Padding:      "pss",
		SaltLength:   32,
		DataIsDigest: true,
	})
	require.Error(t, err, "Sign accepted a 20-byte digest labelled SHA-256")

	var validationErr *ErrValidation
	require.ErrorAs(t, err, &validationErr)
	require.ErrorIs(t, err, ErrInvalidHashFunction)
}

// TestVerify_DataIsDigest_WrongDigestLengthRejected mirrors the Sign case: the
// same assertion is checked on the verify side, so a caller cannot smuggle a
// mislabelled digest past verification either.
func TestVerify_DataIsDigest_WrongDigestLengthRejected(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = software.GenerateRSA(ctx, &types.KeyAttributes{
		CN:            "prehash-verify-badlen",
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	_, err = svc.Verify(ctx, &transport.VerifyRequest{
		Backend:      "software",
		KeyID:        "prehash-verify-badlen",
		Data:         make([]byte, 48),
		Signature:    make([]byte, 256),
		Hash:         "SHA-256",
		Padding:      "pss",
		DataIsDigest: true,
	})
	require.Error(t, err, "Verify accepted a 48-byte digest labelled SHA-256")
	require.ErrorIs(t, err, ErrInvalidHashFunction)
}

// TestCheckSuppliedDigestLength_NoHashIdentityIsUnchecked pins the one case
// the length check must not fire on: the "NONE" sentinel, where no hash
// function is involved and the caller's bytes are a DigestInfo or a digest of
// its own choosing. Checking a length there would break raw CKM_RSA_PKCS.
func TestCheckSuppliedDigestLength_NoHashIdentityIsUnchecked(t *testing.T) {
	if err := checkSuppliedDigestLength(true, crypto.Hash(0), make([]byte, 51)); err != nil {
		t.Fatalf("checkSuppliedDigestLength rejected a DigestInfo under the NONE sentinel: %v", err)
	}
	if err := checkSuppliedDigestLength(false, crypto.SHA256, make([]byte, 7)); err != nil {
		t.Fatalf("checkSuppliedDigestLength fired when DataIsDigest was clear: %v", err)
	}
	if err := checkSuppliedDigestLength(true, crypto.SHA256, make([]byte, 32)); err != nil {
		t.Fatalf("checkSuppliedDigestLength rejected a correct SHA-256 digest: %v", err)
	}
	if err := checkSuppliedDigestLength(true, crypto.SHA256, make([]byte, 31)); err == nil {
		t.Fatal("checkSuppliedDigestLength accepted a 31-byte SHA-256 digest")
	}
}

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

package module

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// rsaSigningTransport is a spec-faithful backend for the sign/verify half of
// PKCS11Transport, backed by a real RSA key.
//
// It exists so a test can drive C_Sign end to end and then check the result
// against crypto/rsa directly, rather than against this module's own Verify.
// It implements exactly the contract transport.SignRequest documents: Hash
// names the digest, DataIsDigest says whether to apply it, and Padding selects
// PKCS#1 v1.5 or PSS. Anything it gets wrong shows up as a signature
// crypto/rsa rejects.
type rsaSigningTransport struct {
	*mockClient
	key *rsa.PrivateKey
}

// Compile-time check: rsaSigningTransport satisfies PKCS11Transport.
//
// Every test double in this package carries this assertion so that adding a
// method to the interface fails here, at the definition, rather than at each
// place the double is passed to WithClient or NewCryptoManager.
var _ PKCS11Transport = (*rsaSigningTransport)(nil)

func newRSASigningTransport(t *testing.T) *rsaSigningTransport {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return &rsaSigningTransport{mockClient: newMockClient(), key: key}
}

// errTestUnsupportedHash is returned for a hash name this transport does not
// implement, so a typo in a test surfaces instead of silently signing under
// SHA-256.
var errTestUnsupportedHash = errors.New("pkcs11test transport: unsupported hash")

// resolveHash mirrors xkms.ResolveHash: empty means the SHA-256 default,
// "NONE" means no hash function is involved at all.
func resolveHash(name string) (crypto.Hash, error) {
	switch strings.ToUpper(name) {
	case "":
		return crypto.SHA256, nil
	case "NONE":
		return crypto.Hash(0), nil
	case "SHA-256":
		return crypto.SHA256, nil
	case "SHA-384":
		return crypto.SHA384, nil
	case "SHA-512":
		return crypto.SHA512, nil
	default:
		return 0, errTestUnsupportedHash
	}
}

func (r *rsaSigningTransport) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	r.signCalled = true
	r.lastSignReq = req

	h, err := resolveHash(req.Hash)
	if err != nil {
		return nil, err
	}

	// The whole point of the contract: hash only when a hash was named AND
	// the caller did not say the data is already that digest.
	digest := req.Data
	if h != 0 && !req.DataIsDigest {
		hasher := h.New()
		hasher.Write(req.Data)
		digest = hasher.Sum(nil)
	}

	var opts crypto.SignerOpts = h
	if strings.EqualFold(req.Padding, "pss") {
		opts = &rsa.PSSOptions{Hash: h, SaltLength: req.SaltLength}
	}

	sig, err := r.key.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}
	return &transport.SignResponse{Signature: sig, Algorithm: "RSA"}, nil
}

// TestSignPSS_SignsTheCallerSuppliedDigest is the regression test for the
// CKM_RSA_PKCS_PSS double-hash defect.
//
// PKCS#11 v3.2 section 6.1.10 defines the input to CKM_RSA_PKCS_PSS as a hash
// value the application already computed: the mechanism "does not compute a
// hash value on the message to be signed". The module used to send that digest
// with only a hash name attached, which the backend read as an instruction to
// hash it, so the signature covered SHA-256(digest) instead of digest.
//
// The negative assertion is the load-bearing one. A signature over
// SHA-256(digest) still round-trips through this module's own Verify, so only
// checking against an outside verifier over the right input distinguishes the
// two.
func TestSignPSS_SignsTheCallerSuppliedDigest(t *testing.T) {
	client := newRSASigningTransport(t)
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "test-backend"})

	message := []byte("the message the application hashed itself")
	digest := sha256.Sum256(message)

	mech := &Mechanism{
		Type: CKM_RSA_PKCS_PSS,
		TypedParameter: &RSAPSSParams{
			HashAlg: CKM_SHA256,
			MGF:     CKG_MGF1_SHA256,
			SaltLen: 32,
		},
	}

	op, err := cm.SignInit(mech, 1, "key-1", "test-backend")
	if err != nil {
		t.Fatalf("SignInit: %v", err)
	}

	sig, err := cm.Sign(context.Background(), op, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub := &client.key.PublicKey
	pssOpts := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}

	// Positive: the signature verifies over the digest the caller supplied.
	// Reported rather than fatal so the negative below is always evaluated --
	// under the double-hashing defect both fire, and seeing both is what
	// identifies the failure as a second hash rather than a broken signature.
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, pssOpts); err != nil {
		t.Errorf("signature does not verify over the caller-supplied digest: %v", err)
	}

	// Negative: it must NOT verify over SHA-256 of that digest. That is what
	// the double-hashing bug produced, and it is invisible to a round trip
	// through this module alone.
	doubleHashed := sha256.Sum256(digest[:])
	if err := rsa.VerifyPSS(pub, crypto.SHA256, doubleHashed[:], sig, pssOpts); err == nil {
		t.Fatal("signature verifies over SHA-256(digest): the module hashed the caller's digest a second time")
	}

	// The request itself must carry both halves of the contract: the digest
	// identity PSS needs for MGF1, and the instruction not to apply it.
	req := client.lastSignReq
	if req.Hash != "SHA-256" {
		t.Errorf("SignRequest.Hash = %q, want %q (PSS needs the digest identity for MGF1)", req.Hash, "SHA-256")
	}
	if !req.DataIsDigest {
		t.Error("SignRequest.DataIsDigest = false, want true for CKM_RSA_PKCS_PSS")
	}
	if req.SaltLength != 32 {
		t.Errorf("SignRequest.SaltLength = %d, want 32", req.SaltLength)
	}
}

// TestSignPSS_HashPrefixedMechanismHashesTheMessage is the other side of the
// same contract: CKM_SHA256_RSA_PKCS_PSS does compute the digest itself
// (PKCS#11 v3.2 section 6.1.11), so the module must hand over the message and
// leave DataIsDigest clear. Marking every PSS mechanism pre-hashed would sign
// the raw message as if it were a digest, which is the mirror-image defect.
func TestSignPSS_HashPrefixedMechanismHashesTheMessage(t *testing.T) {
	client := newRSASigningTransport(t)
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "test-backend"})

	message := []byte("a message the token is expected to hash")

	mech := &Mechanism{
		Type: CKM_SHA256_RSA_PKCS_PSS,
		TypedParameter: &RSAPSSParams{
			HashAlg: CKM_SHA256,
			MGF:     CKG_MGF1_SHA256,
			SaltLen: 32,
		},
	}

	op, err := cm.SignInit(mech, 1, "key-1", "test-backend")
	if err != nil {
		t.Fatalf("SignInit: %v", err)
	}

	sig, err := cm.Sign(context.Background(), op, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if client.lastSignReq.DataIsDigest {
		t.Error("SignRequest.DataIsDigest = true, want false for CKM_SHA256_RSA_PKCS_PSS")
	}

	digest := sha256.Sum256(message)
	pssOpts := &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: 32}
	if err := rsa.VerifyPSS(&client.key.PublicKey, crypto.SHA256, digest[:], sig, pssOpts); err != nil {
		t.Fatalf("signature does not verify over SHA-256(message): %v", err)
	}
}

// TestSignRawMechanisms_DeclareTheirInputPreHashed covers the two mechanisms
// that were already correct via the "NONE" sentinel. They must keep sending
// it -- "NONE" is the digest identity, and there genuinely is none -- and must
// also declare DataIsDigest, so the two fields say the same thing.
func TestSignRawMechanisms_DeclareTheirInputPreHashed(t *testing.T) {
	tests := []struct {
		mech MechanismType
		name string
	}{
		{CKM_RSA_PKCS, "CKM_RSA_PKCS"},
		{CKM_ECDSA, "CKM_ECDSA"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm, client := newTestCryptoManager()
			op, err := cm.SignInit(&Mechanism{Type: tc.mech}, 1, "key-1", "test-backend")
			if err != nil {
				t.Fatalf("SignInit: %v", err)
			}
			if _, err := cm.Sign(context.Background(), op, make([]byte, 32)); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if got := client.lastSignReq.Hash; got != "NONE" {
				t.Errorf("SignRequest.Hash = %q, want %q", got, "NONE")
			}
			if !client.lastSignReq.DataIsDigest {
				t.Errorf("SignRequest.DataIsDigest = false, want true for %s", tc.name)
			}
		})
	}
}

// TestVerifyPSS_MatchesSign checks that C_Verify sends the same DataIsDigest
// C_Sign does. If the two disagree, a signature this module produced fails
// against a digest hashed one extra time, and the failure looks like an
// invalid signature rather than a mismatched request.
func TestVerifyPSS_MatchesSign(t *testing.T) {
	cm, client := newTestCryptoManager()

	mech := &Mechanism{
		Type: CKM_RSA_PKCS_PSS,
		TypedParameter: &RSAPSSParams{
			HashAlg: CKM_SHA256,
			MGF:     CKG_MGF1_SHA256,
			SaltLen: 32,
		},
	}

	signOp, err := cm.SignInit(mech, 1, "key-1", "test-backend")
	if err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	if _, err := cm.Sign(context.Background(), signOp, make([]byte, 32)); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifyOp, err := cm.VerifyInit(mech, 1, "key-1", "test-backend")
	if err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := cm.Verify(context.Background(), verifyOp, make([]byte, 32), []byte("sig")); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	signReq := client.lastSignReq
	verifyReq := client.lastVerifyReq
	if signReq.DataIsDigest != verifyReq.DataIsDigest {
		t.Errorf("DataIsDigest differs: sign=%v verify=%v", signReq.DataIsDigest, verifyReq.DataIsDigest)
	}
	if signReq.Hash != verifyReq.Hash {
		t.Errorf("Hash differs: sign=%q verify=%q", signReq.Hash, verifyReq.Hash)
	}
	if !verifyReq.DataIsDigest {
		t.Error("VerifyRequest.DataIsDigest = false, want true for CKM_RSA_PKCS_PSS")
	}
}

// TestSignPSS_UnsupportedHashInParamsIsRejected is the bad-input case for the
// PSS parameter path: SignInit must refuse parameters it cannot honour rather
// than resolving them to a default digest and signing under a scheme the
// caller did not request.
func TestSignPSS_UnsupportedHashInParamsIsRejected(t *testing.T) {
	cm, _ := newTestCryptoManager()

	mech := &Mechanism{
		Type: CKM_RSA_PKCS_PSS,
		TypedParameter: &RSAPSSParams{
			// Not a hash mechanism at all. PKCS#11 v3.2 section 6.1.9 requires
			// hashAlg to name the digest the application used, and a value
			// this module cannot resolve must be refused rather than
			// defaulted -- a default would sign under a digest the caller did
			// not choose and report success.
			HashAlg: CKM_AES_GCM,
			MGF:     CKG_MGF1_SHA256,
			SaltLen: 64,
		},
	}

	_, err := cm.SignInit(mech, 1, "key-1", "test-backend")
	if err == nil {
		t.Fatal("SignInit accepted a CK_RSA_PKCS_PSS_PARAMS.hashAlg that names no hash")
	}
	var pkcsErr *PKCS11Error
	if !errors.As(err, &pkcsErr) || pkcsErr.Code != CKR_MECHANISM_PARAM_INVALID {
		t.Fatalf("SignInit error = %v, want CKR_MECHANISM_PARAM_INVALID", err)
	}
}

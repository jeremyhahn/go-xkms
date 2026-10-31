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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// TestECDSAInputToDigest checks that CKM_ECDSA input of any length (v3.2
// §6.3.12, Table 70) reaches the service as a SHA-2 length digest holding the
// same integer: truncated to the field width, then left-padded with zeros.
func TestECDSAInputToDigest(t *testing.T) {
	long := []byte(strings.Repeat("abcdefgh", 9)) // 72 bytes
	tests := []struct {
		name     string
		data     []byte
		fieldLen int
		want     []byte
	}{
		{"short input on P-256 is left-padded to 32", long[:19], 32, append(make([]byte, 13), long[:19]...)},
		{"long input on P-256 keeps its leftmost 32 bytes", long[:41], 32, long[:32]},
		{"SHA-256 digest on P-384 passes unchanged", long[:32], 48, long[:32]},
		{"SHA-512 digest on P-256 passes unchanged", long[:64], 32, long[:64]},
		{"short input on P-384 is left-padded to 48", long[:41], 48, append(make([]byte, 7), long[:41]...)},
		{"short input on P-521 is left-padded to 64", long[:19], 66, append(make([]byte, 45), long[:19]...)},
		{"input for an unknown curve passes unchanged", long[:19], 0, long[:19]},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ecdsaInputToDigest(tc.data, tc.fieldLen)
			if err != nil {
				t.Fatalf("ecdsaInputToDigest: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("ecdsaInputToDigest = %x, want %x", got, tc.want)
			}
		})
	}
}

// TestECDSAInputToDigest_Unrepresentable checks that input no SHA-2 length the
// curve holds can carry is refused with CKR_DATA_LEN_RANGE, not sent on.
func TestECDSAInputToDigest_Unrepresentable(t *testing.T) {
	tests := []struct {
		name     string
		dataLen  int
		fieldLen int
	}{
		{"P-521 input wider than SHA-512", 65, 66},
		{"P-192 input of no SHA-2 length", 20, 24},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ecdsaInputToDigest(make([]byte, tc.dataLen), tc.fieldLen)
			if rv := FromError(err); rv != CKR_DATA_LEN_RANGE {
				t.Errorf("ecdsaInputToDigest error = %v (rv %#x), want CKR_DATA_LEN_RANGE", err, rv)
			}
		})
	}
}

// TestSignECDSA_SendsRawInputAsDigest drives the 41-byte input pkcs11-tool
// --sign -m ECDSA sends through C_Sign and C_Verify on a P-256 key: the
// service must receive its leftmost 32 bytes, which it signs, and not the raw
// 41 bytes, which it refuses.
func TestSignECDSA_SendsRawInputAsDigest(t *testing.T) {
	data := []byte("Test data for multi-protocol sign/verify\n")
	cm, client := newTestCryptoManager()

	signOp, err := cm.SignInit(&Mechanism{Type: CKM_ECDSA}, 1, "key-1", "test-backend")
	if err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	signOp.SetECFieldLen(32)
	if _, err := cm.Sign(context.Background(), signOp, data); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := client.lastSignReq.Data; !bytes.Equal(got, data[:32]) {
		t.Errorf("SignRequest.Data = %x, want %x", got, data[:32])
	}

	verifyOp, err := cm.VerifyInit(&Mechanism{Type: CKM_ECDSA}, 1, "key-1", "test-backend")
	if err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	verifyOp.SetECFieldLen(32)
	rawSignature := bytes.Repeat([]byte{0x01}, 64) // r || s on P-256
	if err := cm.Verify(context.Background(), verifyOp, data, rawSignature); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Verification sends the raw input; the verifier truncates it itself.
	if got := client.lastVerifyReq.Data; !bytes.Equal(got, data) {
		t.Errorf("VerifyRequest.Data = %x, want the raw input %x", got, data)
	}
}

// TestSignECDSA_UnrepresentableInputNeverReachesService checks that C_Sign
// refuses CKM_ECDSA input the service cannot sign before calling it.
func TestSignECDSA_UnrepresentableInputNeverReachesService(t *testing.T) {
	cm, client := newTestCryptoManager()
	op, err := cm.SignInit(&Mechanism{Type: CKM_ECDSA}, 1, "key-1", "test-backend")
	if err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	op.SetECFieldLen(66)

	_, err = cm.Sign(context.Background(), op, make([]byte, 65))
	if rv := FromError(err); rv != CKR_DATA_LEN_RANGE {
		t.Errorf("Sign error = %v (rv %#x), want CKR_DATA_LEN_RANGE", err, rv)
	}
	if client.lastSignReq != nil {
		t.Error("Sign reached the service with input it cannot sign")
	}
}

// newP521ECDSAVerifyCase signs a 66-byte raw digest with a P-521 key outside
// the module, the way an application holding the public key elsewhere would,
// and registers the key with a real-crypto transport. The digest is longer
// than every SHA-2 output, so only a verifier that truncates it per SEC 1 v2
// §4.1.4 step 3 accepts the signature.
func newP521ECDSAVerifyCase(t *testing.T) (cm *CryptoManager, client *mockClient, digest, rawSignature []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-521 key: %v", err)
	}
	cm, client, engine := newRealCryptoCryptoManager()
	engine.signers["p521-key"] = key

	digest = make([]byte, 66)
	if _, err := rand.Read(digest); err != nil {
		t.Fatalf("read digest: %v", err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rawSignature = make([]byte, 2*66) // r || s, PKCS#11 v3.2 §6.3.1
	r.FillBytes(rawSignature[:66])
	s.FillBytes(rawSignature[66:])
	return cm, client, digest, rawSignature
}

func TestVerifyECDSA_P521AcceptsRawDigestLongerThanSHA2(t *testing.T) {
	cm, client, digest, rawSignature := newP521ECDSAVerifyCase(t)

	op, err := cm.VerifyInit(&Mechanism{Type: CKM_ECDSA}, 1, "p521-key", "test-backend")
	if err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	op.SetECFieldLen(66)
	if err := cm.Verify(context.Background(), op, digest, rawSignature); err != nil {
		t.Fatalf("Verify of a valid P-521 signature over a 66-byte digest: %v", err)
	}
	if got := client.lastVerifyReq.Data; !bytes.Equal(got, digest) {
		t.Errorf("VerifyRequest.Data = %x, want the raw input %x", got, digest)
	}
}

func TestVerifyECDSA_P521RejectsAlteredRawDigest(t *testing.T) {
	cm, _, digest, rawSignature := newP521ECDSAVerifyCase(t)
	digest[0] ^= 0x80 // inside the 521 bits the verifier keeps

	op, err := cm.VerifyInit(&Mechanism{Type: CKM_ECDSA}, 1, "p521-key", "test-backend")
	if err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	op.SetECFieldLen(66)
	err = cm.Verify(context.Background(), op, digest, rawSignature)
	if rv := FromError(err); rv != CKR_SIGNATURE_INVALID {
		t.Errorf("Verify error = %v (rv %#x), want CKR_SIGNATURE_INVALID", err, rv)
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

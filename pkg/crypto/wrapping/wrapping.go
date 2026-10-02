// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// Package wrapping implements the RSA-OAEP and hybrid RSA+AES-KWP key
// wrapping algorithms used by xkms backends during the key-import and
// key-export ceremonies.
//
// # Memory discipline
//
// Every sensitive intermediate produced during wrap / unwrap — the
// ephemeral AES wrapping key, the padded plaintext, the unwrapped
// material — lives in a *secure.Buffer with an immediate deferred
// Destroy(). Only at the boundary of this package (the public
// []byte-returning signatures) is the material copied out into a
// plain slice, and that slice is the caller's responsibility to move
// into its own *secure.Buffer or *secure.Secret as soon as possible.
//
// That applies to unwrapped plaintext. The wrapped output of the Wrap*
// functions is ciphertext, which is not secret: the last wrapping round
// writes it straight into an ordinary slice, so wrapping hands its callers
// no secret to wipe.
//
// The public signatures remain []byte-in / []byte-out for drop-in
// compatibility with the HSM / cloud backends (awskms, azurekv,
// gcpkms, pkcs11) that are migrated in a later phase; the internal
// hardening still bounces the secret off the Go heap for the duration
// of the arithmetic.
package wrapping

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"hash"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// hashFuncForAlgorithm resolves the hash.Hash to use for a given
// wrapping algorithm. Returns *UnsupportedAlgorithmError for algorithms
// this package does not implement.
func hashFuncForAlgorithm(algorithm backend.WrappingAlgorithm) (hash.Hash, error) {
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1:
		return sha1.New(), nil
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		return sha256.New(), nil
	default:
		return nil, &UnsupportedAlgorithmError{Algorithm: string(algorithm)}
	}
}

// WrapRSAOAEP wraps key material using RSA-OAEP encryption. Suitable
// only for small material (up to RSA key size minus OAEP overhead);
// for larger material use WrapRSAAES.
//
// Parameters:
//   - keyMaterial: plaintext to wrap. Callers should hold this in a
//     *secure.Buffer and pass the Bytes() slice, then Destroy their
//     Buffer after this function returns — the slice is read-only
//     here.
//   - publicKey: the RSA public key to encrypt with.
//   - algorithm: one of the RSAES_OAEP_* values.
func WrapRSAOAEP(keyMaterial []byte, publicKey *rsa.PublicKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, &EmptyInputError{Field: "keyMaterial"}
	}
	if publicKey == nil {
		return nil, &NilInputError{Field: "publicKey"}
	}
	h, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	wrapped, encErr := rsa.EncryptOAEP(h, rand.Reader, publicKey, keyMaterial, nil)
	if encErr != nil {
		return nil, &CryptoError{Op: "rsa.EncryptOAEP", Err: encErr}
	}
	return wrapped, nil
}

// UnwrapRSAOAEP unwraps key material that was encrypted with
// WrapRSAOAEP. The returned plaintext is a fresh heap-allocated slice;
// callers MUST move it into a *secure.Buffer / *secure.Secret
// immediately and wipe the returned slice. This package does its own
// internal wipes but cannot reach into the caller's stack frame.
func UnwrapRSAOAEP(wrappedKey []byte, privateKey *rsa.PrivateKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(wrappedKey) == 0 {
		return nil, &EmptyInputError{Field: "wrappedKey"}
	}
	if privateKey == nil {
		return nil, &NilInputError{Field: "privateKey"}
	}
	h, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	// rsa.DecryptOAEP allocates the output slice. It is sensitive and is
	// the caller's to own and wipe.
	raw, decErr := rsa.DecryptOAEP(h, rand.Reader, privateKey, wrappedKey, nil)
	if decErr != nil {
		return nil, &CryptoError{Op: "rsa.DecryptOAEP", Err: decErr}
	}
	if len(raw) == 0 {
		return nil, &EmptyInputError{Field: "src"}
	}
	return raw, nil
}

// WrapRSAAES wraps key material using the hybrid RSA-OAEP + AES-KWP
// construction (AWS KMS "RSA_AES_KEY_WRAP_SHA_*" scheme). Flow:
//
//  1. Generate a random 256-bit AES wrapping key (secure.Buffer).
//  2. Wrap the AES key with RSA-OAEP using the caller's public key.
//  3. Wrap keyMaterial with AES-KWP (RFC 5649).
//  4. Emit [4-byte wrappedAESKey length][wrappedAESKey][AES-wrapped].
//
// All intermediate sensitive buffers are held in *secure.Buffer for
// the duration of this call and destroyed before returning.
func WrapRSAAES(keyMaterial []byte, publicKey *rsa.PublicKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(keyMaterial) == 0 {
		return nil, &EmptyInputError{Field: "keyMaterial"}
	}
	if publicKey == nil {
		return nil, &NilInputError{Field: "publicKey"}
	}
	h, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	// Step 1: Random 256-bit AES wrapping key, into a Buffer. Its borrow is
	// held only long enough to fill it, wrap it under the RSA key and expand it
	// into the cipher's key schedule; the AES-KWP register buffer is allocated
	// after the borrow is released, because borrows do not nest.
	aesKeyBuf, err := secure.NewBuffer(32)
	if err != nil {
		return nil, &CryptoError{Op: "alloc aes key buffer", Err: err}
	}
	defer aesKeyBuf.Destroy()

	var (
		wrappedAESKey []byte
		block         cipher.Block
	)
	if berr := aesKeyBuf.WithBytes(func(aesKey []byte) error {
		if _, rerr := rand.Read(aesKey); rerr != nil {
			return &CryptoError{Op: "read random aes key", Err: rerr}
		}
		// Step 2: Wrap the AES key with RSA-OAEP; the wrapped output is
		// non-sensitive.
		w, encErr := rsa.EncryptOAEP(h, rand.Reader, publicKey, aesKey, nil)
		if encErr != nil {
			return &CryptoError{Op: "rsa.EncryptOAEP (aes key)", Err: encErr}
		}
		wrappedAESKey = w
		c, cerr := aes.NewCipher(aesKey)
		if cerr != nil {
			return &CryptoError{Op: "aes.NewCipher (wrap)", Err: cerr}
		}
		block = c
		return nil
	}); berr != nil {
		return nil, berr
	}

	// Step 3: Wrap keyMaterial with AES-KWP. The register buffer is a
	// secure.Buffer of its own; the result is ciphertext, which is not secret.
	wrappedMaterial, kwpErr := wrapKWPWithBlock(block, keyMaterial)
	if kwpErr != nil {
		return nil, kwpErr
	}

	// Step 4: Concatenate with length prefix.
	aesKeyLen := uint32(len(wrappedAESKey))
	out := make([]byte, 4+len(wrappedAESKey)+len(wrappedMaterial))
	binary.BigEndian.PutUint32(out[0:4], aesKeyLen)
	copy(out[4:4+len(wrappedAESKey)], wrappedAESKey)
	copy(out[4+len(wrappedAESKey):], wrappedMaterial)
	return out, nil
}

// UnwrapRSAAES inverts WrapRSAAES. Like UnwrapRSAOAEP, the returned
// plaintext is caller-owned and sensitive; callers must immediately
// move it into a Buffer / Secret and wipe.
func UnwrapRSAAES(wrappedKey []byte, privateKey *rsa.PrivateKey, algorithm backend.WrappingAlgorithm) ([]byte, error) {
	if len(wrappedKey) < 4 {
		return nil, &MalformedWrappedKeyError{Reason: "too short"}
	}
	if privateKey == nil {
		return nil, &NilInputError{Field: "privateKey"}
	}
	h, err := hashFuncForAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	aesKeyLen := binary.BigEndian.Uint32(wrappedKey[0:4])
	if aesKeyLen > uint32(len(wrappedKey)-4) {
		return nil, &MalformedWrappedKeyError{Reason: "aes key length overflow"}
	}
	if len(wrappedKey) < int(4+aesKeyLen) {
		return nil, &MalformedWrappedKeyError{Reason: "truncated"}
	}
	wrappedAESKey := wrappedKey[4 : 4+aesKeyLen]
	wrappedMaterial := wrappedKey[4+aesKeyLen:]

	// Unwrap the AES key straight into a Buffer. rsa.DecryptOAEP returns a
	// fresh slice; NewBufferFromBytes moves it into protected memory and wipes
	// the source, on every path.
	rawAES, decErr := rsa.DecryptOAEP(h, rand.Reader, privateKey, wrappedAESKey, nil)
	if decErr != nil {
		return nil, &CryptoError{Op: "rsa.DecryptOAEP (aes key)", Err: decErr}
	}
	aesBuf, bufErr := secure.NewBufferFromBytes(rawAES)
	if bufErr != nil {
		// A zero-length key decrypted from the RSA ciphertext is malformed
		// input; NewBufferFromBytes refuses it.
		return nil, &MalformedWrappedKeyError{Reason: "empty aes key after unwrap"}
	}
	defer aesBuf.Destroy()

	// Expand the AES key into the cipher inside the borrow, then release the
	// borrow before UnwrapAESKWP's register buffer is allocated.
	var block cipher.Block
	if berr := aesBuf.WithBytes(func(aesKey []byte) error {
		if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
			return &InvalidKeySizeError{Algorithm: "aes-kwp", Size: len(aesKey)}
		}
		c, cerr := aes.NewCipher(aesKey)
		if cerr != nil {
			return &CryptoError{Op: "aes.NewCipher (unwrap)", Err: cerr}
		}
		block = c
		return nil
	}); berr != nil {
		return nil, berr
	}

	// Unwrap the material with the AES key. The returned plaintext is
	// sensitive; it is handed to the caller, who now owns it.
	if len(wrappedMaterial) < 16 || len(wrappedMaterial)%8 != 0 {
		return nil, &MalformedWrappedKeyError{Reason: "ciphertext must be >= 16 bytes and multiple of 8"}
	}
	return unwrapKWPWithBlock(block, wrappedMaterial)
}

// WrapAESKWP wraps plaintext under an AES key-encryption key using RFC 5649
// AES Key Wrap with Padding -- PKCS#11 v3.2 §6.10.5's CKM_AES_KEY_WRAP_PAD.
// Intermediate state (padded plaintext, register buffer) lives in a
// *secure.Buffer.
//
// Unlike WrapAESKW (RFC 3394), the plaintext length is arbitrary: RFC 5649
// records it in the Alternative Initial Value and pads the input up to an
// 8-byte boundary, which is what lets a 20-byte or 7-byte key be wrapped at
// all. Callers that already hold block-aligned material of at least 16 bytes
// may use either; only the padded form accepts everything else.
func WrapAESKWP(plaintext, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, &InvalidKeySizeError{Algorithm: "aes-kwp", Size: len(key)}
	}
	// RFC 5649 section 4.1 takes "a key, K (the KEK) and a plaintext, Q, of m
	// octets", with m at least 1: the message length indicator in the AIV
	// records m, and there is no m=0 encoding. Without this the padded length
	// is zero, the wrapping rounds never run, and the return value is the
	// bare 8-octet AIV -- a blob carrying no ciphertext at all, handed back
	// under a nil error as though a key had been wrapped.
	if len(plaintext) == 0 {
		return nil, &EmptyInputError{Field: "plaintext"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &CryptoError{Op: "aes.NewCipher (wrap)", Err: err}
	}
	return wrapKWPWithBlock(block, plaintext)
}

// wrapKWPWithBlock is WrapAESKWP over a cipher the caller has already built,
// so a caller that holds the KEK in protected memory can release its borrow
// before the register buffer is allocated (borrows do not nest). plaintext
// must be non-empty.
func wrapKWPWithBlock(block cipher.Block, plaintext []byte) ([]byte, error) {
	// The registers hold the RFC 5649 Alternative Initial Value (A65959A6
	// then the 32-bit message length indicator) followed by the plaintext
	// padded with zeros to an 8-byte multiple.
	n := (len(plaintext) + 7) / 8
	regLen := (n + 1) * 8
	registers, rerr := secure.NewBuffer(regLen)
	if rerr != nil {
		return nil, &CryptoError{Op: "alloc register buffer", Err: rerr}
	}
	defer registers.Destroy()
	// The wrapped key is ciphertext, so it is produced as ordinary bytes by
	// the last AES call rather than copied out of the registers.
	out := make([]byte, regLen)
	if werr := registers.WithBytes(func(rb []byte) error {
		binary.BigEndian.PutUint32(rb[0:4], 0xA65959A6)
		binary.BigEndian.PutUint32(rb[4:8], uint32(len(plaintext)))
		copy(rb[8:], plaintext)
		clear(rb[8+len(plaintext):])
		if n == 1 {
			// RFC 5649 section 4.1: the single-block case is one AES call
			// over A concatenated with P[1].
			block.Encrypt(out, rb)
			return nil
		}
		wrapRounds(block, rb, n, out)
		return nil
	}); werr != nil {
		return nil, &CryptoError{Op: "wrap registers", Err: werr}
	}
	return out, nil
}

// wrapRounds runs the RFC 3394 section 2.2.1 wrapping rounds over rb, the
// 8-byte A register followed by the n 8-byte blocks R[1..n]: 6*n rounds of
// B = AES(K, A | R[i]), A = MSB(64,B) XOR t, R[i] = LSB(64,B). RFC 5649 reuses
// them unchanged after forming the AIV and padding.
//
// The first five passes run in place, because until the last round every
// register is derived from the plaintext. The sixth and last pass writes its
// result straight into out (A then R[1..n], len(out) == len(rb)) instead of
// back into rb: those bytes are the wrapped key, which is ciphertext and not
// secret, so they are produced as ordinary bytes at the moment they become
// ciphertext rather than copied out of protected memory afterwards. The
// running A register of that pass is held in a local that is wiped on return.
func wrapRounds(block cipher.Block, rb []byte, n int, out []byte) {
	var b [16]byte
	defer clear(b[:])
	for j := 0; j <= 4; j++ {
		for i := 1; i <= n; i++ {
			copy(b[0:8], rb[0:8])
			copy(b[8:16], rb[i*8:(i+1)*8])
			block.Encrypt(b[:], b[:])

			copy(rb[0:8], b[0:8])
			xorCounter(rb[0:8], uint64(n*j+i))
			copy(rb[i*8:(i+1)*8], b[8:16])
		}
	}

	var a [8]byte
	defer clear(a[:])
	copy(a[:], rb[0:8])
	for i := 1; i <= n; i++ {
		copy(b[0:8], a[:])
		copy(b[8:16], rb[i*8:(i+1)*8])
		block.Encrypt(b[:], b[:])

		copy(a[:], b[0:8])
		xorCounter(a[:], uint64(n*5+i))
		copy(out[i*8:(i+1)*8], b[8:16])
	}
	copy(out[0:8], a[:])
}

// xorCounter XORs the 64-bit big-endian encoding of t into the 8-byte
// register a, the "A = MSB(64,B) XOR t" step of RFC 3394 section 2.2.1.
func xorCounter(a []byte, t uint64) {
	for k := 7; k >= 0; k-- {
		a[7-k] ^= byte(t >> (uint(k) * 8))
	}
}

// unwrapRounds inverts wrapRounds in place: the RFC 3394 section 2.2.2 rounds
// with i and j in reverse order.
func unwrapRounds(block cipher.Block, rb []byte, n int) {
	var b [16]byte
	defer clear(b[:])
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			copy(b[0:8], rb[0:8])
			xorCounter(b[0:8], uint64(n*j+i))
			copy(b[8:16], rb[i*8:(i+1)*8])
			block.Decrypt(b[:], b[:])
			copy(rb[0:8], b[0:8])
			copy(rb[i*8:(i+1)*8], b[8:16])
		}
	}
}

// window lends part of a Buffer's borrow. It is a secure.Borrower, so
// secure.CopyOut can copy out the unwrapped key from within the registers
// while the borrow is held across the whole copy.
type window struct {
	buf    *secure.Buffer
	offset int
	length int
}

// WithBytes calls fn with bytes [offset, offset+length) of the buffer. The
// caller guarantees the range lies within the buffer.
func (w window) WithBytes(fn func([]byte) error) error {
	return w.buf.WithBytes(func(b []byte) error {
		return fn(b[w.offset : w.offset+w.length])
	})
}

// kwpAIVHeader is the constant half of the RFC 5649 section 3 Alternative
// Initial Value, A65959A6. The four octets that follow it in the AIV carry the
// message length indicator (MLI), the unpadded length of the wrapped key.
var kwpAIVHeader = [4]byte{0xA6, 0x59, 0x59, 0xA6}

// kwpIntegrityFailure is the single reason reported for every RFC 5649 section
// 4.2 verification failure. It is deliberately one string: an unwrap is
// reachable over the wire with attacker-chosen ciphertext, and an error that
// said whether the header, the length indicator or the padding was wrong would
// hand the caller a distinguisher on the decrypted-but-unauthenticated block.
const kwpIntegrityFailure = "RFC 5649 section 4.2 integrity check failed"

// ctGreaterU64 reports whether x is greater than y, as 1 or 0, without
// branching on either value. Both arguments must be below 2^63 so that the
// high bit of the wrapping subtraction is a faithful borrow indicator; every
// value passed here is either a 32-bit header field or a slice index, so that
// bound holds by construction.
func ctGreaterU64(x, y uint64) int {
	return int((y - x) >> 63)
}

// verifyKWPIntegrity applies all three checks RFC 5649 section 4.2 requires of
// the register block recovered by an AES-KWP unwrap, and returns the validated
// message length indicator:
//
//  1. the first four octets of the AIV equal A65959A6;
//  2. the MLI satisfies 8*(n-1) < MLI <= 8*n;
//  3. the 8*n - MLI trailing padding octets are all zero.
//
// Only the first check used to be applied here, which left the effective
// forgery test at the 32 bits of the header instead of the header plus up to
// 56 bits of padding plus the length bound.
//
// The checks are evaluated unconditionally and folded into one accumulator so
// that no branch, and no error value, depends on which of them failed; the
// padding comparison walks the whole padded region rather than only the
// trailing 8*n - MLI octets, so its cost depends on the public ciphertext
// length and not on the recovered MLI.
//
// rb is the 8-octet AIV followed by the n padded plaintext blocks.
func verifyKWPIntegrity(rb []byte, n int) (int, error) {
	aivOK := subtle.ConstantTimeCompare(rb[0:4], kwpAIVHeader[:])

	mli := uint64(binary.BigEndian.Uint32(rb[4:8]))
	lower := uint64(8 * (n - 1))
	upper := uint64(8 * n)
	rangeOK := ctGreaterU64(mli, lower) & (1 ^ ctGreaterU64(mli, upper))

	padded := rb[8:]
	var padAcc byte
	for i := range padded {
		// Index i holds padding, rather than key material, exactly when
		// i >= MLI. The mask is 0xFF for a padding octet and 0x00 otherwise,
		// so padAcc ends up as the OR of every padding octet.
		isPad := byte(1 ^ ctGreaterU64(mli, uint64(i)))
		padAcc |= padded[i] & -isPad
	}
	padOK := subtle.ConstantTimeByteEq(padAcc, 0)

	if aivOK&rangeOK&padOK != 1 {
		return 0, &MalformedWrappedKeyError{Reason: kwpIntegrityFailure}
	}
	return int(mli), nil
}

// UnwrapAESKWP inverts WrapAESKWP: it unwraps an RFC 5649 blob under an AES
// key-encryption key, applies the full section 4.2 verification (AIV header,
// message length indicator bounds and zero padding, all via
// verifyKWPIntegrity) and recovers the original unpadded length. The unwrapped
// output IS sensitive and is returned as a plain []byte — the caller is
// expected to immediately move it into a secure.Buffer.
func UnwrapAESKWP(ciphertext, key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, &InvalidKeySizeError{Algorithm: "aes-kwp", Size: len(key)}
	}
	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, &MalformedWrappedKeyError{Reason: "ciphertext must be >= 16 bytes and multiple of 8"}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, &CryptoError{Op: "aes.NewCipher (unwrap)", Err: err}
	}
	return unwrapKWPWithBlock(block, ciphertext)
}

// unwrapKWPWithBlock is UnwrapAESKWP over a cipher the caller has already
// built, for the reason wrapKWPWithBlock gives. ciphertext must be at least 16
// bytes and a multiple of 8.
func unwrapKWPWithBlock(block cipher.Block, ciphertext []byte) ([]byte, error) {
	n := (len(ciphertext) / 8) - 1
	registers, rerr := secure.NewBuffer((n + 1) * 8)
	if rerr != nil {
		return nil, &CryptoError{Op: "alloc register buffer (unwrap)", Err: rerr}
	}
	defer registers.Destroy()

	var (
		mli  int
		verr error
	)
	if werr := registers.WithBytes(func(rb []byte) error {
		if n == 1 {
			// RFC 5649 section 4.2 decrypts the lone pair of blocks with a
			// single AES-ECB operation; the verification below is the same
			// one the general case runs.
			block.Decrypt(rb, ciphertext)
		} else {
			copy(rb, ciphertext)
			unwrapRounds(block, rb, n)
		}
		mli, verr = verifyKWPIntegrity(rb, n)
		return nil
	}); werr != nil {
		return nil, &CryptoError{Op: "unwrap registers", Err: werr}
	}
	if verr != nil {
		return nil, verr
	}

	// The unwrapped plaintext sits in rb[8 : 8+mli]. The register buffer is
	// destroyed by the deferred Destroy; the caller owns the copy.
	return copyOutKey(window{buf: registers, offset: 8, length: mli})
}

// copyOutKey copies the unwrapped key out of b into a caller-owned slice. It
// is the one place a sensitive result leaves protected memory, so every
// "returning sensitive bytes to a caller" site has the same shape.
func copyOutKey(b secure.Borrower) ([]byte, error) {
	out, err := secure.CopyOut(b)
	if err != nil {
		return nil, &CryptoError{Op: "copy out unwrapped key", Err: err}
	}
	return out, nil
}

// aesKWDefaultIV is the RFC 3394 section 2.2.3.1 default initial value,
// A0. PKCS#11's CKM_AES_KEY_WRAP has no per-call IV parameter, so every
// wrap under this function uses the standard default rather than a
// caller-supplied alternative (RFC 3394 section 2.2.3.2).
var aesKWDefaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// WrapAESKW wraps plaintext under kek using RFC 3394 AES Key Wrap (no
// padding) -- PKCS#11's CKM_AES_KEY_WRAP. Unlike WrapAESKWP (RFC
// 5649) above, plain AES-KW has no length-padding step: plaintext must
// already be a whole number of 8-byte blocks, and at least two blocks (16
// bytes) per RFC 3394 section 2. Callers with unaligned or shorter material
// need CKM_AES_KEY_WRAP_PAD instead, which this package does not implement.
//
// Verified against the RFC 3394 section 4 known-answer vectors (128/192/256
// -bit KEKs over 128/192/256-bit key data); see wrapping_aeskw_test.go.
func WrapAESKW(plaintext, kek []byte) ([]byte, error) {
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, &InvalidKeySizeError{Algorithm: "aes-kw", Size: len(kek)}
	}
	if len(plaintext) == 0 {
		return nil, &EmptyInputError{Field: "plaintext"}
	}
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, &MalformedWrappedKeyError{Reason: "aes-kw plaintext must be at least 16 bytes and a multiple of 8"}
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, &CryptoError{Op: "aes.NewCipher (aes-kw wrap)", Err: err}
	}

	n := len(plaintext) / 8
	registers, rerr := secure.NewBuffer((n + 1) * 8)
	if rerr != nil {
		return nil, &CryptoError{Op: "alloc register buffer (aes-kw wrap)", Err: rerr}
	}
	defer registers.Destroy()
	// The wrapped key is ciphertext, so the last round writes it into an
	// ordinary slice instead of it being copied out of the registers.
	out := make([]byte, (n+1)*8)
	if werr := registers.WithBytes(func(rb []byte) error {
		copy(rb[0:8], aesKWDefaultIV[:])
		copy(rb[8:], plaintext)
		wrapRounds(block, rb, n, out)
		return nil
	}); werr != nil {
		return nil, &CryptoError{Op: "wrap registers (aes-kw wrap)", Err: werr}
	}
	return out, nil
}

// UnwrapAESKW inverts WrapAESKW. The unwrapped output IS sensitive and is
// returned as a plain []byte via encloseAndCopy -- the caller is expected to
// immediately move it into a secure.Buffer, the same contract
// UnwrapAESKWP documents above.
func UnwrapAESKW(wrapped, kek []byte) ([]byte, error) {
	if len(kek) != 16 && len(kek) != 24 && len(kek) != 32 {
		return nil, &InvalidKeySizeError{Algorithm: "aes-kw", Size: len(kek)}
	}
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, &MalformedWrappedKeyError{Reason: "aes-kw wrapped key must be at least 24 bytes and a multiple of 8"}
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, &CryptoError{Op: "aes.NewCipher (aes-kw unwrap)", Err: err}
	}

	n := (len(wrapped) / 8) - 1
	registers, rerr := secure.NewBuffer((n + 1) * 8)
	if rerr != nil {
		return nil, &CryptoError{Op: "alloc register buffer (aes-kw unwrap)", Err: rerr}
	}
	defer registers.Destroy()

	// RFC 3394 section 2.2.2 step 3: the recovered A must equal the initial
	// value. subtle.ConstantTimeCompare rather than a byte loop with an early
	// return, which would leak through timing how many leading octets of a
	// forged blob matched -- the loop is the whole authenticity check for
	// CKM_AES_KEY_WRAP, and unwrap is reachable with attacker-chosen input.
	var intact bool
	if werr := registers.WithBytes(func(rb []byte) error {
		copy(rb, wrapped)
		unwrapRounds(block, rb, n)
		intact = subtle.ConstantTimeCompare(rb[0:8], aesKWDefaultIV[:]) == 1
		return nil
	}); werr != nil {
		return nil, &CryptoError{Op: "unwrap registers (aes-kw unwrap)", Err: werr}
	}
	if !intact {
		return nil, &MalformedWrappedKeyError{Reason: "invalid AES-KW integrity check value"}
	}

	return copyOutKey(window{buf: registers, offset: 8, length: n * 8})
}

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

package types

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	// The KDF pseudorandom functions are selected by name at runtime, so
	// their implementations must be linked in for crypto.Hash.Available to
	// report them. SHA-1 is linked because the ANSI X9.63 and NIST SP 800-56A
	// concatenation KDFs are defined over it and PKCS#11 v3.0 names it
	// (CKD_SHA1_KDF); see concatKDFHashes. Deliberately absent: MD4, MD5 and
	// RIPEMD-160, which no key-derivation standard approves.
	// SP 800-56A Rev. 3 and SP 800-131A Rev. 2 approve SHA-1 for key
	// derivation, which is why it is linked -- but the STANDARD approving it
	// and the RUNTIME permitting it are different claims, and this comment
	// used to assert only the first. Under GODEBUG=fips140=only Go refuses
	// crypto/sha1 outright, whatever the use, and panics on the first Write.
	// concatKDFHashes still lists SHA-1; kdfAlgorithmBridge.hash filters it
	// out through HashUsable when the process will not compute it
	// (go-xkms#292).
	_ "crypto/sha1" //nolint:gosec // G505: linked for the X9.63/SP 800-56A concatenation KDFs; refused at lookup when the runtime will not compute it
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// Errors returned by KDFParams.Derive.
var (
	// ErrKDFParamNotApplicable indicates the caller supplied a parameter the
	// selected KDF algorithm does not consume. The parameter is rejected
	// rather than dropped: silently ignoring a caller-supplied KDF input
	// produces a key derived from inputs the caller did not choose.
	ErrKDFParamNotApplicable = errors.New("kdf parameter is not applicable to the selected algorithm")

	// ErrUnsupportedKDFAlgorithm indicates the KDF algorithm has no
	// implementation in pkg/crypto/kdf.
	ErrUnsupportedKDFAlgorithm = errors.New("unsupported KDF algorithm")

	// ErrUnsupportedKDFHash indicates the requested hash is not one of the
	// approved KDF pseudorandom functions, or its implementation is not
	// linked into the binary.
	ErrUnsupportedKDFHash = errors.New("unsupported KDF hash algorithm")

	// ErrKeyDerivationNotSupported indicates the backend holds the named key
	// but cannot run a key derivation function over it. It is a capability
	// boundary, not a missing implementation: a backend whose symmetric key
	// material never leaves its hardware, and whose hardware exposes no KDF
	// command, has no way to derive without either exporting the key (which
	// its protection forbids) or deriving from something that is not the key
	// (which produces a key an attacker who knows the same non-secret can
	// reproduce). Backends in that position do not implement
	// SymmetricKeyDeriver at all, so the refusal is visible to the caller as
	// this error before any derivation is attempted.
	ErrKeyDerivationNotSupported = errors.New("backend cannot derive from a stored symmetric key")

	// ErrEmptyKeyMaterial indicates a derivation was attempted with no input
	// keying material. It is an error rather than a defaulted empty string
	// because every KDF in this package will happily derive from zero bytes
	// and return a well-formed, entirely predictable key.
	ErrEmptyKeyMaterial = errors.New("key derivation requires non-empty input keying material")

	// ErrKeyLengthTooLarge indicates the caller asked a KDF to produce more
	// than MaxDerivedKeyLength bytes of output.
	//
	// It exists because none of the constructions pkg/crypto/kdf implements
	// refuses a large caller-chosen length on its own: the ANSI X9.63 and
	// NIST SP 800-56A concatenation KDFs accept requests up to 2^32 hash
	// blocks and preallocate reps*hash.Size() before deriving a single byte,
	// and the NIST SP 800-108 modes accept requests up to roughly 512 MiB.
	// A single DeriveKey or DeriveKeyECDH request naming an unbounded
	// key_length could therefore task the server with a multi-gigabyte
	// allocation before any of those adapters run (go-xkms#1259). Checked at
	// every derivation entry point -- KDFParams.Derive and
	// DeriveFromKeyMaterial -- so no caller of either can reach an adapter
	// with a length neither of them has already refused.
	ErrKeyLengthTooLarge = errors.New("requested key length exceeds the maximum derived key length")
)

// MaxDerivedKeyLength is the largest output, in bytes, that a key derivation
// function invoked through this package may produce.
//
// It is the single length ceiling for every KDF this service exposes --
// HKDF, the SP 800-108r1 modes, the ANSI X9.63 / SP 800-56A concatenation
// KDFs, and the raw (CKD_NULL) pass-through -- checked once, in
// KDFParams.Derive and DeriveFromKeyMaterial, rather than reimplemented by
// each adapter in pkg/crypto/kdf. Those adapters keep their own
// construction-specific ceilings (2^32 hash blocks for the concatenation
// KDFs, ~512 MiB for SP 800-108, RFC 5869's 255*HashLen for HKDF): those are
// correctness bounds tied to each wire format's own counter or length field,
// not a capacity policy, and every one of them is far larger than any key or
// MAC this service ever derives. 1024 bytes covers the largest output this
// service actually produces -- a 512-bit (64-byte) symmetric key or HMAC key
// -- with generous headroom for algorithms added later, while remaining far
// below a size that could pressure server memory from a single request.
const MaxDerivedKeyLength = 1024

// SymmetricKeyDeriver extends SymmetricKeyProvider with derivation from a key
// the backend already holds, named only by its attributes.
//
// It exists so PKCS#11 C_DeriveKey (v3.2 §5.18.5) can be answered without the
// base key's material crossing a process boundary. The PKCS#11 module runs in
// the calling application's address space and knows a base key only by its
// object handle, label and backend key identifier; none of those is secret.
// Running the KDF there — over whatever the module can see — either derives
// from a non-secret (which is a cryptographic failure, because anyone holding
// the same label reproduces the key) or requires exporting a key whose
// CKA_SENSITIVE/CKA_EXTRACTABLE settings forbid export. Moving the derivation
// behind this interface removes both options: the request carries the base
// key's identity and the mechanism parameters, and the KDF runs where the key
// material already lives.
//
// Implemented by every backend that can reach its own symmetric key material:
// software, the symmetric key provider, TPM 2.0 (which unseals into the
// backend and zeroizes afterwards) and PKCS#11 (for a token key whose
// CKA_EXTRACTABLE permits the token to release it). Deliberately NOT
// implemented by AWS KMS, GCP KMS, Azure Key Vault, Vault Transit or the phone
// backend: none of those exposes either the key material or a KDF over it, so
// they advertise no capability and callers receive
// ErrKeyDerivationNotSupported instead of a key derived from something else.
type SymmetricKeyDeriver interface {
	SymmetricKeyProvider

	// DeriveFromSymmetricKey runs the key derivation function selected by
	// params over the symmetric key identified by attrs, returning
	// params.KeyLength bytes of derived keying material.
	//
	// The base key's material is never returned and never leaves the
	// implementation. Implementations must return
	// ErrKeyDerivationNotSupported when the key exists but its protection
	// settings do not permit the backend to read it for derivation, so that
	// a caller can tell "this key may not be derived from" apart from "this
	// key does not exist".
	DeriveFromSymmetricKey(ctx context.Context, attrs *KeyAttributes, params *kdf.KDFParams) ([]byte, error)
}

// DeriveFromKeyMaterial runs the key derivation function selected by params
// over ikm. It is the one place a backend's SymmetricKeyDeriver
// implementation turns recovered key material into derived key material, so
// every backend produces identical bytes for identical inputs.
//
// The algorithm is taken from params.Algorithm and resolved through
// pkg/crypto/kdf's own dispatch table, which covers HKDF (RFC 5869), the ANSI
// X9.63 and NIST SP 800-56A concatenation KDFs, and all three NIST SP 800-108r1
// modes — counter, feedback and double-pipeline. Unlike KDFParams.Derive, this
// function does not filter parameters by applicability: its caller is a
// backend acting on a request the service layer has already validated against
// the selected construction.
//
// Empty ikm is refused. Every construction here derives happily from zero
// bytes, and the result is a well-formed key that anyone can recompute.
func DeriveFromKeyMaterial(ikm []byte, params *kdf.KDFParams) ([]byte, error) {
	if params == nil {
		return nil, &errs.Detail{Err: ErrUnsupportedKDFAlgorithm, Detail: "nil KDF parameters"}
	}
	if len(ikm) == 0 {
		return nil, ErrEmptyKeyMaterial
	}
	// Refused before NewAdapter/DeriveKey run: this is the one entry point
	// DeriveKey's raw-input-key-material and stored-symmetric-key paths both
	// call, and none of the adapters below bounds a caller-chosen KeyLength
	// on its own. See ErrKeyLengthTooLarge.
	if params.KeyLength > MaxDerivedKeyLength {
		return nil, &errs.Detail{
			Err:    ErrKeyLengthTooLarge,
			Detail: fmt.Sprintf("requested %d bytes, maximum is %d bytes", params.KeyLength, MaxDerivedKeyLength),
		}
	}

	adapter, err := kdf.NewAdapter(params.Algorithm)
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedKDFAlgorithm, Detail: params.Algorithm.String()}
	}

	derived, err := adapter.DeriveKey(ikm, params)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "KDF derivation failed for " + params.Algorithm.String(), Err: err}
	}

	return derived, nil
}

// prfKDFHashes are the hashes accepted by the HMAC-based key derivation
// functions — HKDF (RFC 5869) and the SP 800-108r1 modes. These constructions
// have no external interoperability contract pinning a particular digest, so
// the table holds the line at a 256-bit digest (128-bit collision security)
// floor: SHA-2 and SHA-3 only. MD4, MD5, SHA-1, RIPEMD-160 and the truncated
// digests are not reachable.
var prfKDFHashes = map[string]crypto.Hash{
	"SHA-256":  crypto.SHA256,
	"SHA-384":  crypto.SHA384,
	"SHA-512":  crypto.SHA512,
	"SHA3-256": crypto.SHA3_256,
	"SHA3-384": crypto.SHA3_384,
	"SHA3-512": crypto.SHA3_512,
}

// concatKDFHashes are the hashes accepted by the two single-step
// concatenation KDFs, ANSI X9.63 and NIST SP 800-56A. They are a superset of
// prfKDFHashes because these two constructions do carry an interoperability
// contract: PKCS#11 v3.0 defines one CK_EC_KDF_TYPE per hash
// (CKD_SHA1_KDF, CKD_SHA224_KDF, CKD_SHA3_224_KDF and the CKD_*_KDF_SP800
// variants), and the xkms PKCS#11 module advertises them, so every one of them
// has to derive rather than fail.
//
// Admitting SHA-1 and the 224-bit digests here is a deliberate, standards-
// backed exception to the signature-side weak-hash policy in hashpolicy.go,
// not a relaxation of it:
//
//   - ANSI X9.63 defines its concatenation KDF over SHA-1.
//   - NIST SP 800-56A Rev. 3 §5.1 approves SHA-1, SHA-224 and the SHA-3
//     family as hash functions for its key-derivation functions.
//   - NIST SP 800-131A Rev. 2 disallows SHA-1 for digital signature
//     generation but keeps it acceptable for non-signature applications,
//     which is exactly this use.
//
// A concatenation KDF relies on the preimage and pseudorandomness of the
// digest, not its collision resistance, so the SHA-1 collision attacks that
// bar it from signing do not apply. Signing with SHA-1 remains refused; see
// AvailableHashes and ParseHash.
//
// That reasoning is about the STANDARDS, and it is unchanged. It does not
// bind the runtime: under GODEBUG=fips140=only Go refuses crypto/sha1 for
// every use, approved or not. The set below is therefore the set this
// construction accepts IN PRINCIPLE; kdfAlgorithmBridge.hash narrows it to
// what the running process can actually compute, so a caller naming SHA-1 in
// such a process gets an unsupported-hash error instead of a panic
// (go-xkms#292).
var concatKDFHashes = func() map[string]crypto.Hash {
	hashes := map[string]crypto.Hash{
		"SHA-1":    crypto.SHA1,
		"SHA-224":  crypto.SHA224,
		"SHA3-224": crypto.SHA3_224,
	}
	for name, h := range prfKDFHashes {
		hashes[name] = h
	}
	return hashes
}()

// kdfAlgorithmBridge describes how one KDFAlgorithm maps onto the canonical
// kdf package: which adapter implements it and which KDFParams fields it
// consumes. Fields absent from the applicability set are rejected.
type kdfAlgorithmBridge struct {
	algorithm kdf.KDFAlgorithm

	// hashes is the set of hash names this construction accepts, keyed by
	// canonical spelling. It is per-algorithm rather than global because the
	// approved hash set is a property of the construction and its
	// interoperability contract, not of the package.
	hashes map[string]crypto.Hash

	usesSalt            bool
	usesInfo            bool
	usesLabelContext    bool
	usesCounter         bool
	usesInitializationV bool
}

// kdfBridges is the single dispatch table from the xkms wire-level KDF
// algorithm to its canonical implementation. Every backend derives through
// this table, which is why all of them produce identical bytes for identical
// inputs.
var kdfBridges = map[KDFAlgorithm]kdfAlgorithmBridge{
	KDFAlgorithmHKDF: {
		algorithm: kdf.AlgorithmHKDF,
		hashes:    prfKDFHashes,
		usesSalt:  true,
		usesInfo:  true,
	},
	KDFAlgorithmX963: {
		algorithm: kdf.AlgorithmX963,
		hashes:    concatKDFHashes,
		usesInfo:  true,
	},
	KDFAlgorithmSP80056A: {
		algorithm: kdf.AlgorithmSP80056A,
		hashes:    concatKDFHashes,
		usesInfo:  true,
	},
	KDFAlgorithmSP800108Counter: {
		algorithm:        kdf.AlgorithmSP800108Counter,
		hashes:           prfKDFHashes,
		usesLabelContext: true,
		usesCounter:      true,
	},
	KDFAlgorithmSP800108Feedback: {
		algorithm:           kdf.AlgorithmSP800108Feedback,
		hashes:              prfKDFHashes,
		usesLabelContext:    true,
		usesCounter:         true,
		usesInitializationV: true,
	},
}

// hash resolves the caller-supplied hash name against the set this
// construction accepts. It reports the hash only when the name is approved for
// this algorithm and the implementation is linked into the binary.
func (b kdfAlgorithmBridge) hash(name string) (crypto.Hash, bool) {
	h, ok := b.hashes[name]
	if !ok {
		return 0, false
	}
	// HashUsable rather than h.Available: Available reports LINKAGE, and under
	// GODEBUG=fips140=only a refused digest stays linked and panics on the
	// first Write instead. This lookup is the only place the KDF hash sets are
	// reported to a caller, so narrowing here is what makes them a truthful
	// capability report rather than a list of names that can kill the process
	// (go-xkms#292).
	return h, HashUsable(h)
}

// Derive runs the shared secret through the KDF these parameters select and
// returns KeyLength bytes of keying material. It is the single derivation
// entry point for every backend that implements KeyAgreementProvider, so a
// given (secret, params) pair yields the same bytes on TPM 2.0, PKCS#11,
// software, and phone backends alike.
//
// Derive assumes Validate has already been called; it re-derives nothing that
// Validate defaults, and callers that skip Validate get the errors below
// rather than a silently defaulted key.
//
// KeyLength is checked against MaxDerivedKeyLength here regardless, before
// either the raw pass-through or a kdf.KDFAdapter runs, rather than trusted
// to Validate: this is the one entry point every backend's DeriveKeyECDH
// calls, and a caller-chosen KeyLength that reached the adapters below
// unbounded could preallocate gigabytes (go-xkms#1259).
//
// Parameter applicability is enforced, not ignored. Each algorithm consumes a
// specific subset of KDFParams; supplying a field outside that subset returns
// ErrKDFParamNotApplicable:
//
//	HKDF                Salt, Info
//	X963                Info
//	SP800-56A           Info
//	SP800-108-COUNTER   Label, Context, CounterLength, CounterLocation
//	SP800-108-FEEDBACK  Label, Context, CounterLength, CounterLocation, IV
//
// The approved hash set is likewise per-algorithm. HKDF and the SP 800-108
// modes take SHA-256/384/512 and SHA3-256/384/512; the two concatenation KDFs
// additionally take SHA-1, SHA-224 and SHA3-224, which ANSI X9.63,
// SP 800-56A Rev. 3 and PKCS#11 v3.0 all define for that construction. See
// prfKDFHashes and concatKDFHashes.
//
// BREAKING CHANGE: the two SP 800-108 labels previously derived with HKDF and
// consumed Salt and Info. They now run the real SP 800-108r1 construction and
// take Label and Context; see the package documentation of
// github.com/jeremyhahn/go-xkms/pkg/crypto/kdf for the full notice.
func (p *KDFParams) Derive(sharedSecret []byte) ([]byte, error) {
	if p == nil {
		return nil, &errs.Detail{Err: ErrUnsupportedKDFAlgorithm, Detail: "nil KDF parameters"}
	}
	if p.KeyLength > MaxDerivedKeyLength {
		return nil, &errs.Detail{
			Err:    ErrKeyLengthTooLarge,
			Detail: fmt.Sprintf("requested %d bytes, maximum is %d bytes", p.KeyLength, MaxDerivedKeyLength),
		}
	}

	if p.Algorithm == KDFAlgorithmRaw {
		return p.deriveRaw(sharedSecret)
	}

	bridge, ok := kdfBridges[p.Algorithm]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnsupportedKDFAlgorithm, Detail: p.Algorithm.String()}
	}

	hash, ok := bridge.hash(p.Hash)
	if !ok {
		return nil, &errs.Detail{
			Err:    ErrUnsupportedKDFHash,
			Detail: p.Hash + " is not an approved hash for " + p.Algorithm.String(),
		}
	}

	if err := bridge.checkApplicability(p); err != nil {
		return nil, err
	}

	adapter, err := kdf.NewAdapter(bridge.algorithm)
	if err != nil {
		return nil, &errs.Detail{Err: ErrUnsupportedKDFAlgorithm, Detail: p.Algorithm.String()}
	}

	derived, err := adapter.DeriveKey(sharedSecret, &kdf.KDFParams{
		Algorithm:       bridge.algorithm,
		Hash:            hash,
		KeyLength:       p.KeyLength,
		Salt:            p.Salt,
		Info:            p.Info,
		Label:           p.Label,
		Context:         p.Context,
		CounterLength:   p.CounterLength,
		CounterLocation: p.CounterLocation,
		IV:              p.IV,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "KDF derivation failed for " + p.Algorithm.String(), Err: err}
	}

	return derived, nil
}

// ErrRawKDFTooShort indicates a raw (CKD_NULL) derivation asked for more key
// material than the shared secret contains. There is no KDF to expand it with,
// so the request cannot be answered; returning the short secret instead would
// hand back a key of a length the caller did not ask for, and padding it would
// invent key material.
var ErrRawKDFTooShort = errors.New("raw key derivation cannot produce more key material than the shared secret contains")

// rawKDFApplicable rejects every KDF input for KDFAlgorithmRaw.
//
// CKD_NULL consumes nothing: PKCS#11 v3.2's CK_ECDH1_DERIVE_PARAMS states that
// with it "pSharedData must be NULL and ulSharedDataLen must be zero". A salt,
// info, label, context or IV supplied alongside it is a caller that believes
// those values separate its key from someone else's; accepting and discarding
// them would give both parties the same key.
func (p *KDFParams) rawKDFApplicable() error {
	notApplicable := func(field string) error {
		return &errs.Detail{
			Err:    ErrKDFParamNotApplicable,
			Detail: field + " is not an input to " + p.Algorithm.String(),
		}
	}

	switch {
	case p.Hash != "":
		return notApplicable("Hash")
	case len(p.Salt) > 0:
		return notApplicable("Salt")
	case len(p.Info) > 0:
		return notApplicable("Info")
	case len(p.Label) > 0:
		return notApplicable("Label")
	case len(p.Context) > 0:
		return notApplicable("Context")
	case len(p.IV) > 0:
		return notApplicable("IV")
	case p.CounterLength != 0:
		return notApplicable("CounterLength")
	case p.CounterLocation != "":
		return notApplicable("CounterLocation")
	}
	return nil
}

// deriveRaw answers a CKD_NULL derivation: the shared secret itself, truncated
// to KeyLength.
//
// PKCS#11 v3.2 §6.3.17 says CKM_ECDH1_DERIVE "derives a secret value, and
// truncates the result according to the CKA_KEY_TYPE attribute of the template
// and, if it has one and the key type supports it, the CKA_VALUE_LEN attribute
// of the template. (The truncation removes bytes from the leading end of the
// secret value.)" -- so a shorter key is the tail of the secret, not its head.
//
// KeyLength's upper bound is Derive's, checked before this method is ever
// reached; it is not repeated here because this method's own bound --
// KeyLength must not exceed len(sharedSecret) -- is always tighter (an ECDH
// shared secret is at most a few hundred bytes), so nothing this function
// does can allocate more than MaxDerivedKeyLength bytes even without
// repeating the check.
func (p *KDFParams) deriveRaw(sharedSecret []byte) ([]byte, error) {
	if len(sharedSecret) == 0 {
		return nil, ErrEmptyKeyMaterial
	}
	if err := p.rawKDFApplicable(); err != nil {
		return nil, err
	}
	if p.KeyLength <= 0 {
		return nil, &errs.Message{Msg: fmt.Sprintf("key length must be positive, got %d", p.KeyLength)}
	}
	if p.KeyLength > len(sharedSecret) {
		return nil, &errs.Detail{
			Err:    ErrRawKDFTooShort,
			Detail: fmt.Sprintf("requested %d bytes from a %d-byte shared secret", p.KeyLength, len(sharedSecret)),
		}
	}

	derived := make([]byte, p.KeyLength)
	copy(derived, sharedSecret[len(sharedSecret)-p.KeyLength:])
	return derived, nil
}

// checkApplicability rejects any parameter the selected algorithm does not
// consume, naming the offending field so the caller can correct it.
func (b kdfAlgorithmBridge) checkApplicability(p *KDFParams) error {
	notApplicable := func(field string) error {
		return &errs.Detail{
			Err:    ErrKDFParamNotApplicable,
			Detail: field + " is not an input to " + p.Algorithm.String(),
		}
	}

	if len(p.Salt) > 0 && !b.usesSalt {
		return notApplicable("Salt")
	}
	if len(p.Info) > 0 && !b.usesInfo {
		return notApplicable("Info")
	}
	if len(p.Label) > 0 && !b.usesLabelContext {
		return notApplicable("Label")
	}
	if len(p.Context) > 0 && !b.usesLabelContext {
		return notApplicable("Context")
	}
	if !b.usesCounter {
		if p.CounterLength != 0 {
			return notApplicable("CounterLength")
		}
		if p.CounterLocation != "" {
			return notApplicable("CounterLocation")
		}
	}
	if len(p.IV) > 0 && !b.usesInitializationV {
		return notApplicable("IV")
	}

	return nil
}

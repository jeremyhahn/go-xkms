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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// ErrUnwrapCiphertextRejected is the one error every ciphertext-dependent
// unwrap failure reports, for every mechanism, on every backend.
//
// C_UnwrapKey is reachable over gRPC, QUIC, MCP, the unix socket and REST with
// a caller-designated key and a caller-supplied blob, which makes each
// non-authenticated mechanism a decryption oracle in the classic sense:
// CKM_RSA_PKCS is the Bleichenbacher/Marvin shape and CKM_AES_CBC_PAD is the
// Vaudenay padding-oracle shape. RFC 8017 section 7.2.2 is explicit that an
// implementation must not reveal which check failed, and the same reasoning
// covers PKCS#7 unpadding, so the reason a blob was refused is deliberately
// discarded here rather than reported.
//
// What this does NOT do is remove the oracle. An unwrap that succeeds returns
// key material and an unwrap that fails does not, and that one bit is the
// oracle's whole answer; only refusing the mechanism outright would close it,
// and both mechanisms are sanctioned by PKCS#11 v3.2 for C_UnwrapKey. What it
// does close is every *additional* bit: which of several checks failed, and --
// more importantly, since backends other than software surface their own
// diagnostics -- whatever an HSM or a cloud KMS chose to say about the
// ciphertext.
//
// The cost is diagnostic: an operator debugging a genuine unwrap failure sees
// only that the blob was rejected. That is the same trade TLS made when it
// stopped distinguishing decrypt_error from bad_record_mac.
var ErrUnwrapCiphertextRejected = errors.New("keystore: unwrap failed: ciphertext rejected")

// Wrap/unwrap algorithms accepted on WrapKeyByIDRequest.Algorithm and
// UnwrapKeyByIDRequest.Algorithm.
//
// There is ONE vocabulary: types.KeyWrapAlgorithm, the constants published in
// the gRPC proto, the REST API specification and the CLI documentation. Every
// caller speaks it, including the PKCS#11 module, whose mechanismToAlgorithm
// maps CK_MECHANISM (and, for OAEP, CK_RSA_PKCS_OAEP_PARAMS.hashAlg) straight
// onto these constants.
//
// It did not used to. The module emitted its own lowercase mechanism names
// ("rsa-oaep") that named no digest and that no other transport spoke, so the
// service accepted only those and rejected the exact strings its own proto
// told callers to send -- breaking wrap and unwrap over gRPC and MCP. The
// vocabularies are unified rather than translated: a mapping table between
// them would have preserved the divergence, and a third spelling is exactly
// what created it.
type wrapKind uint8

const (
	kindAESKW wrapKind = iota + 1
	kindAESKWP
	kindAESGCM
	kindAESCBC
	kindAESCBCPad
	kindRSAOAEP
	kindRSAPKCS1v15
)

// wrapMechanism is the normalized form of a requested algorithm: which
// construction to use, and (for OAEP) which digest. Dispatch happens on this
// rather than on strings, so a digest is chosen once, where the algorithm is
// resolved, instead of being defaulted independently at each call site.
type wrapMechanism struct {
	kind wrapKind

	// digest is the OAEP hash. It is meaningful only for kindRSAOAEP.
	digest crypto.Hash

	// weak marks an algorithm the project refuses rather than performs.
	// SHA-1 OAEP is rejected everywhere in this codebase (see
	// ResolveOAEPHash): OAEP has no legacy blobs to read, so there is no
	// compatibility argument for it, and silently substituting SHA-256 would
	// return a wrong answer as success. It is unconditional: no configuration
	// re-admits it.
	weak bool

	// legacy marks an algorithm that authenticates nothing and is therefore
	// refused unless the operator opts in with crypto.allow_legacy_key_wrap
	// (types.AllowLegacyKeyWrap). It is not derived here: types owns the set,
	// so the policy, the compliance-gap message and this table cannot drift
	// apart. See types.IsLegacyKeyWrapAlgorithm for the reasoning and the
	// measurements.
	legacy bool
}

// authenticated reports whether a wrong unwrapping key reliably fails the
// mechanism's own integrity check: AES-KW and AES-KWP (RFC 3394/5649
// integrity check value), AES-GCM (tag) and RSA-OAEP (padding check). Those
// may try each enabled version of a rotated key in turn. The legacy
// mechanisms -- AES-CBC and RSA PKCS#1 v1.5 -- authenticate nothing, so
// trying keys would return garbage or act as a padding oracle, and they
// need the caller's key version instead.
func (m wrapMechanism) authenticated() bool {
	return !m.legacy
}

// wrapMechanisms maps each canonical algorithm onto its normalized mechanism.
// A map rather than a switch, per the project's dispatch convention, and a
// single table so an algorithm cannot be accepted by wrap but refused by
// unwrap. The keys are types.KeyWrapAlgorithm constants, so a renamed constant
// is a compile error rather than a request the service starts rejecting.
var wrapMechanisms = map[types.KeyWrapAlgorithm]wrapMechanism{
	types.WrapAESKW:         {kind: kindAESKW},
	types.WrapAESKWP:        {kind: kindAESKWP},
	types.WrapAES128KWP:     {kind: kindAESKWP},
	types.WrapAES256KWP:     {kind: kindAESKWP},
	types.WrapAESGCM:        {kind: kindAESGCM},
	types.WrapAESCBC:        {kind: kindAESCBC, legacy: true},
	types.WrapAESCBCPad:     {kind: kindAESCBCPad, legacy: true},
	types.WrapRSAPKCS1v15:   {kind: kindRSAPKCS1v15, legacy: true},
	types.WrapRSAOAEPSHA256: {kind: kindRSAOAEP, digest: crypto.SHA256},
	types.WrapRSAOAEPSHA384: {kind: kindRSAOAEP, digest: crypto.SHA384},
	types.WrapRSAOAEPSHA512: {kind: kindRSAOAEP, digest: crypto.SHA512},
	types.WrapRSAOAEPSHA1:   {kind: kindRSAOAEP, digest: crypto.SHA1, weak: true},
}

// resolveWrapMechanism normalizes a requested algorithm. An unknown algorithm
// and one refused by policy are distinguished: reporting a weak digest as
// "unsupported" would send an operator looking for a missing feature instead
// of a rejected one.
//
// Two refusals live here and they are not the same refusal. mech.weak is
// unconditional -- SHA-1 OAEP is rejected in every configuration -- while
// mech.legacy is a policy the operator can reverse, and the error says so and
// names the setting. Both are checked before the mechanism is returned, so
// wrap and unwrap enforce them identically; the table is deliberately shared so
// an algorithm cannot be accepted by one and refused by the other.
//
// The legacy gate covers wrap as well as unwrap even though the oracle is an
// unwrap-side property. Permitting a wrap whose matching unwrap is refused
// would hand a caller a blob this service will not read back, which is a worse
// answer than refusing the wrap.
func resolveWrapMechanism(algorithm, operation string) (wrapMechanism, error) {
	mech, ok := wrapMechanisms[types.KeyWrapAlgorithm(algorithm)]
	if !ok {
		return wrapMechanism{}, &ErrValidation{
			Sentinel: ErrOperationNotSupported,
			Detail:   "unsupported " + operation + " algorithm: " + algorithm,
		}
	}
	if mech.weak {
		return wrapMechanism{}, &ErrOperationWrap{
			Sentinel: ErrWeakOAEPHash,
			Detail:   "RSA-OAEP key wrapping requires SHA-256 or stronger; " + algorithm + " is rejected",
		}
	}
	if mech.legacy && !types.AllowLegacyKeyWrap() {
		reason, _ := types.LegacyKeyWrapReason(types.KeyWrapAlgorithm(algorithm))
		return wrapMechanism{}, &ErrValidation{
			Sentinel: ErrLegacyWrapDisabled,
			Detail: algorithm + " is refused for " + operation + ": " + reason +
				". Set crypto.allow_legacy_key_wrap=true to enable it (ignored in FIPS mode, where the validated module's approved mechanism set applies)",
		}
	}
	return mech, nil
}

// wrapParams carries the CK_MECHANISM parameters a PKCS#11 C_WrapKey or
// C_UnwrapKey caller supplied, alongside the algorithm that names the
// construction.
//
// They travel as one struct rather than as request fields read at each call
// site so wrap and unwrap cannot resolve them differently: every field here is
// a value both halves must agree on exactly. A nonce or IV that differs
// decrypts to garbage, AAD that differs fails authentication, a tag length
// that differs reads as a forgery (NIST SP 800-38D §5.2.2), and an RSA-OAEP
// label that differs fails OAEP decoding (RFC 8017 §7.1.2).
//
// Dropping them was silent in exactly the case that matters: a caller naming
// CK_RSA_PKCS_OAEP_PARAMS.pSourceData got a blob encrypted under the empty
// label and a success, and a round trip through this service alone still
// passed because both halves dropped it identically. Only a peer that honoured
// the label could tell, which is the one observation a self-test never makes.
type wrapParams struct {
	// iv is CK_GCM_PARAMS.pIv, or the AES-CBC initialization vector. On wrap,
	// empty asks the provider to generate one. On unwrap it is optional and
	// asserts what the blob must contain: see checkFramedIV.
	iv []byte

	// aad is CK_GCM_PARAMS.pAAD, authenticated but not encrypted. It is not
	// carried in the blob, so an unwrap must repeat it.
	aad []byte

	// tagBits is CK_GCM_PARAMS.ulTagBits. Zero selects the full-length tag.
	tagBits int

	// oaepLabel is CK_RSA_PKCS_OAEP_PARAMS.pSourceData.
	oaepLabel []byte
}

// gcmTagBytes converts CK_GCM_PARAMS.ulTagBits into the tag length in bytes
// both halves of an AES-GCM wrap must use.
//
// PKCS#11 v3.2 §6.13.3 and NIST SP 800-38D §5.2.1.2 admit 96, 104, 112, 120
// and 128 bits, a t-bit tag being the leading t bits of the full tag. Zero
// means the caller expressed no preference and takes the full 128-bit tag,
// which is what SP 800-38D appendix C recommends absent a supporting analysis.
func (p wrapParams) gcmTagBytes() (int, error) {
	if p.tagBits == 0 {
		return aesGCMTagSize, nil
	}
	if p.tagBits%8 != 0 || p.tagBits < 96 || p.tagBits > 128 {
		return 0, &ErrValidation{
			Sentinel: ErrInvalidKeyAttributes,
			Detail:   "aes-gcm tag length must be 96, 104, 112, 120 or 128 bits",
		}
	}
	return p.tagBits / 8, nil
}

// checkCallerIV refuses a caller-supplied IV or nonce of the wrong length
// before it reaches the provider, so a wrap cannot silently proceed under an
// IV other than the one the caller named.
func checkCallerIV(iv []byte, want int, mechanism string) error {
	if len(iv) == 0 || len(iv) == want {
		return nil
	}
	return &ErrValidation{
		Sentinel: ErrInvalidKeyAttributes,
		Detail:   mechanism + " initialization vector must be " + strconv.Itoa(want) + " bytes",
	}
}

// checkFramedIV enforces a caller-supplied IV on the unwrap side.
//
// The blob is self-describing, so the IV it carries is what the unwrap uses.
// A caller that names one anyway is asserting which blob this is, and an
// assertion that does not hold must be refused rather than ignored: silently
// unwrapping under a different IV than the caller named is the same class of
// fault as dropping the parameter altogether.
func checkFramedIV(want, framed []byte, mechanism string) error {
	if len(want) == 0 || bytes.Equal(want, framed) {
		return nil
	}
	return &ErrValidation{
		Sentinel: ErrInvalidKeyAttributes,
		Detail:   mechanism + " wrapped key material was not produced with the initialization vector supplied",
	}
}

// aesGCMNonceSize and aesGCMTagSize describe the self-describing wire format
// wrapKeyMaterial/unwrapKeyMaterial use for CKM_AES_GCM: nonce || ciphertext
// || tag. WrapKeyByIDResponse/UnwrapKeyByIDRequest carry a single opaque
// WrappedKey blob with no separate nonce/tag fields (unlike, say,
// module_authwrap.go's C_WrapKeyAuthenticated, which threads
// CK_GCM_PARAMS.pIv end to end on a request built for exactly that), so the
// blob must carry everything needed to reverse it.
const (
	aesGCMNonceSize = 12
	aesGCMTagSize   = 16
)

// aesGCMWrapModeExplicit and aesGCMWrapModeRandom are the one-byte prefix
// wrapAESGCM/unwrapAESGCM add ahead of the nonce, mirroring
// types.GCMNonceMode: explicit for a caller- or RNG-supplied nonce Seal took
// as a parameter, random when GODEBUG=fips140=only forced the wrap through
// cipher.NewGCMWithRandomNonce (see docs/fips/README.md "AEAD construction").
// unwrapAESGCM cannot otherwise tell which construction to rebuild -- the
// process unwrapping a blob is not necessarily the one that wrapped it, so
// its own current FIPS posture says nothing about how the blob was made.
const (
	aesGCMWrapModeExplicit byte = 0x00
	aesGCMWrapModeRandom   byte = 0x01
)

// unwrapOperationNames gives the ErrKeyOperation.Operation label each mechanism
// reports when an unwrap fails.
//
// It is a table rather than a literal at each site because the label is part of
// what makes two failures indistinguishable. The zero-length guard in
// unwrapKeyMaterial first reported the caller-supplied algorithm string
// ("RSA_PKCS1_V1_5 unwrap") while the decryption failure beside it reported
// "rsa-pkcs unwrap", so a conformant-but-empty PKCS#1 v1.5 ciphertext was
// distinguishable from a non-conformant one by the label alone -- the very
// oracle answer ErrUnwrapCiphertextRejected exists to withhold.
// TestUnwrapRSAPKCS1v15_RejectsConformantEmptyPayload holds the two together.
var unwrapOperationNames = map[wrapKind]string{
	kindAESKW:       "aes-kw unwrap",
	kindAESKWP:      "aes-kwp unwrap",
	kindAESGCM:      "aes-gcm unwrap",
	kindAESCBC:      string(types.CipherModeCBC) + " unwrap",
	kindAESCBCPad:   string(types.CipherModeCBCPad) + " unwrap",
	kindRSAOAEP:     "rsa-oaep unwrap",
	kindRSAPKCS1v15: "rsa-pkcs unwrap",
}

// wrapKeyMaterial encrypts (wraps) keyMaterial under the real,
// caller-designated wrapping key described by wrappingAttrs, using the
// PKCS#11 mechanism named by algorithm.
//
// This is the C_WrapKey primitive: the wrapping key already exists and is
// used as-is. It is deliberately independent of
// backend.ImportExportBackend.GetImportParameters/WrapKey, which serve a
// different feature (the key-IMPORT ceremony) and always wrap under a
// freshly generated ephemeral key pair rather than an existing one.
func wrapKeyMaterial(ctx context.Context, b Backend, wrappingAttrs *types.KeyAttributes, algorithm string, params wrapParams, keyMaterial []byte) ([]byte, error) {
	mech, err := resolveWrapMechanism(algorithm, "wrap")
	if err != nil {
		return nil, err
	}

	switch mech.kind {
	case kindAESKW:
		return wrapAESKeyWrap(ctx, b, wrappingAttrs, keyMaterial)
	case kindAESKWP:
		return wrapAESKeyWrapPad(ctx, b, wrappingAttrs, keyMaterial)
	case kindAESGCM:
		return wrapAESGCM(ctx, b, wrappingAttrs, params, keyMaterial)
	case kindAESCBC:
		return wrapAESCBC(ctx, b, wrappingAttrs, types.CipherModeCBC, params, keyMaterial)
	case kindAESCBCPad:
		return wrapAESCBC(ctx, b, wrappingAttrs, types.CipherModeCBCPad, params, keyMaterial)
	case kindRSAOAEP:
		return wrapRSAOAEP(ctx, b, wrappingAttrs, mech.digest, params.oaepLabel, keyMaterial)
	case kindRSAPKCS1v15:
		return wrapRSAPKCS1v15(ctx, b, wrappingAttrs, keyMaterial)
	default:
		// Unreachable: resolveWrapMechanism only returns kinds handled above.
		// Fail closed rather than fall through to a nil wrap.
		return nil, &ErrValidation{Sentinel: ErrOperationNotSupported, Detail: "unsupported wrap algorithm: " + algorithm}
	}
}

// unwrapKeyMaterial inverts wrapKeyMaterial: it decrypts wrapped under the
// real, caller-designated unwrapping key described by unwrappingAttrs. This
// is the C_UnwrapKey primitive and shares the same independence from the
// import ceremony as wrapKeyMaterial above.
func unwrapKeyMaterial(ctx context.Context, b Backend, unwrappingAttrs *types.KeyAttributes, algorithm string, params wrapParams, wrapped []byte) ([]byte, error) {
	mech, err := resolveWrapMechanism(algorithm, "unwrap")
	if err != nil {
		return nil, err
	}

	var (
		plaintext []byte
		unwrapErr error
	)
	switch mech.kind {
	case kindAESKW:
		plaintext, unwrapErr = unwrapAESKeyWrap(ctx, b, unwrappingAttrs, wrapped)
	case kindAESKWP:
		plaintext, unwrapErr = unwrapAESKeyWrapPad(ctx, b, unwrappingAttrs, wrapped)
	case kindAESGCM:
		plaintext, unwrapErr = unwrapAESGCM(ctx, b, unwrappingAttrs, params, wrapped)
	case kindAESCBC:
		plaintext, unwrapErr = unwrapAESCBC(ctx, b, unwrappingAttrs, types.CipherModeCBC, params, wrapped)
	case kindAESCBCPad:
		plaintext, unwrapErr = unwrapAESCBC(ctx, b, unwrappingAttrs, types.CipherModeCBCPad, params, wrapped)
	case kindRSAOAEP:
		plaintext, unwrapErr = unwrapRSAOAEP(ctx, b, unwrappingAttrs, mech.digest, params.oaepLabel, wrapped)
	case kindRSAPKCS1v15:
		plaintext, unwrapErr = unwrapRSAPKCS1v15(ctx, b, unwrappingAttrs, wrapped)
	default:
		return nil, &ErrValidation{Sentinel: ErrOperationNotSupported, Detail: "unsupported unwrap algorithm: " + algorithm}
	}
	if unwrapErr != nil {
		return nil, unwrapErr
	}

	// A zero-length result is not a key, and reaching one means the blob was
	// accepted for the wrong reason. RSA-PKCS#1 v1.5 gets here whenever a
	// ciphertext happens to be padding-conformant around an empty payload,
	// which is precisely the Bleichenbacher adversary's cheapest hit: before
	// this check that call returned (nil error, empty key material), handing
	// the attacker a confirmed conformant ciphertext AND a key object.
	// unwrapAESCBC already refused the analogous empty-ciphertext case for the
	// same reason; the rule belongs to every mechanism, applied once, here.
	//
	// It reports ErrUnwrapCiphertextRejected so it is indistinguishable from a
	// decryption failure -- reporting it separately would restore the oracle
	// answer the check exists to withhold.
	if len(plaintext) == 0 {
		return nil, &ErrKeyOperation{
			Operation: unwrapOperationNames[mech.kind],
			KeyID:     unwrappingAttrs.CN,
			Err:       ErrUnwrapCiphertextRejected,
		}
	}
	return plaintext, nil
}

// rawSymmetricWrappingKey returns the raw bytes of the symmetric key
// described by attrs, for wrap algorithms that are not an AEAD construction
// (CKM_AES_KEY_WRAP) and so have no types.SymmetricEncrypter operation to
// use instead. This reads the key material in-process rather than treating
// it as an export: unlike ImportExportBackend.ExportKeyMaterial (which
// releases a key's value to the caller across the wire), these bytes never
// leave the process.
//
// The returned slice belongs to the caller, which every backend's
// types.SymmetricKey.Raw guarantees by handing back a defensive copy (the
// hardware-backed backends refuse the call outright). The caller must
// therefore wipe it with secure.Wipe on every path, deferred, so that a
// key-encryption key is not left in the heap for the garbage collector to
// hand to whatever allocates next.
func rawSymmetricWrappingKey(ctx context.Context, b Backend, attrs *types.KeyAttributes) ([]byte, error) {
	symProvider, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported, Detail: "wrapping key backend does not support symmetric keys"}
	}
	key, err := symProvider.GetSymmetricKey(ctx, attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get symmetric wrapping key", KeyID: attrs.CN, Err: err}
	}
	raw, err := key.Raw()
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "read raw wrapping key material", KeyID: attrs.CN, Err: err}
	}
	return raw, nil
}

// wrapAESKeyWrap wraps keyMaterial under an AES key-encryption key using
// RFC 3394 AES Key Wrap (CKM_AES_KEY_WRAP).
func wrapAESKeyWrap(ctx context.Context, b Backend, attrs *types.KeyAttributes, keyMaterial []byte) ([]byte, error) {
	kek, err := rawSymmetricWrappingKey(ctx, b, attrs)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(kek)
	wrapped, err := wrapping.WrapAESKW(keyMaterial, kek)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "aes-kw wrap", KeyID: attrs.CN, Err: err}
	}
	return wrapped, nil
}

// unwrapAESKeyWrap inverts wrapAESKeyWrap.
func unwrapAESKeyWrap(ctx context.Context, b Backend, attrs *types.KeyAttributes, wrapped []byte) ([]byte, error) {
	kek, err := rawSymmetricWrappingKey(ctx, b, attrs)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(kek)
	plaintext, err := wrapping.UnwrapAESKW(wrapped, kek)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: unwrapOperationNames[kindAESKW], KeyID: attrs.CN, Err: err}
	}
	return plaintext, nil
}

// wrapAESKeyWrapPad wraps keyMaterial under an AES key-encryption key using
// RFC 5649 AES Key Wrap with Padding (CKM_AES_KEY_WRAP_PAD). It shares
// wrapAESKeyWrap's in-process read of the KEK for the same reason: neither
// construction is an AEAD, so there is no types.SymmetricEncrypter operation
// to express it through.
func wrapAESKeyWrapPad(ctx context.Context, b Backend, attrs *types.KeyAttributes, keyMaterial []byte) ([]byte, error) {
	kek, err := rawSymmetricWrappingKey(ctx, b, attrs)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(kek)
	wrapped, err := wrapping.WrapAESKWP(keyMaterial, kek)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "aes-kwp wrap", KeyID: attrs.CN, Err: err}
	}
	return wrapped, nil
}

// unwrapAESKeyWrapPad inverts wrapAESKeyWrapPad.
func unwrapAESKeyWrapPad(ctx context.Context, b Backend, attrs *types.KeyAttributes, wrapped []byte) ([]byte, error) {
	kek, err := rawSymmetricWrappingKey(ctx, b, attrs)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(kek)
	plaintext, err := wrapping.UnwrapAESKWP(wrapped, kek)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: unwrapOperationNames[kindAESKWP], KeyID: attrs.CN, Err: err}
	}
	return plaintext, nil
}

// wrapAESGCM wraps keyMaterial under an AES key using the key's own
// SymmetricEncrypter (the same AEAD path the generic Encrypt RPC uses),
// rather than reading its raw bytes: CKM_AES_GCM is an AEAD construction,
// so the key never needs to leave the SymmetricEncrypter abstraction. The
// nonce and tag are prefixed/suffixed into the returned blob (see
// aesGCMNonceSize/aesGCMTagSize) since WrapKeyByIDResponse carries only a
// single WrappedKey field.
func wrapAESGCM(ctx context.Context, b Backend, attrs *types.KeyAttributes, params wrapParams, keyMaterial []byte) ([]byte, error) {
	tagSize, err := params.gcmTagBytes()
	if err != nil {
		return nil, err
	}
	if err := checkCallerIV(params.iv, aesGCMNonceSize, "aes-gcm"); err != nil {
		return nil, err
	}

	symProvider, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported, Detail: "wrapping key backend does not support symmetric keys"}
	}
	encrypter, err := symProvider.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get symmetric wrapping encrypter", KeyID: attrs.CN, Err: err}
	}

	// The (wrapping key, IV) pair is claimed here: after every check above --
	// the tag length, the IV length, and the backend's own resolution of the
	// key -- and immediately before the AEAD call. Claiming any earlier would
	// burn the IV of a wrap that was going to be refused anyway, and the
	// caller's corrected retry with that same IV would then be refused as a
	// reuse of a wrap that never happened.
	if len(params.iv) > 0 {
		if err := claimAEADNonce(ctx, b, attrs, gcmWrapOperation, params.iv); err != nil {
			return nil, err
		}
	}

	// A caller-supplied nonce reaches the provider verbatim; an empty one asks
	// it to generate one. Either way the nonce comes back on the result and is
	// prefixed to the blob, so a token-generated nonce is never lost.
	opts := &types.EncryptOptions{Nonce: params.iv, AdditionalData: params.aad}
	if params.tagBits != 0 {
		opts.TagSize = tagSize
	}

	encrypted, err := encrypter.Encrypt(keyMaterial, opts)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: gcmWrapOperation, KeyID: attrs.CN, Err: err}
	}
	if len(encrypted.Nonce) != aesGCMNonceSize || len(encrypted.Tag) != tagSize {
		return nil, &ErrKeyOperation{
			Operation: gcmWrapOperation,
			KeyID:     attrs.CN,
			Err:       ErrOperationFailed,
		}
	}

	// A nonce the provider generated is claimed too, once it is known. The
	// guard exists to catch a repeat whatever produced it, and a provider whose
	// RNG has stopped producing fresh values is precisely the failure that
	// makes a generated IV unsafe. The blob is withheld when the claim fails:
	// the encryption has already happened by then, so the one thing still worth
	// preventing is the second ciphertext under that pair reaching anybody.
	if len(params.iv) == 0 {
		if err := claimAEADNonce(ctx, b, attrs, gcmWrapOperation, encrypted.Nonce); err != nil {
			return nil, err
		}
	}

	modeByte := aesGCMWrapModeExplicit
	if encrypted.GCMNonceMode == types.GCMNonceModeRandom {
		modeByte = aesGCMWrapModeRandom
	}

	out := make([]byte, 0, 1+len(encrypted.Nonce)+len(encrypted.Ciphertext)+len(encrypted.Tag))
	out = append(out, modeByte)
	out = append(out, encrypted.Nonce...)
	out = append(out, encrypted.Ciphertext...)
	out = append(out, encrypted.Tag...)
	return out, nil
}

// unwrapAESGCM inverts wrapAESGCM.
func unwrapAESGCM(ctx context.Context, b Backend, attrs *types.KeyAttributes, params wrapParams, wrapped []byte) ([]byte, error) {
	tagSize, err := params.gcmTagBytes()
	if err != nil {
		return nil, err
	}
	if len(wrapped) < 1+aesGCMNonceSize+tagSize {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "aes-gcm wrapped key material is too short"}
	}
	modeByte := wrapped[0]
	body := wrapped[1:]
	var nonceMode types.GCMNonceMode
	switch modeByte {
	case aesGCMWrapModeExplicit:
		nonceMode = types.GCMNonceModeExplicit
	case aesGCMWrapModeRandom:
		nonceMode = types.GCMNonceModeRandom
	default:
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "aes-gcm wrapped key material has an unrecognized nonce-mode byte"}
	}
	nonce := body[:aesGCMNonceSize]
	tag := body[len(body)-tagSize:]
	ciphertext := body[aesGCMNonceSize : len(body)-tagSize]

	if err := checkFramedIV(params.iv, nonce, "aes-gcm"); err != nil {
		return nil, err
	}

	symProvider, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported, Detail: "unwrapping key backend does not support symmetric keys"}
	}
	encrypter, err := symProvider.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get symmetric unwrapping encrypter", KeyID: attrs.CN, Err: err}
	}

	decryptOpts := &types.DecryptOptions{AdditionalData: params.aad}
	if params.tagBits != 0 {
		decryptOpts.TagSize = tagSize
	}

	plaintext, err := encrypter.Decrypt(&types.EncryptedData{
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		Tag:          tag,
		GCMNonceMode: nonceMode,
	}, decryptOpts)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: unwrapOperationNames[kindAESGCM], KeyID: attrs.CN, Err: err}
	}
	return plaintext, nil
}

// aesCBCIVSize is the length of the AES-CBC initialization vector, which
// RFC 3602 and PKCS#11 v3.2 §6.10 both fix at one AES block.
const aesCBCIVSize = 16

// wrapAESCBC wraps keyMaterial under an AES key using CBC, the mechanism
// PKCS#11 v3.2 §6.10 lists with CKF_WRAP for both CKM_AES_CBC (mode
// types.CipherModeCBC) and CKM_AES_CBC_PAD (types.CipherModeCBCPad).
//
// Both are refused unless crypto.allow_legacy_key_wrap is set; see
// unwrapAESCBC for what the missing integrity check costs.
//
// §6.10.3 says the unpadded mechanism wraps "the value of the CKA_VALUE
// attribute of the key that is wrapped, padded on the trailing end with up to
// block size minus one null bytes so that the resulting length is a multiple
// of the block size", and §6.10.4 that the padded mechanism applies PKCS#7
// instead. Neither is applied here: the symmetric provider owns both
// behaviours (encryptCBC pads for CipherModeCBCPad and refuses a
// non-block-aligned input otherwise), so key material whose length is not a
// multiple of the block size is refused rather than silently null-padded into
// something the caller cannot distinguish on the way back.
//
// The IV is prefixed to the returned blob for the same reason wrapAESGCM
// prefixes its nonce: WrapKeyByIDResponse carries a single opaque WrappedKey
// field and no separate IV, so a blob that did not describe itself could not be
// unwrapped. CBC's IV is not secret -- it only needs to be unpredictable -- so
// carrying it in the clear alongside the ciphertext costs nothing.
//
// Unlike wrapAESKeyWrap, this goes through the key's own SymmetricEncrypter
// rather than reading the raw KEK, because the provider already implements the
// mode; the key never leaves the abstraction.
func wrapAESCBC(ctx context.Context, b Backend, attrs *types.KeyAttributes, mode types.CipherMode, params wrapParams, keyMaterial []byte) ([]byte, error) {
	if err := checkCallerIV(params.iv, aesCBCIVSize, string(mode)); err != nil {
		return nil, err
	}

	symProvider, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported, Detail: "wrapping key backend does not support symmetric keys"}
	}
	encrypter, err := symProvider.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get symmetric wrapping encrypter", KeyID: attrs.CN, Err: err}
	}

	encrypted, err := encrypter.Encrypt(keyMaterial, &types.EncryptOptions{Mode: mode, IV: params.iv})
	if err != nil {
		return nil, &ErrKeyOperation{Operation: string(mode) + " wrap", KeyID: attrs.CN, Err: err}
	}
	if len(encrypted.IV) != aesCBCIVSize {
		return nil, &ErrKeyOperation{Operation: string(mode) + " wrap", KeyID: attrs.CN, Err: ErrOperationFailed}
	}

	out := make([]byte, 0, len(encrypted.IV)+len(encrypted.Ciphertext))
	out = append(out, encrypted.IV...)
	out = append(out, encrypted.Ciphertext...)
	return out, nil
}

// unwrapAESCBC inverts wrapAESCBC, splitting the IV back off the front of the
// blob. A blob carrying no ciphertext at all is refused here rather than passed
// down: CBC decryption of zero blocks yields an empty key, which is not a key.
//
// NEITHER MODE PROVIDES INTEGRITY, AND AN UNWRAP SUCCESS HERE IS NOT
// AUTHENTICATION. A caller must never read one as evidence that the blob came
// from this service, from the holder of the unwrapping key, or from anywhere in
// particular. Unpadded CBC (types.CipherModeCBC) checks nothing whatsoever: any
// blob of a whole number of blocks decrypts, so a random 48-byte input returns
// 32 bytes of key material with a nil error on the first try -- measured, not
// theorised. CipherModeCBCPad checks only that the last plaintext byte
// describes valid PKCS#7 padding, which random input satisfies about once in
// 256 tries (215, measured). What comes back in either case is the decryption
// of whatever the caller supplied, and UnwrapKeyByID imports it as a usable
// key: the caller chooses the ciphertext, the service chooses nothing.
//
// PKCS#11 v3.2 section 6.10 does sanction both mechanisms for C_UnwrapKey, so
// this is a deployment policy and not a conformance deviation, and both are
// gated off by default rather than removed: resolveWrapMechanism refuses them
// with ErrLegacyWrapDisabled unless crypto.allow_legacy_key_wrap is set. An
// operator who must interoperate with an application that requires them can
// turn them on, at the cost of a reported compliance gap.
func unwrapAESCBC(ctx context.Context, b Backend, attrs *types.KeyAttributes, mode types.CipherMode, params wrapParams, wrapped []byte) ([]byte, error) {
	if len(wrapped) <= aesCBCIVSize {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "aes-cbc wrapped key material is too short"}
	}
	iv := wrapped[:aesCBCIVSize]
	ciphertext := wrapped[aesCBCIVSize:]

	if err := checkFramedIV(params.iv, iv, string(mode)); err != nil {
		return nil, err
	}

	symProvider, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{Sentinel: ErrSymmetricNotSupported, Detail: "unwrapping key backend does not support symmetric keys"}
	}
	encrypter, err := symProvider.SymmetricEncrypter(ctx, attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get symmetric unwrapping encrypter", KeyID: attrs.CN, Err: err}
	}

	// Every way this decrypt can fail -- PKCS#7 unpadding (CipherModeCBCPad),
	// a ciphertext that is not a whole number of blocks, anything the provider
	// reports -- collapses to ErrUnwrapCiphertextRejected. CKM_AES_CBC_PAD
	// unwrap is a textbook Vaudenay padding oracle otherwise: the provider's
	// unpadPKCS7 is already constant-time and already returns one
	// ErrInvalidPadding for all its own failure modes, and this preserves that
	// property across the service boundary instead of re-splitting it into
	// "invalid padding" and "not block aligned" on the wire.
	plaintext, err := encrypter.Decrypt(&types.EncryptedData{
		Ciphertext: ciphertext,
		IV:         iv,
	}, &types.DecryptOptions{Mode: mode})
	if err != nil {
		return nil, &ErrKeyOperation{Operation: string(mode) + " unwrap", KeyID: attrs.CN, Err: ErrUnwrapCiphertextRejected}
	}
	return plaintext, nil
}

// rsaWrappingPublicKey resolves the RSA public key to wrap under, mirroring
// how XKMSService.EncryptAsym and asymEncrypterKey both resolve a key's
// public half.
func rsaWrappingPublicKey(ctx context.Context, b Backend, attrs *types.KeyAttributes) (*rsa.PublicKey, error) {
	privKey, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get wrapping key", KeyID: attrs.CN, Err: err}
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyType, Detail: "wrapping key does not implement crypto.Signer"}
	}
	rsaPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyType, Detail: "wrapping key is not RSA"}
	}
	return rsaPub, nil
}

// wrapRSAOAEP wraps keyMaterial under an RSA public key using RSA-OAEP
// (CKM_RSA_PKCS_OAEP).
//
// The digest comes from the resolved mechanism, not from a constant here: a
// canonical suite name carries its own hash (RSAES_OAEP_SHA_256), while a
// bare PKCS#11 mechanism name (rsa-oaep) carries none and takes the
// project-wide SHA-256 default that EncryptAsym and CryptoManager also apply.
// SHA-1 OAEP is refused before reaching this function (ErrWeakOAEPHash).
//
// Selecting a digest the suite vocabulary cannot express (e.g. SHA-384 via
// CK_RSA_PKCS_OAEP_PARAMS) still needs an explicit OAEP-hash field on
// WrapKeyByIDRequest/UnwrapKeyByIDRequest.
func wrapRSAOAEP(ctx context.Context, b Backend, attrs *types.KeyAttributes, digest crypto.Hash, label, keyMaterial []byte) ([]byte, error) {
	rsaPub, err := rsaWrappingPublicKey(ctx, b, attrs)
	if err != nil {
		return nil, err
	}
	// label is CK_RSA_PKCS_OAEP_PARAMS.pSourceData, the RFC 8017 §7.1 encoding
	// parameter L. It is bound into the ciphertext, so a wrap that dropped it
	// produced a blob no label-using peer could read while reporting success.
	wrapped, err := rsa.EncryptOAEP(digest.New(), rand.Reader, rsaPub, keyMaterial, label)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "rsa-oaep wrap", KeyID: attrs.CN, Err: err}
	}
	return wrapped, nil
}

// unwrapRSAOAEP inverts wrapRSAOAEP, using the unwrapping key's own
// crypto.Decrypter (the same resolution Decrypt uses for its asymmetric
// fallback) rather than a freshly generated key.
func unwrapRSAOAEP(ctx context.Context, b Backend, attrs *types.KeyAttributes, digest crypto.Hash, label, wrapped []byte) ([]byte, error) {
	decrypter, err := b.Decrypter(ctx, attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get unwrapping decrypter", KeyID: attrs.CN, Err: err}
	}
	// One error for every decryption failure. OAEP's decoding is not the
	// Bleichenbacher shape, but RFC 8017 section 7.1.2 gives it the same rule
	// for the same reason -- Manger's attack distinguishes the integer-too-large
	// check from the decoding check -- and crypto/rsa.DecryptOAEP is written to
	// return one rsa.ErrDecryption in constant time. A backend that is not
	// crypto/rsa may not be so careful, so its diagnostics stop here.
	plaintext, err := decrypter.Decrypt(rand.Reader, wrapped, &rsa.OAEPOptions{Hash: digest, Label: label})
	if err != nil {
		return nil, &ErrKeyOperation{Operation: unwrapOperationNames[kindRSAOAEP], KeyID: attrs.CN, Err: ErrUnwrapCiphertextRejected}
	}
	return plaintext, nil
}

// wrapRSAPKCS1v15 wraps keyMaterial under an RSA public key using PKCS#1
// v1.5 encryption (CKM_RSA_PKCS), matching Decrypt's/Encrypt's own PKCS#1
// v1.5 default for an unnamed padding.
//
// Like the CBC pair, it is refused unless crypto.allow_legacy_key_wrap is set:
// PKCS#1 v1.5 authenticates nothing, and the conformance check its unwrap
// performs is the Bleichenbacher oracle.
func wrapRSAPKCS1v15(ctx context.Context, b Backend, attrs *types.KeyAttributes, keyMaterial []byte) ([]byte, error) {
	rsaPub, err := rsaWrappingPublicKey(ctx, b, attrs)
	if err != nil {
		return nil, err
	}
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, keyMaterial) //nolint:staticcheck // SA1019: CKM_RSA_PKCS is PKCS#1 v1.5 by definition; gated on crypto.allow_legacy_key_wrap
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "rsa-pkcs wrap", KeyID: attrs.CN, Err: err}
	}
	return wrapped, nil
}

// unwrapRSAPKCS1v15 inverts wrapRSAPKCS1v15.
func unwrapRSAPKCS1v15(ctx context.Context, b Backend, attrs *types.KeyAttributes, wrapped []byte) ([]byte, error) {
	decrypter, err := b.Decrypter(ctx, attrs)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "get unwrapping decrypter", KeyID: attrs.CN, Err: err}
	}
	// nil DecrypterOpts selects PKCS#1 v1.5, per asymDecrypterOpts's
	// documented default and crypto.Decrypter's own contract.
	//
	// The failure is reported as ErrUnwrapCiphertextRejected and nothing else.
	// RFC 8017 section 7.2.2: "it is important that ... the error message
	// output ... not reveal which check failed", because a distinguishable
	// failure is the conformance oracle Bleichenbacher's attack (and its Marvin
	// refinement) needs. crypto/rsa.DecryptPKCS1v15 already returns a single
	// rsa.ErrDecryption in constant time; a PKCS#11 token or a cloud KMS
	// returns whatever it likes, and none of it goes on the wire from here.
	plaintext, err := decrypter.Decrypt(rand.Reader, wrapped, nil)
	if err != nil {
		return nil, &ErrKeyOperation{Operation: unwrapOperationNames[kindRSAPKCS1v15], KeyID: attrs.CN, Err: ErrUnwrapCiphertextRejected}
	}
	return plaintext, nil
}

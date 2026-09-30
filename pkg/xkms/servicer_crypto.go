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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// defaultECDHKeyLength is the derived-key length in bytes used when a
// DeriveKeyECDH request does not specify one. 32 bytes yields an AES-256 key.
const defaultECDHKeyLength = 32

// defaultDerivedKeyLength is the derived-key length in bytes used when a
// DeriveKey request does not specify one. 32 bytes yields an AES-256 key.
const defaultDerivedKeyLength = 32

// deriveKeyBridge describes how one DeriveKey algorithm name maps onto the
// canonical kdf package: which adapter implements it, and which of the
// request's KDF inputs that construction actually consumes.
//
// The applicability flags exist because the request type carries HKDF's
// vocabulary (Salt, Info) alongside SP 800-108's (Label, Context), and no
// construction consumes all four. A field the selected algorithm has no input
// for is refused rather than dropped: an ignored KDF input yields a key derived
// from parameters the caller did not choose, and the response looks exactly
// like a successful derivation.
type deriveKeyBridge struct {
	// newAdapter constructs the canonical adapter for this algorithm.
	newAdapter func() kdf.KDFAdapter

	// usesSaltInfo marks the extract-and-expand construction (HKDF), whose
	// inputs are the salt and the info string.
	usesSaltInfo bool

	// usesLabelContext marks the SP 800-108r1 modes, whose fixed input data
	// is assembled from a label and a context.
	usesLabelContext bool

	// usesSaltAsIV marks SP 800-108 Feedback Mode, the one construction with
	// an initial value K(0). The wire has no IV field, so the salt carries it;
	// this is the same convention DeriveKeyECDH uses (see buildECDHKDFParams).
	usesSaltAsIV bool
}

// kdfFactory provides O(1) dispatch for KDF algorithm selection. It is the only
// DeriveKey parameter assembly in the process: the gRPC service used to carry a
// second, independent one, and the two had already drifted — a salt supplied
// with SP 800-108 Feedback Mode became K(0) over gRPC and was silently dropped
// everywhere else, so the same request derived two different keys depending on
// which transport carried it.
var kdfFactory = map[string]deriveKeyBridge{
	"hkdf": {
		newAdapter:   func() kdf.KDFAdapter { return kdf.NewHKDFAdapter() },
		usesSaltInfo: true,
	},
	"sp800-108-counter": {
		newAdapter:       func() kdf.KDFAdapter { return kdf.NewSP800108CounterAdapter() },
		usesLabelContext: true,
	},
	"sp800-108-feedback": {
		newAdapter:       func() kdf.KDFAdapter { return kdf.NewSP800108FeedbackAdapter() },
		usesLabelContext: true,
		usesSaltAsIV:     true,
	},
	"sp800-108-double-pipeline": {
		newAdapter:       func() kdf.KDFAdapter { return kdf.NewSP800108DoublePipelineAdapter() },
		usesLabelContext: true,
	},
}

// kdfAlgorithms maps the wire-level KDF algorithm names to their canonical
// types.KDFAlgorithm values for O(1) lookup.
var kdfAlgorithms = map[string]types.KDFAlgorithm{
	"HKDF":               types.KDFAlgorithmHKDF,
	"SP800-108-COUNTER":  types.KDFAlgorithmSP800108Counter,
	"SP800-108-FEEDBACK": types.KDFAlgorithmSP800108Feedback,
	"SP800-56A":          types.KDFAlgorithmSP80056A,
	"X963":               types.KDFAlgorithmX963,

	// "RAW" is the wire name for "apply no KDF": the shared secret itself,
	// truncated to the requested length. It is PKCS#11's CKD_NULL. It has to
	// be a name a caller can say, distinct from saying nothing, because saying
	// nothing means "I did not choose" and resolves to HKDF.
	"RAW": types.KDFAlgorithmRaw,
}

// kdfHashNames maps a caller-supplied hash name, stripped of separators and
// upper-cased, to its canonical spelling.
// The SHA-1, SHA-224 and SHA3-224 spellings are here because the two
// concatenation KDFs accept those hashes (ANSI X9.63, SP 800-56A Rev. 3,
// PKCS#11 v3.0 CKD_SHA1_KDF / CKD_SHA224_KDF / CKD_SHA3_224_KDF). Normalizing
// them here does not admit them to HKDF or SP 800-108: types.KDFParams checks
// the name against the set the selected construction approves.
var kdfHashNames = map[string]string{
	"SHA1":    "SHA-1",
	"SHA224":  "SHA-224",
	"SHA256":  "SHA-256",
	"SHA384":  "SHA-384",
	"SHA512":  "SHA-512",
	"SHA3224": "SHA3-224",
	"SHA3256": "SHA3-256",
	"SHA3384": "SHA3-384",
	"SHA3512": "SHA3-512",
}

// parseKDFAlgorithm resolves a wire-level KDF algorithm name.
//
// An empty name selects HKDF, the documented default for ECDH key agreement
// when the caller does not name a KDF. A name that is present but unrecognized
// is an error.
//
// Falling back to HKDF for an unrecognized name is what this function used to
// do, and it is not detectable by the caller: "SP800-108-COUNTR" and
// "sp800_108_counter" both produced a valid-looking HKDF key and a success
// response, so a caller that believed it was deriving under SP 800-108 got
// keying material from a different construction with no indication of it.
func parseKDFAlgorithm(alg string) (types.KDFAlgorithm, error) {
	if alg == "" {
		return types.KDFAlgorithmHKDF, nil
	}
	parsed, ok := kdfAlgorithms[strings.ToUpper(alg)]
	if !ok {
		return "", &ErrValidation{
			Sentinel: ErrInvalidKDFAlgorithm,
			Detail:   "unsupported KDF algorithm: " + alg,
		}
	}
	return parsed, nil
}

// parseKDFHash normalizes a caller-supplied hash name to its canonical
// spelling. Empty input defaults to SHA-256; unrecognized input is returned
// unchanged so types.KDFParams.Validate reports it.
func parseKDFHash(hash string) string {
	if hash == "" {
		return "SHA-256"
	}
	if canonical, ok := kdfHashNames[strings.ToUpper(strings.ReplaceAll(hash, "-", ""))]; ok {
		return canonical
	}
	return hash
}

// signaturePaddingPKCS1v15 and signaturePaddingPSS are the wire-level values
// transport.SignRequest.Padding / transport.VerifyRequest.Padding accept.
const (
	signaturePaddingPKCS1v15 = "pkcs1v15"
	signaturePaddingPSS      = "pss"
)

// parseSignaturePadding resolves a caller-supplied RSA padding scheme name to
// a PSS/PKCS#1v1.5 selector for the given key algorithm.
//
// An empty name and the explicit name "pkcs1v15" both select PKCS#1 v1.5,
// which is today's only behaviour; this is what makes an empty Padding field
// on the wire fully backward compatible. "pss" selects RSASSA-PSS and is
// refused for any key algorithm other than RSA, since PSS has no ECDSA or
// Ed25519 analogue and silently falling back to PKCS#1 v1.5 or to the key's
// native scheme would sign under a scheme the caller did not ask for. Any
// other name is refused rather than mapped to a default, for the same reason
// ResolveHash refuses an unrecognized hash name.
func parseSignaturePadding(padding string, alg x509.PublicKeyAlgorithm) (isPSS bool, err error) {
	switch strings.ToLower(strings.TrimSpace(padding)) {
	case "", signaturePaddingPKCS1v15:
		return false, nil
	case signaturePaddingPSS:
		if alg != x509.RSA {
			return false, &ErrValidation{
				Sentinel: ErrInvalidKeyAlgorithm,
				Detail:   "RSA-PSS padding requires an RSA key, got: " + alg.String(),
			}
		}
		return true, nil
	default:
		return false, &ErrValidation{
			Sentinel: ErrInvalidSignatureScheme,
			Detail:   "unsupported signature padding: " + padding,
		}
	}
}

// checkSuppliedDigestLength verifies that a caller-supplied digest is the
// length the named hash function produces.
//
// It only applies when the caller set DataIsDigest and named a hash: that pair
// is an assertion that these bytes are the output of that function, and the
// length is the one part of the assertion the server can check. A digest of
// the wrong length is a caller error, and saying so is more useful than
// letting crypto/rsa report the same condition as "input must be hashed
// message" from inside a signing routine, or -- for ECDSA, which truncates
// whatever it is given (SEC 1 v2.0 section 4.1.3) -- than producing a valid
// signature over bytes that are not the digest the caller believes they are.
//
// A zero hash carries no length to check against: that is the "NONE" sentinel,
// where no hash function is involved at all and the caller's bytes are a
// complete DigestInfo or a bare digest of its own choosing.
func checkSuppliedDigestLength(dataIsDigest bool, h crypto.Hash, digest []byte) error {
	if !dataIsDigest || h == 0 {
		return nil
	}
	if len(digest) != h.Size() {
		return &ErrValidation{
			Sentinel: ErrInvalidHashFunction,
			Detail: fmt.Sprintf(
				"data_is_digest is set with hash %s, but data is %d bytes and %s produces %d",
				h.String(), len(digest), h.String(), h.Size()),
		}
	}
	return nil
}

// backendCapabilitySentinels lists the sentinel errors a Backend raises when
// it refuses an operation because the underlying hardware or service
// genuinely cannot perform it -- a capability boundary discovered while
// carrying out the operation, not a fault. backend.ErrOperationNotSupported is
// the one most backends share: PKCS#11's Decrypter and RotateKey, Azure Key
// Vault, GCP KMS, AWS KMS, Vault and the software backend all join it into
// their own errors for exactly this. TPM2 raises its own package-local
// sentinel instead for the refusal this list exists to classify: TPM2_Sign
// builds its own DigestInfo and rejects a caller-supplied one, and
// TPM2_RSA_Decrypt is refused outright on a sign-only key (see
// tpm2backend.ErrUnsupportedOperation, which TPM2's own Sign joins onto the
// TPM's error for exactly this reason). Both belong in one list rather than as
// per-backend special cases at each call site below, so a future backend with
// its own local sentinel for this shape has a single place to register it.
var backendCapabilitySentinels = []error{
	backend.ErrOperationNotSupported,
	tpm2backend.ErrUnsupportedOperation,
}

// isBackendCapabilityRefusal reports whether err is a backend's refusal to
// perform an operation because it is outside what the underlying hardware or
// service can do, as opposed to a transient or programming fault (a wrong
// PIN, a severed transport, a corrupted digest). The distinction matters all
// the way to the wire: a refusal classified as ErrOperationNotSupported here
// reaches gRPC as codes.Unimplemented (pkg/api/grpc/errors_keyops.go) and the
// PKCS#11 module as CKR_FUNCTION_NOT_SUPPORTED (pkg/pkcs11/module/errors.go),
// telling the caller "this token cannot do that" instead of the generic
// CKR_FUNCTION_FAILED a fault would report.
func isBackendCapabilityRefusal(err error) bool {
	for _, sentinel := range backendCapabilitySentinels {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// wrapOperationError classifies err as ErrOperationNotSupported when it is a
// backend capability refusal (see isBackendCapabilityRefusal), and otherwise
// wraps it under fallback exactly as before. An error that is not a known
// capability sentinel keeps its original classification, so an unrelated
// failure is never reported as "not supported" -- that would be worse than
// today's generic fault, because a caller who retries a real fault believing
// the operation is categorically impossible will retry forever instead of
// retrying the operation that can actually succeed.
func wrapOperationError(fallback error, detail string, err error) error {
	if isBackendCapabilityRefusal(err) {
		return &ErrOperationWrap{Sentinel: ErrOperationNotSupported, Detail: detail, Err: err}
	}
	return &ErrOperationWrap{Sentinel: fallback, Detail: detail, Err: err}
}

// Sign signs data using the specified key.
// For Ed25519 keys, pure signing is used (no pre-hashing).
// For RSA keys, PKCS#1 v1.5 padding is used unless the request selects
// RSA-PSS. For ECDSA keys, ASN.1 signing is used.
// The data is hashed with the specified hash algorithm before signing,
// unless the request's Hash is the "NONE" sentinel or DataIsDigest is set, in
// which case the caller-supplied bytes are signed directly (PKCS#11's raw
// CKM_RSA_PKCS and CKM_RSA_PKCS_PSS contracts respectively).
//
// The key's current version signs, and KeyVersion reports it; the signature
// itself stays in its standard format.
// Implements the CryptoServicer interface.
func (s *XKMSService) Sign(ctx context.Context, req *transport.SignRequest) (resp *transport.SignResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpSign, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil sign request"}
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	cur, err := k.current()
	if err != nil {
		return nil, err
	}

	resp, err = signWith(ctx, k.backend, cur.attrs, req)
	if err != nil {
		return nil, err
	}
	resp.KeyVersion = cur.number
	return resp, nil
}

// signWith signs req's data with the key attrs describes in b. See Sign.
func signWith(ctx context.Context, b Backend, attrs *types.KeyAttributes, req *transport.SignRequest) (*transport.SignResponse, error) {
	signer, err := b.Signer(ctx, attrs)
	if err != nil {
		return nil, wrapOperationError(ErrSigningFailed, "failed to get signer", err)
	}

	isPSS, err := parseSignaturePadding(req.Padding, attrs.KeyAlgorithm)
	if err != nil {
		return nil, err
	}

	// Ed25519 uses pure signing (no pre-hashing) unless CK_EDDSA_PARAMS
	// selected the Ed25519ctx or Ed25519ph variant (RFC 8032 Table 73,
	// threaded from CKM_EDDSA via req.PreHash/req.Context).
	if attrs.KeyAlgorithm == x509.Ed25519 {
		if req.PreHash || len(req.Context) > 0 {
			sig, signErr := signEd25519Variant(signer, req.Data, req.PreHash, req.Context)
			if signErr != nil {
				return nil, signErr
			}
			return &transport.SignResponse{
				Signature: sig,
				Algorithm: algorithmString(attrs),
			}, nil
		}
		sig, signErr := signer.Sign(rand.Reader, req.Data, crypto.Hash(0))
		if signErr != nil {
			return nil, wrapOperationError(ErrSigningFailed, "", signErr)
		}
		return &transport.SignResponse{
			Signature: sig,
			Algorithm: algorithmString(attrs),
		}, nil
	}

	// Only Ed25519 signs an empty message (RFC 8032); everything else needs
	// data to hash, so an empty payload is a client error rather than a
	// signature over nothing.
	if len(req.Data) == 0 {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "data is required"}
	}

	// For RSA and ECDSA, hash the data first. Hash(0) ("NONE" on the wire)
	// means the caller already built the digest; it is used as-is.
	h, err := ResolveHash(req.Hash)
	if err != nil {
		return nil, err
	}
	if isPSS && h == 0 {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidHashFunction,
			Detail:   "RSA-PSS requires a hash algorithm; hash \"NONE\" is not valid with padding \"pss\"",
		}
	}

	// DataIsDigest separates "which digest" from "apply it". RSASSA-PSS needs
	// the digest's identity for MGF1 and the salt length (RFC 8017 section
	// 9.1) while taking an already-hashed input (PKCS#11 v3.2 section 6.1.15),
	// so naming the hash cannot by itself mean "hash the data".
	digest := req.Data
	if h != 0 && !req.DataIsDigest {
		hasher := h.New()
		hasher.Write(req.Data)
		digest = hasher.Sum(nil)
	}

	if err := checkSuppliedDigestLength(req.DataIsDigest, h, digest); err != nil {
		return nil, err
	}

	// An in-process RSA key signs through crypto/rsa, which under
	// GODEBUG=fips140=only panics on a PKCS#1 v1.5 signature with no named
	// digest rather than returning an error. Refuse first with the typed
	// error. A PKCS#11 or TPM signer is not covered: it builds its own
	// DigestInfo and the check answers nil for it (go-xkms#486).
	if err := types.CheckRawPKCS1v15(signer, h); err != nil {
		return nil, wrapOperationError(ErrSigningFailed, "", err)
	}

	var opts crypto.SignerOpts = h
	if isPSS {
		opts = &rsa.PSSOptions{Hash: h, SaltLength: req.SaltLength}
	}

	sig, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, wrapOperationError(ErrSigningFailed, "", err)
	}

	return &transport.SignResponse{
		Signature: sig,
		Algorithm: algorithmString(attrs),
	}, nil
}

// signEd25519Variant signs message under the Ed25519ctx or Ed25519ph
// variant (RFC 8032 Table 73) selected by preHash/context.
//
// Go's crypto/ed25519 implements both variants directly through
// ed25519.Options: Hash: crypto.SHA512 selects Ed25519ph, and a non-empty
// Context alone (Hash zero) selects Ed25519ctx. PKCS#11's CKM_EDDSA passes
// the original, unhashed message to C_Sign even for the pre-hashed variant
// (v3.2 section 6.3.14 Table 74: "Input length: any"), so Ed25519ph's own
// SHA-512 pre-hash step is performed here before signing.
//
// Only a raw ed25519.PrivateKey signer can honor these variants: Go's
// ed25519.PrivateKey.Sign is the implementation that understands
// *ed25519.Options, and no other crypto.Signer backing an Ed25519 key in
// this codebase (HSM, TPM, cloud KMS) is known to. A backend that cannot
// prove it supports the requested variant is refused outright rather than
// silently signing under plain Ed25519, which would return CKR_OK for a
// signature the caller did not ask for.
func signEd25519Variant(signer crypto.Signer, message []byte, preHash bool, context []byte) ([]byte, error) {
	edKey, ok := signer.(ed25519.PrivateKey)
	if !ok {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidSignatureScheme,
			Detail:   "this backend does not support EdDSA context data or the pre-hashed (Ed25519ph) variant",
		}
	}

	opts := &ed25519.Options{Context: string(context)}
	if preHash {
		digest := sha512.Sum512(message)
		message = digest[:]
		opts.Hash = crypto.SHA512
	}

	sig, err := edKey.Sign(rand.Reader, message, opts)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrSigningFailed, Err: err}
	}
	return sig, nil
}

// verifyEd25519Variant verifies a signature produced under the Ed25519ctx
// or Ed25519ph variant. Unlike signing, verification only needs the public
// key, so every backend can honor it uniformly. See signEd25519Variant for
// why Ed25519ph re-hashes message here.
func verifyEd25519Variant(pub ed25519.PublicKey, message, signature []byte, preHash bool, context []byte) bool {
	opts := &ed25519.Options{Context: string(context)}
	if preHash {
		digest := sha512.Sum512(message)
		message = digest[:]
		opts.Hash = crypto.SHA512
	}
	return ed25519.VerifyWithOptions(pub, message, signature, opts) == nil
}

// Verify verifies a signature against data using the specified key.
// For Ed25519 keys, pure verification is used (no pre-hashing).
// For RSA keys, PKCS#1 v1.5 verification is used unless the request selects
// RSA-PSS. For ECDSA keys, ASN.1 verification is used.
// The data is hashed with the specified hash algorithm before verification,
// unless the request's Hash is the "NONE" sentinel or DataIsDigest is set, in
// which case the caller-supplied bytes are verified directly (PKCS#11's raw
// CKM_RSA_PKCS and CKM_RSA_PKCS_PSS contracts respectively).
//
// A request naming KeyVersion verifies with that version, which must be
// enabled. Without one, every enabled version is tried, newest first: a
// signature check is a public-key operation, and a false accept under the
// wrong key is cryptographically negligible. KeyVersion in the response names
// the version the signature verified under.
// Implements the CryptoServicer interface.
func (s *XKMSService) Verify(ctx context.Context, req *transport.VerifyRequest) (resp *transport.VerifyResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpVerify, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil verify request"}
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	versions, err := k.trialVersions(req.KeyVersion)
	if err != nil {
		return nil, err
	}

	var first *transport.VerifyResponse
	for _, v := range versions {
		result, err := verifyWith(ctx, k.backend, v.attrs, req)
		if err != nil {
			return nil, err
		}
		if result.Valid {
			result.KeyVersion = v.number
			return result, nil
		}
		if first == nil {
			first = result
		}
	}
	return first, nil
}

// verifyWith verifies req's signature with the key attrs describes in b. See
// Verify.
func verifyWith(ctx context.Context, b Backend, attrs *types.KeyAttributes, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	// Get the key and extract public key
	privKey, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrVerificationFailed, Detail: "failed to get key", Err: err}
	}

	keySigner, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrVerificationFailed, Detail: "key does not implement crypto.Signer"}
	}
	pubKey := keySigner.Public()

	isPSS, err := parseSignaturePadding(req.Padding, attrs.KeyAlgorithm)
	if err != nil {
		return nil, err
	}

	// Ed25519 uses pure verification (no pre-hashing) unless CK_EDDSA_PARAMS
	// selected the Ed25519ctx or Ed25519ph variant. See the matching
	// comment in Sign.
	if attrs.KeyAlgorithm == x509.Ed25519 {
		edPub, edOK := pubKey.(ed25519.PublicKey)
		if !edOK {
			return nil, &ErrOperationWrap{Sentinel: ErrVerificationFailed, Detail: "invalid Ed25519 public key type"}
		}
		if req.PreHash || len(req.Context) > 0 {
			valid := verifyEd25519Variant(edPub, req.Data, req.Signature, req.PreHash, req.Context)
			return &transport.VerifyResponse{Valid: valid}, nil
		}
		valid := ed25519.Verify(edPub, req.Data, req.Signature)
		return &transport.VerifyResponse{Valid: valid}, nil
	}

	// Only Ed25519 verifies over an empty message (RFC 8032); everything else
	// needs data to hash.
	if len(req.Data) == 0 {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "data is required"}
	}

	// Hash the data for RSA/ECDSA verification. Hash(0) ("NONE" on the wire)
	// means the caller already built the digest; it is used as-is.
	h, err := ResolveHash(req.Hash)
	if err != nil {
		return nil, err
	}
	if isPSS && h == 0 {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidHashFunction,
			Detail:   "RSA-PSS requires a hash algorithm; hash \"NONE\" is not valid with padding \"pss\"",
		}
	}

	// DataIsDigest means Data is already the digest; Hash still names which
	// digest produced it, which RSASSA-PSS needs for MGF1 and the salt
	// length. See the matching comment in Sign.
	digest := req.Data
	if h != 0 && !req.DataIsDigest {
		hasher := h.New()
		hasher.Write(req.Data)
		digest = hasher.Sum(nil)
	}

	if err := checkSuppliedDigestLength(req.DataIsDigest, h, digest); err != nil {
		return nil, err
	}

	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		// rsa.VerifyPKCS1v15 has the same fips140=only panic as the signing
		// side, and verification always runs in this process. The regime
		// withholding the operation is an error, not a false verdict: a
		// Valid=false answer would claim the signature was checked.
		if err := types.CheckRawPKCS1v15(pub, h); err != nil {
			return nil, &ErrOperationWrap{Sentinel: ErrVerificationFailed, Err: err}
		}
		var verifyErr error
		if isPSS {
			verifyErr = rsa.VerifyPSS(pub, h, digest, req.Signature, &rsa.PSSOptions{Hash: h, SaltLength: req.SaltLength})
		} else {
			verifyErr = rsa.VerifyPKCS1v15(pub, h, digest, req.Signature)
		}
		if verifyErr != nil {
			return &transport.VerifyResponse{
				Valid:   false,
				Message: verifyErr.Error(),
			}, nil
		}
		return &transport.VerifyResponse{Valid: true}, nil

	case *ecdsa.PublicKey:
		valid := ecdsa.VerifyASN1(pub, digest, req.Signature)
		return &transport.VerifyResponse{Valid: valid}, nil

	default:
		return nil, &ErrOperationWrap{
			Sentinel: ErrVerificationFailed,
			Detail:   fmt.Sprintf("unsupported public key type %T", pubKey),
		}
	}
}

// Encrypt encrypts plaintext using the specified key.
// For symmetric keys, uses the SymmetricKeyProvider interface.
// For asymmetric (RSA) keys, falls back to PKCS#1 v1.5 encryption with the
// key's public half -- the counterpart of Decrypt's own PKCS#1 v1.5 default.
// RSA-OAEP has a selectable digest and is served by the dedicated
// EncryptAsym RPC instead, since EncryptRequest carries no padding/digest
// field for OAEP's hash algorithm to travel in on.
//
// The key's current version encrypts, and KeyVersion reports it; the
// ciphertext stays in its standard format. A caller keeps KeyVersion to
// decrypt AES-CBC and RSA PKCS#1 v1.5 ciphertext once the key is rotated.
// Implements the CryptoServicer interface.
func (s *XKMSService) Encrypt(ctx context.Context, req *transport.EncryptRequest) (resp *transport.EncryptResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpEncrypt, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil encrypt request"}
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	cur, err := k.current()
	if err != nil {
		return nil, err
	}

	resp, err = encryptWith(ctx, k.backend, cur.attrs, req)
	if err != nil {
		return nil, err
	}
	resp.KeyVersion = cur.number
	return resp, nil
}

// encryptWith encrypts req's plaintext with the key attrs describes in b. See
// Encrypt.
func encryptWith(ctx context.Context, b Backend, attrs *types.KeyAttributes, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider); ok {
		encrypter, err := symBackend.SymmetricEncrypter(ctx, attrs)
		if err == nil {
			// Mode/IV match the REST and QUIC handlers' own conversion
			// (rest.EncryptHandler, quic.handleEncrypt) exactly: an empty Mode
			// selects the key's native AEAD default, and an unrecognized Mode
			// string is left for SymmetricEncrypter.Encrypt to reject as a typed
			// error rather than silently running the default cipher.
			mode := types.CipherMode(strings.ToLower(req.Mode))

			// The empty Mode is the key's AEAD (AES-GCM or ChaCha20-Poly1305).
			// A caller-supplied nonce for it is claimed before the seal, and a
			// claim that fails refuses the request before any ciphertext
			// exists; see claimAEADNonce.
			aeadMode := mode == ""
			if aeadMode && len(req.Nonce) > 0 {
				if err := claimAEADNonce(ctx, b, attrs, aeadEncryptOperation, req.Nonce); err != nil {
					return nil, err
				}
			}

			encrypted, err := encrypter.Encrypt(req.Plaintext, &types.EncryptOptions{
				AdditionalData: req.AdditionalData,
				Nonce:          req.Nonce,
				Mode:           mode,
				IV:             req.IV,
				TagSize:        req.TagSize,
			})
			if err != nil {
				return nil, wrapOperationError(ErrEncryptionFailed, "", err)
			}

			// Any nonce the caller did not claim above -- one the provider
			// generated -- is recorded now that it is known, so nobody can
			// present it later as their own. Providers that keep the nonce
			// inside their own ciphertext format return none, and have
			// nothing to record.
			if aeadMode && len(encrypted.Nonce) > 0 && !bytes.Equal(encrypted.Nonce, req.Nonce) {
				if err := claimGeneratedAEADNonce(ctx, b, attrs, encrypted.Nonce); err != nil {
					return nil, err
				}
			}
			return &transport.EncryptResponse{
				Ciphertext:   encrypted.Ciphertext,
				Nonce:        encrypted.Nonce,
				Tag:          encrypted.Tag,
				IV:           encrypted.IV,
				GCMNonceMode: string(encrypted.GCMNonceMode),
			}, nil
		}
	}

	// Fall back to asymmetric (RSA) encryption. This is what lets a key
	// wrapped under an RSA KEK actually work: C_WrapKey's local-fallback
	// path (module.WrapKey, when the target key has no backend KeyID) drives
	// this same RPC for CKM_RSA_PKCS, and previously had no branch to reach
	// here at all -- every asymmetric-KEK wrap failed with "backend does not
	// support symmetric encryption" regardless of the key it was given.
	//
	rsaPub, err := asymEncrypterKey(ctx, b, attrs)
	if err != nil {
		return nil, err
	}

	// PKCS#1 v1.5 encryption authenticates nothing and its conformance check
	// is the Bleichenbacher/Marvin decryption oracle (RFC 8017 section
	// 7.2.2) -- the same reasoning servicer_wrapkey.go gates
	// types.WrapRSAPKCS1v15 on, and the same reasoning Decrypt's asymmetric
	// fallback (asymDecrypterOpts) gates its own PKCS#1 v1.5 default on. This
	// RPC has no wrap/unwrap algorithm parameter to dispatch
	// resolveWrapMechanism on, so the process-wide policy accessor is read
	// directly: one operator setting, crypto.allow_legacy_key_wrap, governs
	// every PKCS#1 v1.5 construction this service performs. EncryptAsym
	// (RSA-OAEP) is the unconditionally available replacement and requires no
	// configuration change.
	//
	// Checked after asymEncrypterKey resolves an RSA key, not before: a
	// caller whose key cannot even reach this construction (not RSA, no
	// crypto.Signer) should see that error, not a policy refusal for a
	// construction that was never going to run anyway.
	if !types.AllowLegacyKeyWrap() {
		return nil, legacyRSAPKCS1v15Refusal(
			"Encrypt's asymmetric fallback",
			"Use EncryptAsym (RSA-OAEP) instead")
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, req.Plaintext) //nolint:staticcheck // SA1019: CKM_RSA_PKCS is PKCS#1 v1.5 by definition; gated on crypto.allow_legacy_key_wrap
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Err: err}
	}

	return &transport.EncryptResponse{Ciphertext: ciphertext}, nil
}

// asymEncrypterKey resolves the RSA public key to encrypt under for the
// asymmetric Encrypt fallback. Mirrors how Verify and EncryptAsym both
// resolve a key's public half: GetKey plus a crypto.Signer assertion, since
// crypto.PrivateKey carries no Public() method of its own.
func asymEncrypterKey(ctx context.Context, b Backend, attrs *types.KeyAttributes) (*rsa.PublicKey, error) {
	privKey, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "failed to get key", Err: err}
	}

	keySigner, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "key does not implement crypto.Signer"}
	}

	rsaPub, ok := keySigner.Public().(*rsa.PublicKey)
	if !ok {
		return nil, &ErrOperationWrap{
			Sentinel: ErrEncryptionFailed,
			Detail:   "backend does not support symmetric encryption and key is not RSA",
		}
	}

	return rsaPub, nil
}

// legacyRSAPKCS1v15Refusal builds the policy refusal every RSA PKCS#1 v1.5
// construction in this service reports when crypto.allow_legacy_key_wrap is
// unset. Encrypt's asymmetric fallback and Decrypt's asymmetric fallback
// (asymDecrypterOpts) both call it, so the sentinel, the reason and the
// setting name cannot drift apart between the two halves of the operation --
// they previously had: Encrypt refused PKCS#1 v1.5 by default while Decrypt
// performed it unconditionally, which is the gap go-xkms#1283 closes.
//
// what names the construction being refused ("Encrypt's asymmetric
// fallback", "Decrypt's asymmetric fallback"); alternative names the
// unconditionally available replacement and how to reach it.
func legacyRSAPKCS1v15Refusal(what, alternative string) error {
	reason, _ := types.LegacyKeyWrapReason(types.WrapRSAPKCS1v15)
	return &ErrValidation{
		Sentinel: ErrLegacyWrapDisabled,
		Detail: what + " (PKCS#1 v1.5) is refused: " + reason +
			". " + alternative + ", or set crypto.allow_legacy_key_wrap=true to re-admit it" +
			" (ignored in FIPS mode, where the validated module's approved mechanism set applies)",
	}
}

// Decrypt decrypts ciphertext using the specified key.
// For symmetric keys, uses the SymmetricKeyProvider interface.
// For asymmetric keys, uses the crypto.Decrypter interface.
//
// A request naming KeyVersion decrypts with that version, which must be
// enabled. Without one the version is chosen per ciphertext kind (see
// decryptionAuthenticated): AEAD and RSA-OAEP ciphertext tries every enabled
// version, newest first; AES-CBC and RSA PKCS#1 v1.5 ciphertext uses the one
// enabled version, and with more than one is refused with
// *keyversion.KeyVersionRequiredError. KeyVersion in the response names the
// version that decrypted.
// Implements the CryptoServicer interface.
func (s *XKMSService) Decrypt(ctx context.Context, req *transport.DecryptRequest) (resp *transport.DecryptResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpDecrypt, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil decrypt request"}
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	versions, err := k.selectVersions(req.KeyVersion, decryptionAuthenticated(k.representative(), req))
	if err != nil {
		return nil, err
	}

	resp, n, err := firstSuccess(versions, func(v keyVersion) (*transport.DecryptResponse, error) {
		return decryptWith(ctx, k.backend, v.attrs, req)
	})
	if err != nil {
		return nil, err
	}
	resp.KeyVersion = n
	return resp, nil
}

// decryptionAuthenticated reports whether a wrong key reliably fails the
// decryption req asks for, so each enabled version may be tried in turn: an
// AEAD ciphertext (its tag) or an RSA-OAEP one (its padding check). AES-CBC
// and RSA PKCS#1 v1.5 ciphertext authenticate nothing -- a wrong key decrypts
// to garbage or passes the padding check by chance, and trying keys one
// after another is a padding oracle -- so they need the one version the
// caller names. Only the mode or padding's name is read here; decryptWith
// validates it, so a refused padding is still reported as itself.
func decryptionAuthenticated(attrs *types.KeyAttributes, req *transport.DecryptRequest) bool {
	if attrs.IsSymmetric() {
		switch types.CipherMode(strings.ToLower(req.Mode)) {
		case types.CipherModeCBC, types.CipherModeCBCPad:
			return false
		default:
			return true
		}
	}
	return strings.EqualFold(req.Padding, "oaep")
}

// decryptWith decrypts req's ciphertext with the key attrs describes in b.
// See Decrypt.
func decryptWith(ctx context.Context, b Backend, attrs *types.KeyAttributes, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	// Try symmetric decryption first. IV travels on the ciphertext bundle
	// (types.EncryptedData) and Mode on the options, matching the REST and
	// QUIC handlers' own conversion (rest.DecryptHandler, quic.handleDecrypt)
	// exactly. An unrecognized Mode string is left for
	// SymmetricEncrypter.Decrypt to reject as a typed error rather than
	// silently running the default cipher against it.
	if symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider); ok {
		encrypter, symErr := symBackend.SymmetricEncrypter(ctx, attrs)
		if symErr == nil {
			plaintext, decErr := encrypter.Decrypt(&types.EncryptedData{
				Ciphertext:   req.Ciphertext,
				Nonce:        req.Nonce,
				Tag:          req.Tag,
				IV:           req.IV,
				GCMNonceMode: types.GCMNonceMode(req.GCMNonceMode),
			}, &types.DecryptOptions{
				AdditionalData: req.AdditionalData,
				Mode:           types.CipherMode(strings.ToLower(req.Mode)),
				TagSize:        req.TagSize,
			})
			if decErr != nil {
				return nil, wrapOperationError(ErrDecryptionFailed, "", decErr)
			}
			return &transport.DecryptResponse{Plaintext: plaintext}, nil
		}
	}

	// Fall back to asymmetric decryption
	decrypter, err := b.Decrypter(ctx, attrs)
	if err != nil {
		return nil, wrapOperationError(ErrDecryptionFailed, "failed to get decrypter", err)
	}

	// The padding has to be stated: passing nil opts means PKCS#1 v1.5, so an
	// OAEP ciphertext decrypted without options fails with a generic error that
	// looks like corruption rather than a padding mismatch.
	opts, err := asymDecrypterOpts(req)
	if err != nil {
		return nil, err
	}

	plaintext, err := decrypter.Decrypt(rand.Reader, req.Ciphertext, opts)
	if err != nil {
		return nil, wrapAsymDecryptError(attrs, err)
	}

	return &transport.DecryptResponse{Plaintext: plaintext}, nil
}

// wrapAsymDecryptError classifies a crypto.Decrypter failure from Decrypt's
// asymmetric fallback. A backend capability refusal (isBackendCapabilityRefusal
// -- a TPM2 raw-decrypt refusal on a sign-only key, for instance) keeps its
// own diagnostic text under ErrOperationNotSupported exactly as
// wrapOperationError reports it elsewhere in this file: that text names a
// static capability boundary, not a property of the ciphertext, so revealing
// it teaches a caller nothing about the plaintext.
//
// Every other failure is reported as the one uniform ErrDecryptionFailed,
// discarding the underlying cause entirely. RFC 8017 section 7.2.2 (PKCS#1
// v1.5) and section 7.1.2 (OAEP, Manger's attack) both require that an
// implementation not reveal which check inside the decryption step failed,
// because a distinguishable failure is the conformance oracle the
// Bleichenbacher/Marvin and Manger attacks need. Decrypt is reachable over
// every transport with a caller-designated key and a caller-supplied
// ciphertext, exactly like C_UnwrapKey, so it withholds the same detail
// servicer_wrapkey.go's ErrUnwrapCiphertextRejected already withholds for
// unwrap: a PKCS#11 token's or a cloud KMS's own diagnostic text about why a
// ciphertext was refused never reaches the caller.
func wrapAsymDecryptError(attrs *types.KeyAttributes, err error) error {
	if isBackendCapabilityRefusal(err) {
		return &ErrOperationWrap{Sentinel: ErrOperationNotSupported, Err: err}
	}
	return &ErrKeyOperation{Operation: "decrypt", KeyID: attrs.CN, Err: ErrDecryptionFailed}
}

// asymDecrypterOpts builds the crypto.DecrypterOpts for an asymmetric decrypt.
// It returns nil for PKCS#1 v1.5, which is the default when no padding is
// named -- and, like every PKCS#1 v1.5 construction in this service, that
// default is refused unless crypto.allow_legacy_key_wrap is set
// (types.AllowLegacyKeyWrap). PKCS#1 v1.5 decryption's own conformance check
// is the Bleichenbacher/Marvin decryption oracle (RFC 8017 section 7.2.2),
// the same construction Encrypt's asymmetric fallback gates and
// servicer_wrapkey.go's resolveWrapMechanism gates for types.WrapRSAPKCS1v15;
// this was the one PKCS#1 v1.5 construction in the service that ran
// unconditionally (go-xkms#1283).
//
// The unnamed-padding default is otherwise unchanged and deliberate: Encrypt's
// asymmetric fallback has exactly one construction (PKCS#1 v1.5, no padding
// parameter of its own), so a Decrypt that defaulted an unnamed padding to
// OAEP could never read back what Encrypt produced. An unnamed padding still
// means PKCS#1 v1.5 -- it is simply refused, like every other PKCS#1 v1.5
// construction, until the operator opts in. A caller who wants OAEP names it
// explicitly (Padding: "oaep"), which EncryptAsym requires unconditionally on
// its side of the same round trip.
//
// The OAEP digest is resolved through ResolveOAEPHash, the same gate
// EncryptAsym uses, so the two halves of the operation agree on both the
// default and the refusal. They previously did not: encrypt refused SHA-1 and
// defaulted an unnamed digest to SHA-256, while decrypt accepted SHA-1 and
// defaulted to it. A ciphertext this service produced under its own default
// therefore could not be decrypted by it, and a caller could reach SHA-1 OAEP
// through the decrypt half of an operation the encrypt half forbids.
//
// The default is deliberate. PKCS#1 v2.2 (RFC 8017 appendix A.2.1) makes SHA-1
// OAEP's default digest, so an unnamed hash could honestly mean SHA-1 -- and
// answering SHA-256 instead is a silent substitution that fails as an
// indecipherable ciphertext rather than as a wrong parameter. It resolves to
// SHA-256 anyway because that is what this service's encrypt half has always
// produced for an unnamed digest, and matching it is what makes an
// encrypt/decrypt round trip work at all; a peer that genuinely means RFC 8017's
// default gets an honest refusal when it says so, because SHA-1 named
// explicitly -- in CK_RSA_PKCS_OAEP_PARAMS.hashAlg or on any other transport --
// is rejected outright rather than quietly upgraded to a digest it did not ask
// for and cannot reproduce.
func asymDecrypterOpts(req *transport.DecryptRequest) (crypto.DecrypterOpts, error) {
	switch strings.ToLower(req.Padding) {
	case "", "pkcs1v15":
		if !types.AllowLegacyKeyWrap() {
			return nil, legacyRSAPKCS1v15Refusal(
				"Decrypt's asymmetric fallback",
				`Set padding="oaep" instead`)
		}
		return nil, nil
	case "oaep":
		h, err := ResolveOAEPHash(req.Hash)
		if err != nil {
			return nil, err
		}
		if h == 0 {
			return nil, &ErrValidation{
				Sentinel: ErrInvalidHashFunction,
				Detail:   "RSA-OAEP requires a hash algorithm; hash \"NONE\" is not valid",
			}
		}
		return &rsa.OAEPOptions{Hash: h, Label: req.Label}, nil
	default:
		return nil, &ErrValidation{
			Sentinel: ErrInvalidSignatureScheme,
			Detail:   "unsupported decryption padding: " + req.Padding,
		}
	}
}

// EncryptAsym encrypts plaintext using an RSA public key with OAEP padding.
// The key must be an RSA key. The key's current version's public key
// encrypts, and KeyVersion reports it. Implements the CryptoServicer
// interface.
func (s *XKMSService) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (resp *transport.EncryptAsymResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpEncrypt, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil encrypt-asym request"}
	}

	k, err := s.resolveKeyIn(ctx, req.Backend, req.TenantID, req.KeyID)
	if err != nil {
		return nil, err
	}
	cur, err := k.current()
	if err != nil {
		return nil, err
	}
	b, attrs := k.backend, cur.attrs

	// Get the key and extract the RSA public key
	privKey, err := b.GetKey(ctx, attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "failed to get key", Err: err}
	}

	keySigner, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "key does not implement crypto.Signer"}
	}

	rsaPub, ok := keySigner.Public().(*rsa.PublicKey)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "key is not RSA, asymmetric encryption requires RSA"}
	}

	// Use the specified hash or default to SHA-256 for OAEP.
	// SHA-1 OAEP is rejected: no blobs have ever been persisted with SHA-1
	// OAEP in this codebase (the wrap path has always defaulted to SHA-256),
	// so there is no compatibility requirement to accept it on either side.
	//
	// ResolveOAEPHash checks the name, not the resolved hash, so the refusal
	// holds even in a deployment that set crypto.allow_weak_hashes: OAEP has no
	// legacy blobs to read, so the escape hatch that exists for signing does not
	// apply here. It is the same gate asymDecrypterOpts uses, which is what
	// keeps the two halves of an OAEP operation on one digest vocabulary.
	h, err := ResolveOAEPHash(req.Hash)
	if err != nil {
		return nil, err
	}
	if h == 0 {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidHashFunction,
			Detail:   "RSA-OAEP requires a hash algorithm; hash \"NONE\" is not valid",
		}
	}

	// The label is the caller's, not a hardcoded empty one. It is RFC 8017's
	// encoding parameter L, and asymDecrypterOpts already passes the matching
	// DecryptRequest.Label to rsa.OAEPOptions -- so encrypting under nil while
	// decrypting under the caller's value meant the two halves of one OAEP
	// operation used different labels and the round trip could never close.
	ciphertext, err := rsa.EncryptOAEP(h.New(), rand.Reader, rsaPub, req.Plaintext, req.Label)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "RSA OAEP encryption failed", Err: err}
	}

	return &transport.EncryptAsymResponse{
		Ciphertext: ciphertext,
		KeyVersion: cur.number,
	}, nil
}

// buildECDHKDFParams maps the wire-level KDF fields of a DeriveKeyECDH
// request onto types.KDFParams.
//
// The wire carries a salt and an info field, which are HKDF's vocabulary.
// SP 800-108 has neither: its fixed input data is built from a Label and a
// Context. The mapping is therefore explicit rather than positional:
//
//	HKDF, X9.63, SP 800-56A  KDFSalt -> Salt, KDFInfo -> Info; KDFLabel rejected
//	SP 800-108 counter       KDFInfo -> Context, KDFLabel -> Label; KDFSalt rejected
//	SP 800-108 feedback      KDFInfo -> Context, KDFLabel -> Label, KDFSalt -> IV (K(0))
//
// A salt supplied for SP 800-108 counter mode, or a label supplied for a
// construction that has no label, is rejected rather than dropped: there is no
// input for it to become, and silently discarding it would derive a key from
// parameters the caller did not choose.
//
// KDFLabel is the SP 800-108 Label, and it is what gives an ECDH derivation
// domain separation. Without it, two protocols deriving from the same shared
// secret with the same Context get the same key; SP 800-108r1 §4 binds the
// Label into the fixed input data precisely so they do not.
func buildECDHKDFParams(req *transport.DeriveKeyECDHRequest, keyLength int) (*types.KDFParams, error) {
	algorithm, err := parseKDFAlgorithm(req.KDFAlgorithm)
	if err != nil {
		return nil, err
	}

	params := &types.KDFParams{
		Algorithm: algorithm,
		Hash:      parseKDFHash(req.KDFHash),
		KeyLength: keyLength,
	}

	switch params.Algorithm {
	case types.KDFAlgorithmRaw:
		// CKD_NULL runs no derivation, so it consumes no hash and no shared
		// info: PKCS#11 v3.2's CK_ECDH1_DERIVE_PARAMS requires pSharedData to
		// be NULL with it. parseKDFHash defaults an unnamed hash to SHA-256,
		// which would name a digest for a step that does not exist, so the
		// field is cleared rather than defaulted. Anything the caller did
		// supply is refused, not dropped -- a caller that believes its shared
		// info separates its key from another party's must not be given the
		// other party's key.
		params.Hash = ""
		if req.KDFHash != "" {
			return nil, &ErrValidation{
				Sentinel: ErrInvalidKeyAttributes,
				Detail:   "kdf_hash is not an input to RAW; CKD_NULL applies no key derivation function",
			}
		}
		for _, supplied := range []struct {
			name  string
			value []byte
		}{
			{"kdf_salt", req.KDFSalt},
			{"kdf_info", req.KDFInfo},
			{"kdf_label", req.KDFLabel},
		} {
			if len(supplied.value) > 0 {
				return nil, &ErrValidation{
					Sentinel: ErrInvalidKeyAttributes,
					Detail:   supplied.name + " is not an input to RAW; CKD_NULL applies no key derivation function",
				}
			}
		}

	case types.KDFAlgorithmSP800108Counter:
		if len(req.KDFSalt) > 0 {
			return nil, &ErrValidation{
				Sentinel: ErrInvalidKeyAttributes,
				Detail:   "kdf_salt is not an input to SP800-108-COUNTER",
			}
		}
		params.Label = req.KDFLabel
		params.Context = req.KDFInfo

	case types.KDFAlgorithmSP800108Feedback:
		params.Label = req.KDFLabel
		params.Context = req.KDFInfo
		params.IV = req.KDFSalt

	default:
		if len(req.KDFLabel) > 0 {
			return nil, &ErrValidation{
				Sentinel: ErrInvalidKeyAttributes,
				Detail:   "kdf_label is not an input to " + string(params.Algorithm),
			}
		}
		params.Salt = req.KDFSalt
		params.Info = req.KDFInfo
	}

	return params, nil
}

// params maps the wire-level KDF fields of a DeriveKey request onto the
// canonical kdf.KDFParams for this construction, refusing any field the
// construction has no input for.
func (b deriveKeyBridge) params(req *transport.DeriveKeyRequest, keyLength int, h crypto.Hash) (*kdf.KDFParams, error) {
	notApplicable := func(field string) error {
		return &ErrValidation{
			Sentinel: ErrInvalidKeyAttributes,
			Detail:   field + " is not an input to " + req.Algorithm,
		}
	}

	params := &kdf.KDFParams{
		Algorithm: b.newAdapter().Algorithm(),
		KeyLength: keyLength,
		Hash:      h,
	}

	switch {
	case b.usesSaltInfo:
		params.Salt = req.Salt
		params.Info = req.Info
	case b.usesSaltAsIV:
		// Feedback Mode: the salt is K(0), and info still has no home.
		params.IV = req.Salt
		if len(req.Info) > 0 {
			return nil, notApplicable("info")
		}
	default:
		if len(req.Salt) > 0 {
			return nil, notApplicable("salt")
		}
		if len(req.Info) > 0 {
			return nil, notApplicable("info")
		}
	}

	if b.usesLabelContext {
		params.Label = req.Label
		params.Context = req.Context
		return params, nil
	}
	if len(req.Label) > 0 {
		return nil, notApplicable("label")
	}
	if len(req.Context) > 0 {
		return nil, notApplicable("context")
	}

	return params, nil
}

// DeriveKey derives a key using the specified KDF algorithm.
// Supports HKDF, SP800-108-COUNTER, SP800-108-FEEDBACK, and SP800-108-DOUBLE-PIPELINE.
// Implements the CryptoServicer interface.
//
// This is the only implementation of the operation. Every transport reaches it:
// the gRPC service used to run its own copy of the adapter dispatch and
// parameter assembly against pkg/crypto/kdf directly, which is both the layering
// violation the project forbids and a source of silent divergence, since two
// assemblies of the same primitive both produce plausible keys.
//
// The base key is named one of two ways, never both (deriveBaseKeyMaterial):
// as raw input_key_material the caller already holds, or as the identity
// (backend + key_id) of a key the backend holds. In the second form the KDF
// runs inside the backend, over the real key material, and only the derived
// bytes come back — see types.SymmetricKeyDeriver for why that has to happen
// there and not in the caller's address space.
//
// Requests that name a capability this operation does not implement — storing
// the result — are refused with ErrOperationNotSupported rather than being
// answered with an exported key the caller did not ask for. A backend that
// refuses the derivation itself because it is a genuine capability boundary
// (see isBackendCapabilityRefusal) is classified the same way, rather than as
// the generic key-derivation failure deriveBaseKeyMaterial otherwise reports.
func (s *XKMSService) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (resp *transport.DeriveKeyResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = s.metricsBackendName(req.Backend)
	}
	defer func() { recordServiceOp(metrics.OpDeriveKey, metricsBackend, start, err) }()

	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil derive-key request"}
	}

	algorithm := strings.ToLower(strings.TrimSpace(req.Algorithm))
	if algorithm == "" {
		algorithm = "hkdf"
	}

	bridge, ok := kdfFactory[algorithm]
	if !ok {
		return nil, &ErrValidation{Sentinel: ErrOperationNotSupported, Detail: "unsupported KDF algorithm: " + req.Algorithm}
	}

	h, err := ResolveHash(req.Hash)
	if err != nil {
		return nil, err
	}
	if h == 0 {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidHashFunction,
			Detail:   "key derivation requires a hash algorithm; hash \"NONE\" is not valid",
		}
	}

	keyLength := int(req.KeyLength)
	if keyLength <= 0 {
		keyLength = defaultDerivedKeyLength
	}
	// Refused before any KDF parameter assembly or backend work: a caller
	// that names an oversized key_length must not cause an adapter in
	// pkg/crypto/kdf to preallocate on its behalf. types.KDFParams.Derive and
	// types.DeriveFromKeyMaterial enforce the same ceiling as the actual
	// gate; this is the same check, reported as request validation instead of
	// an operation failure so it surfaces as InvalidArgument, matching every
	// other malformed KDF field this function reports (go-xkms#1259).
	if keyLength > types.MaxDerivedKeyLength {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidKeyAttributes,
			Detail:   fmt.Sprintf("key_length %d exceeds the maximum of %d bytes", keyLength, types.MaxDerivedKeyLength),
		}
	}

	params, err := bridge.params(req, keyLength, h)
	if err != nil {
		return nil, err
	}

	// Refused before the base key is resolved: a request the operation cannot
	// complete must not cause a backend to unseal or release anything.
	if req.StoreResult {
		return nil, &ErrOperationWrap{
			Sentinel: ErrOperationNotSupported,
			Detail:   "storing a derived key is not supported; set store_result to false",
		}
	}

	derivedKey, keyVersion, err := s.deriveBaseKeyMaterial(ctx, req, params)
	if err != nil {
		if isBackendCapabilityRefusal(err) {
			return nil, &ErrOperationWrap{
				Sentinel: ErrOperationNotSupported,
				Detail:   "key derivation is not supported by this backend",
				Err:      err,
			}
		}
		return nil, err
	}

	return &transport.DeriveKeyResponse{
		DerivedKey: derivedKey,
		Algorithm:  req.Algorithm,
		KeyLength:  len(derivedKey),
		KeyVersion: keyVersion,
	}, nil
}

// DeriveKeyECDH performs ECDH key agreement against a peer public key and runs
// the resulting shared secret through a KDF to produce a symmetric key.
//
// The named backend must expose a key provider implementing
// types.KeyAgreementProvider; backends that do not (software-only providers,
// most cloud KMS backends) yield ErrOperationNotSupported, which is a genuine
// capability boundary rather than a missing implementation.
//
// The agreement uses the local key's current version, or the enabled version
// KeyVersion names; the response reports which, since the peer must hold
// that version's public key for the two sides to agree.
// Implements the CryptoServicer interface.
func (s *XKMSService) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (resp *transport.DeriveKeyECDHResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = req.Backend
	}
	defer func() { recordServiceOp(metrics.OpDeriveKeyECDH, metricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilRequest
	}
	if req.KeyID == "" {
		return nil, requiredField("key_id")
	}
	if req.Backend == "" {
		return nil, requiredField("backend")
	}
	if len(req.PeerPublicKey) == 0 {
		return nil, requiredField("peer_public_key")
	}

	// Refused before any backend or key lookup: a caller that names an
	// oversized key_length must not cause the backend to be resolved, the
	// key attributes fetched, or (once it runs) ECDH computed, only to have
	// the result handed to a KDF adapter that preallocates on the caller's
	// behalf. types.KDFParams.Derive enforces the same ceiling as the actual
	// gate (every DeriveKeyECDH backend validates through it); this is the
	// same check, reported as request validation instead of the generic
	// ErrKeyAgreementFailed so it surfaces as InvalidArgument, matching every
	// other malformed request field this function reports (go-xkms#1259).
	if req.KeyLength > types.MaxDerivedKeyLength {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidKeyAttributes,
			Detail:   fmt.Sprintf("key_length %d exceeds the maximum of %d bytes", req.KeyLength, types.MaxDerivedKeyLength),
		}
	}

	b, err := s.resolveTenantBackend(req.Backend, req.TenantID)
	if err != nil {
		return nil, roleLookupError("backend", req.Backend, err)
	}

	agreement, ok := b.KeyProvider().(types.KeyAgreementProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  req.Backend,
			Detail:   "does not support ECDH key agreement",
		}
	}

	k, err := s.resolveKey(ctx, b, req.Backend, req.KeyID)
	if err != nil {
		return nil, roleLookupError("key", req.KeyID, err)
	}
	version, err := k.use(req.KeyVersion)
	if err != nil {
		return nil, roleLookupError("key", req.KeyID, err)
	}
	attrs := version.attrs

	if attrs.KeyAlgorithm != x509.ECDSA {
		return nil, &ErrValidation{
			Sentinel: ErrInvalidKeyAlgorithm,
			Detail:   "key must be an ECDSA key for ECDH, got: " + attrs.KeyAlgorithm.String(),
		}
	}

	keyLength := req.KeyLength
	if keyLength <= 0 {
		keyLength = defaultECDHKeyLength
	}

	params, err := buildECDHKDFParams(req, keyLength)
	if err != nil {
		return nil, err
	}

	derivedKey, err := agreement.DeriveKeyECDH(ctx, attrs, req.PeerPublicKey, params)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrKeyAgreementFailed, Err: err}
	}

	return &transport.DeriveKeyECDHResponse{
		DerivedKey: derivedKey,
		KeyVersion: version.number,
	}, nil
}

// AttestKey returns a cryptographic attestation proving a key resides in
// hardware and never left the secure boundary.
//
// The named backend must expose a key provider implementing
// types.AttestingKeyProvider (TPM 2.0, PKCS#11). Software and cloud providers
// that cannot attest yield ErrOperationNotSupported — a real capability
// boundary, not a stub.
// Implements the CryptoServicer interface.
func (s *XKMSService) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (resp *transport.AttestKeyResponse, err error) {
	start := time.Now()
	metricsBackend := ""
	if req != nil {
		metricsBackend = req.Backend
	}
	defer func() { recordServiceOp(metrics.OpAttestKey, metricsBackend, start, err) }()

	if req == nil {
		return nil, ErrNilRequest
	}
	if req.Backend == "" {
		return nil, requiredField("backend")
	}
	if req.KeyID == "" {
		return nil, requiredField("key_id")
	}

	b, err := s.resolveTenantBackend(req.Backend, req.TenantID)
	if err != nil {
		return nil, roleLookupError("backend", req.Backend, err)
	}

	attester, ok := b.KeyProvider().(types.AttestingKeyProvider)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  req.Backend,
			Detail:   "does not support attestation",
		}
	}

	// The key's current version is attested.
	k, err := s.resolveKey(ctx, b, req.Backend, req.KeyID)
	if errors.Is(err, ErrKeyNotFound) {
		return nil, &ErrRoleLookup{Role: "key", Name: req.KeyID, Err: ErrKeyNotFound}
	}
	if err != nil {
		return nil, &ErrKeyOperation{Operation: "list keys", Err: err}
	}
	cur, err := k.current()
	if err != nil {
		return nil, &ErrRoleLookup{Role: "key", Name: req.KeyID, Err: err}
	}

	result, err := attester.AttestKey(ctx, cur.attrs, req.Nonce)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrAttestationFailed, Err: err}
	}

	stmt, ok := result.(*attestation.AttestationStatement)
	if !ok {
		return nil, &ErrOperationWrap{
			Sentinel: ErrAttestationFailed,
			Detail:   fmt.Sprintf("unexpected attestation result type %T", result),
		}
	}

	certChain := make([][]byte, 0, len(stmt.CertificateChain))
	for _, cert := range stmt.CertificateChain {
		certChain = append(certChain, cert.Raw)
	}

	return &transport.AttestKeyResponse{
		Format:             stmt.Format,
		CertificateChain:   certChain,
		AttestationData:    stmt.AttestationData,
		Signature:          stmt.Signature,
		SignatureAlgorithm: stmt.SignatureAlgorithm.String(),
		Nonce:              stmt.Nonce,
		Backend:            stmt.Backend,
	}, nil
}

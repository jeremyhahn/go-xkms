package tpm2

import (
	"crypto"
	"crypto/x509"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// requestedSignHash reports the hash algorithm the caller asked TPM2_Sign to
// use, as a crypto.Hash.
//
// A nil opts means the caller expressed no preference, which selects SHA-256 to
// match xkms.ResolveHash's treatment of an unspecified hash name. A returned
// crypto.Hash(0) is the "NONE" sentinel: the caller has already produced the
// exact bytes to sign and does not want them hashed again. Resolving what that
// means for the TPM depends on the key, so it is left to eccSchemeHash and
// rsaSchemeHash.
func requestedSignHash(opts crypto.SignerOpts) crypto.Hash {
	if opts == nil {
		return crypto.SHA256
	}
	return opts.HashFunc()
}

// isPSSRequest reports whether the caller asked for an RSA-PSS signature.
//
// Two places can say so and either is sufficient: the key attributes name an
// RSA-PSS x509.SignatureAlgorithm, which is how a key is configured for PSS, or
// the signer options carry rsa.PSSOptions, which is how crypto.Signer callers
// ask per operation. The answer selects the scheme sent to the TPM and the
// branch that unpacks the TPMT_SIGNATURE, so it must be computed once and used
// for both; deriving them separately is how a signature gets requested as one
// shape and read as another.
func isPSSRequest(keyAttrs *types.KeyAttributes, opts *store.SignerOpts) bool {
	if keyAttrs != nil && store.IsRSAPSS(keyAttrs.SignatureAlgorithm) {
		return true
	}
	return opts != nil && opts.PSSOptions != nil
}

// namedSchemeHash maps the digest algorithms this package supports in a
// TPMT_SIG_SCHEME onto their TPM algorithm IDs (TCG TPM 2.0 Library Part 2,
// section 6.3). crypto.Hash(0) is deliberately absent: it is not a digest
// algorithm but the "already hashed" sentinel, and each key type answers it
// differently.
var namedSchemeHash = map[crypto.Hash]tpm2.TPMIAlgHash{
	crypto.SHA256: tpm2.TPMAlgSHA256,
	crypto.SHA384: tpm2.TPMAlgSHA384,
	crypto.SHA512: tpm2.TPMAlgSHA512,
}

// schemeHashByDigestSize maps a digest length in bytes onto the only hash
// algorithm in namedSchemeHash that produces a digest of that length.
//
// The map is unambiguous by construction -- SHA-256, SHA-384 and SHA-512 have
// distinct digest sizes -- and the TPM makes it the only admissible answer:
// TPM2_Sign rejects a digest whose length differs from the size of the hash
// algorithm named in inScheme with TPM_RC_SIZE (TCG TPM 2.0 Library Part 3,
// section 12.1). Naming any other algorithm for a given digest length is
// therefore not a different signature but a guaranteed failure.
var schemeHashByDigestSize = map[int]tpm2.TPMIAlgHash{
	32: tpm2.TPMAlgSHA256,
	48: tpm2.TPMAlgSHA384,
	64: tpm2.TPMAlgSHA512,
}

// digestSizeOfSchemeHash is the inverse of schemeHashByDigestSize, extended to
// the digest algorithms a key's public area may name even though this package
// will not select them for a new signature.
//
// It exists to check the caller's digest against the algorithm the scheme will
// name, before the command is sent. The TPM performs the same check and answers
// TPM_RC_SIZE, which tells the caller only that some parameter was the wrong
// size (TCG TPM 2.0 Library Part 3, section 12.1).
var digestSizeOfSchemeHash = map[tpm2.TPMIAlgHash]int{
	tpm2.TPMAlgSHA1:   20,
	tpm2.TPMAlgSHA256: 32,
	tpm2.TPMAlgSHA384: 48,
	tpm2.TPMAlgSHA512: 64,
}

// checkDigestLength reports whether a digest of digestLen bytes can be signed
// under hashAlg.
//
// TPM2_Sign requires the digest to be exactly the size of the scheme's hash
// algorithm and answers anything else with TPM_RC_SIZE. Checking here means the
// caller is told which length was expected instead of receiving a response code
// naming a command parameter number. A hash algorithm whose size is not known
// to this package is passed through: the TPM remains the authority, and
// inventing a length would refuse a signature it would have produced.
func checkDigestLength(hashAlg tpm2.TPMIAlgHash, digestLen int) error {
	size, ok := digestSizeOfSchemeHash[hashAlg]
	if !ok || size == digestLen {
		return nil
	}
	return ErrDigestLengthMismatch
}

// eccSchemeHash resolves the hash algorithm to place in the TPMT_SIG_SCHEME of
// a TPM2_Sign command for an ECC key.
//
// TPM2_Sign never hashes anything: it signs the digest handed to it (TCG TPM 2.0
// Library Part 3, section 12.1). For ECDSA the scheme's hash algorithm does not
// enter the signature computation at all -- Part 4's CryptEccSign consumes the
// digest directly, truncated to the order of the curve -- so its only jobs are
// to satisfy the TPM's consistency check against the key's own scheme and to
// declare the digest's length.
//
// Two key shapes arrive here and they are resolved differently:
//
//   - A key whose public area names a scheme (TPMS_ECC_PARMS with a scheme other
//     than TPM_ALG_NULL, Part 2, section 12.2.3.6) can only be signed with under
//     that scheme's hash: Part 3, section 12.1 requires inScheme to be
//     TPM_ALG_NULL or to match the key's scheme exactly, hash algorithm
//     included, and answers a mismatch with TPM_RC_SCHEME. Such a key therefore
//     resolves hash "NONE" to its own scheme hash, and refuses any other named
//     digest with ErrSignSchemeMismatch rather than letting TPM_RC_SCHEME reach
//     the caller. Keys created before this package moved to TPM_ALG_NULL
//     templates have this shape, and this is what keeps them working.
//
//   - A key whose public area names TPM_ALG_NULL imposes no constraint, so the
//     caller's named digest is passed straight through. For hash "NONE" there is
//     no scheme hash to fall back on, and the answer is taken from the length of
//     the digest the caller supplied: the TPM requires the digest length to
//     equal the size of the hash named in inScheme (TPM_RC_SIZE otherwise), so
//     exactly one algorithm is admissible and every other choice would fail
//     outright. Because the hash algorithm is not an input to the ECDSA
//     computation, the resulting signature is over precisely the bytes the
//     caller supplied -- naming the length-compatible algorithm asserts nothing
//     the caller did not. A digest whose length matches no supported algorithm
//     is refused with ErrSchemeHashUnresolved.
func eccSchemeHash(
	requested crypto.Hash,
	keyScheme tpm2.TPMTECCScheme,
	digestLen int) (tpm2.TPMIAlgHash, error) {

	keyHashAlg, fixed, err := eccKeySchemeHash(keyScheme)
	if err != nil {
		return 0, err
	}

	if requested == 0 {
		if fixed {
			// The key's own hash is the only value inScheme may carry, so the
			// digest has to be the length that hash produces. Inferring from
			// the digest instead would name an algorithm the key does not
			// have, and the TPM would answer TPM_RC_SCHEME rather than telling
			// the caller its digest was the wrong length.
			if err := checkDigestLength(keyHashAlg, digestLen); err != nil {
				return 0, err
			}
			return keyHashAlg, nil
		}
		inferred, ok := schemeHashByDigestSize[digestLen]
		if !ok {
			return 0, ErrSchemeHashUnresolved
		}
		return inferred, nil
	}

	hashAlg, ok := namedSchemeHash[requested]
	if !ok {
		return 0, store.ErrInvalidHashFunction
	}
	if fixed && hashAlg != keyHashAlg {
		return 0, ErrSignSchemeMismatch
	}
	if err := checkDigestLength(hashAlg, digestLen); err != nil {
		return 0, err
	}
	return hashAlg, nil
}

// eccKeySchemeHash reports the hash algorithm named by an ECC key's signing
// scheme.
//
// fixed is false, with a nil error, when the key's public area names
// TPM_ALG_NULL: the key constrains nothing and the scheme is chosen per
// operation (TCG TPM 2.0 Library Part 3, section 12.1). A scheme that is neither
// TPM_ALG_NULL nor ECDSA -- a key-agreement scheme, or a signing scheme this
// package does not implement -- cannot be satisfied by the ECDSA command this
// package issues, and is reported as ErrSignSchemeMismatch.
func eccKeySchemeHash(
	keyScheme tpm2.TPMTECCScheme) (tpm2.TPMIAlgHash, bool, error) {

	if keyScheme.Scheme == tpm2.TPMAlgNull || keyScheme.Scheme == 0 {
		return 0, false, nil
	}
	if keyScheme.Scheme != tpm2.TPMAlgECDSA {
		return 0, false, ErrSignSchemeMismatch
	}
	ecdsaScheme, err := keyScheme.Details.ECDSA()
	if err != nil {
		return 0, false, ErrSchemeHashUnresolved
	}
	if ecdsaScheme.HashAlg == tpm2.TPMAlgNull || ecdsaScheme.HashAlg == 0 {
		return 0, false, ErrSchemeHashUnresolved
	}
	return ecdsaScheme.HashAlg, true, nil
}

// rsaSchemeHash resolves the hash algorithm to place in the TPMT_SIG_SCHEME of
// a TPM2_Sign command for an RSA key.
//
// Unlike ECDSA, the scheme hash is load-bearing for RSA: for an RSASSA scheme
// TPM2_Sign builds the PKCS#1 v1.5 DigestInfo itself, from the OID of the
// scheme's hash algorithm, and requires the supplied digest to be exactly that
// algorithm's digest size (TCG TPM 2.0 Library Part 3, section 12.1; the
// encoding is Part 4's RSASSA_Encode). The hash therefore cannot be inferred
// from the digest's length the way it is for ECDSA -- a 32-byte buffer under
// SHA-256 is signed as the digest inside a DigestInfo the TPM builds, not as the
// bytes themselves -- and hash "NONE", which asks for the caller's bytes to be
// padded and signed verbatim, cannot be honoured at all. See
// ErrRawRSASignUnsupported; it holds for a TPM_ALG_NULL key exactly as it does
// for a scheme-bearing one, because the refusal comes from how TPM2_Sign encodes
// RSASSA rather than from the key's scheme.
//
// As for ECC, a key whose public area names a scheme can only be signed with
// under that scheme's hash, so a request for any other digest is refused with
// ErrSignSchemeMismatch instead of being sent to the TPM to come back as
// TPM_RC_SCHEME.
func rsaSchemeHash(
	requested crypto.Hash,
	keyScheme tpm2.TPMTRSAScheme,
	digestLen int) (tpm2.TPMIAlgHash, error) {

	if requested == 0 {
		return 0, ErrRawRSASignUnsupported
	}
	hashAlg, ok := namedSchemeHash[requested]
	if !ok {
		return 0, store.ErrInvalidHashFunction
	}

	keyHashAlg, fixed, err := rsaKeySchemeHash(keyScheme)
	if err != nil {
		return 0, err
	}
	if fixed && hashAlg != keyHashAlg {
		return 0, ErrSignSchemeMismatch
	}
	if err := checkDigestLength(hashAlg, digestLen); err != nil {
		return 0, err
	}
	return hashAlg, nil
}

// rsaKeySchemeHash reports the hash algorithm named by an RSA key's signing
// scheme.
//
// fixed is false, with a nil error, when the key's public area names
// TPM_ALG_NULL. A scheme that is neither TPM_ALG_NULL nor one of the two signing
// schemes this package issues -- an encryption scheme such as OAEP, for
// instance -- cannot be signed with and is reported as ErrSignSchemeMismatch
// (TCG TPM 2.0 Library Part 2, section 12.2.3.5).
func rsaKeySchemeHash(
	keyScheme tpm2.TPMTRSAScheme) (tpm2.TPMIAlgHash, bool, error) {

	switch keyScheme.Scheme {
	case tpm2.TPMAlgNull, 0:
		return 0, false, nil

	case tpm2.TPMAlgRSASSA:
		scheme, err := keyScheme.Details.RSASSA()
		if err != nil {
			return 0, false, ErrSchemeHashUnresolved
		}
		if scheme.HashAlg == tpm2.TPMAlgNull || scheme.HashAlg == 0 {
			return 0, false, ErrSchemeHashUnresolved
		}
		return scheme.HashAlg, true, nil

	case tpm2.TPMAlgRSAPSS:
		scheme, err := keyScheme.Details.RSAPSS()
		if err != nil {
			return 0, false, ErrSchemeHashUnresolved
		}
		if scheme.HashAlg == tpm2.TPMAlgNull || scheme.HashAlg == 0 {
			return 0, false, ErrSchemeHashUnresolved
		}
		return scheme.HashAlg, true, nil

	default:
		return 0, false, ErrSignSchemeMismatch
	}
}

// rsaSignScheme resolves the signature scheme algorithm -- RSASSA or RSAPSS --
// to place in the TPMT_SIG_SCHEME of a TPM2_Sign command for an RSA key.
//
// A key whose public area names a scheme can only be signed with under that
// scheme (TCG TPM 2.0 Library Part 3, section 12.1), so it answers for itself
// and a caller asking for the other padding is refused with
// ErrSignSchemeMismatch rather than being handed a signature of a shape it did
// not request. A key created with TPM_ALG_NULL constrains nothing, and the
// choice comes from the caller: pss is true when the key attributes name an
// RSA-PSS signature algorithm or the signer options carry rsa.PSSOptions.
//
// The returned algorithm is also what selects the branch that unpacks the
// TPMT_SIGNATURE, so the signature is always read as the shape that was
// requested of the TPM.
func rsaSignScheme(
	keyScheme tpm2.TPMTRSAScheme, pss bool) (tpm2.TPMIAlgSigScheme, error) {

	switch keyScheme.Scheme {
	case tpm2.TPMAlgNull, 0:
		if pss {
			return tpm2.TPMAlgRSAPSS, nil
		}
		return tpm2.TPMAlgRSASSA, nil

	case tpm2.TPMAlgRSASSA:
		if pss {
			return 0, ErrSignSchemeMismatch
		}
		return tpm2.TPMAlgRSASSA, nil

	case tpm2.TPMAlgRSAPSS:
		if !pss {
			return 0, ErrSignSchemeMismatch
		}
		return tpm2.TPMAlgRSAPSS, nil

	default:
		return 0, ErrSignSchemeMismatch
	}
}

// signatureAlgorithms names the x509.SignatureAlgorithm of each signature
// scheme a key's public area can fix, by the scheme's hash algorithm: the
// TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS and TPMS_SIG_SCHEME_ECDSA
// members of TPMU_ASYM_SCHEME (TCG TPM 2.0 Library Part 2, section 11.2.3.5).
var signatureAlgorithms = map[tpm2.TPMAlgID]map[tpm2.TPMIAlgHash]x509.SignatureAlgorithm{
	tpm2.TPMAlgRSASSA: {
		tpm2.TPMAlgSHA256: x509.SHA256WithRSA,
		tpm2.TPMAlgSHA384: x509.SHA384WithRSA,
		tpm2.TPMAlgSHA512: x509.SHA512WithRSA,
	},
	tpm2.TPMAlgRSAPSS: {
		tpm2.TPMAlgSHA256: x509.SHA256WithRSAPSS,
		tpm2.TPMAlgSHA384: x509.SHA384WithRSAPSS,
		tpm2.TPMAlgSHA512: x509.SHA512WithRSAPSS,
	},
	tpm2.TPMAlgECDSA: {
		tpm2.TPMAlgSHA256: x509.ECDSAWithSHA256,
		tpm2.TPMAlgSHA384: x509.ECDSAWithSHA384,
		tpm2.TPMAlgSHA512: x509.ECDSAWithSHA512,
	},
}

// keySignatureAlgorithm returns the signature algorithm a key's public area
// fixes in the scheme of its TPMS_RSA_PARMS or TPMS_ECC_PARMS (TCG TPM 2.0
// Library Part 2, sections 12.2.3.5 and 12.2.3.6). A Restricted signing key
// always fixes one, and signs only under it: an IAK's RSA template is H-1
// with either TPM_ALG_RSASSA or TPM_ALG_RSAPSS, its ECC templates H-2 to H-4
// TPM_ALG_ECDSA, each over the template's nameAlg (TCG "TPM 2.0 Keys for
// Device Identity and Attestation" v1.00 r12, section 7.3.4).
//
// A key whose scheme is TPM_ALG_NULL, as an RSA IDevID's is (Template H-1
// for an unrestricted key), or is no signature scheme, as a decryption key's
// is, fixes none: x509.UnknownSignatureAlgorithm is returned with no error.
func keySignatureAlgorithm(pub *tpm2.TPMTPublic) (x509.SignatureAlgorithm, error) {
	scheme, hash, err := keySignatureScheme(pub)
	if err != nil {
		return x509.UnknownSignatureAlgorithm, err
	}
	if scheme == tpm2.TPMAlgNull {
		return x509.UnknownSignatureAlgorithm, nil
	}
	sigAlgo, ok := signatureAlgorithms[scheme][hash]
	if !ok {
		return x509.UnknownSignatureAlgorithm, ErrKeySchemeHashUnnamed
	}
	return sigAlgo, nil
}

// keySignatureScheme returns the signature scheme and scheme hash a key's
// public area fixes, or TPM_ALG_NULL when it fixes no signature scheme.
func keySignatureScheme(pub *tpm2.TPMTPublic) (tpm2.TPMAlgID, tpm2.TPMIAlgHash, error) {
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return tpm2.TPMAlgNull, 0, err
		}
		scheme := rsaDetail.Scheme.Scheme
		if scheme != tpm2.TPMAlgRSASSA && scheme != tpm2.TPMAlgRSAPSS {
			return tpm2.TPMAlgNull, 0, nil
		}
		hash, _, err := rsaKeySchemeHash(rsaDetail.Scheme)
		return scheme, hash, err

	case tpm2.TPMAlgECC:
		eccDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return tpm2.TPMAlgNull, 0, err
		}
		if eccDetail.Scheme.Scheme != tpm2.TPMAlgECDSA {
			return tpm2.TPMAlgNull, 0, nil
		}
		hash, _, err := eccKeySchemeHash(eccDetail.Scheme)
		return tpm2.TPMAlgECDSA, hash, err

	default:
		return tpm2.TPMAlgNull, 0, nil
	}
}

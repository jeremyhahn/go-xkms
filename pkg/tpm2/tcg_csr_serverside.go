package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/google/go-tpm/tpm2"
)

// Server-side (stateless) TCG-CSR verification functions.
// These functions don't require TPM access and can be used by ACME servers
// to verify TCG-CSR-IDEVID requests from clients.

// AssertDevIDKeyConformant refuses a public area carried in a TCG-CSR-IDEVID
// whose key is not the IDevID or IAK the TCG specification defines.
//
// This is the CA's half of TCG "TPM 2.0 Keys for Device Identity and
// Attestation" v1.00 r12 §6.2.2 steps 7d and 7e — "Verify the attributes of the
// IDevID key public area" and "Verify the attributes of the IAK public area" —
// which §4 makes an obligation rather than a courtesy: "the OEM CA MUST be
// diligent in verifying all aspects of TPM binding to the device and verifying
// key Attributes and Policies."
//
// The attributes required are §4.1 for an AK and §4.2 for a DevID key —
// Restricted (AK only), Signing, Not-decrypting, FixedTPM — and the Template
// H-0 shape of §7.3.4.1 including userWithAuth and adminWithPolicy. The policy
// checked is the §7.3.6.6 IDevID/IAK Key Policy for the key's own nameAlg. A
// key whose authPolicy is anything else is administered by a policy the
// specification did not write, so certifying it would attest to a binding the
// CA cannot describe; it is refused with ErrDevIDTemplateNonConformant.
//
// This shares assertDevIDAttributesConformant with the provisioning path, so a
// CA cannot accept a key its own provisioning would refuse to create. It stops
// short of the creation-only rules that path also applies -- the section 7.3.1
// unique string, and the H-1 through H-4 scheme, symmetric, exponent and kdf --
// because those describe a template, not a key. Section 7.3.1 is explicit: "At
// the time of key creation, the unique field MUST be set to one of the strings
// shown in Table 2." TPM2_CreatePrimary consumes that string as derivation
// input and returns an outPublic whose unique field holds the generated public
// key, and outPublic is what a TCG-CSR-IDEVID carries; demanding the string
// here would refuse every genuine device.
func AssertDevIDKeyConformant(kind DevIDKeyKind, public *tpm2.TPMTPublic) error {
	if public == nil {
		return &errs.Detail{Err: ErrDevIDTemplateNonConformant, Detail: "no public area supplied"}
	}
	return assertDevIDAttributesConformant(kind, *public)
}

// VerifyTCG_CSR_IDevID_Stateless verifies a TCG-CSR-IDEVID using stateless verification.
// This is a server-side verification that doesn't require TPM access.
//
// Per TCG TPM 2.0 Keys for Device Identity and Attestation Section 6.2.2:
// 1. Extract IDevID public key and verify the signature on TCG-CSR-IDEVID (7a)
// 2. Verify the attributes and policy of the IDevID key public area (7d)
// 3. Verify the attributes and policy of the IAK public area (7e)
//
// Step 7b, verifying the EK certificate against the TPM manufacturer's public
// key, is NOT done here and is not done by this function's callers either. The
// CSR carries the EK certificate and nothing anchors it, so what this function
// returns is a key proven resident in *a* TPM, not in a TPM the manufacturer
// vouched for.
//
// Returns:
// - Public key of the IDevID
// - Unpacked CSR structure
// - Error if validation fails
func VerifyTCG_CSR_IDevID_Stateless(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (crypto.PublicKey, *UNPACKED_TCG_CSR_IDEVID, error) {

	// Unpack CSR to native Go types
	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		return nil, nil, err
	}

	// Validate hash algorithm ID bounds before conversion (G115)
	if unpacked.CsrContents.HashAlgoId > math.MaxUint16 {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("hash algorithm ID too large: %d", unpacked.CsrContents.HashAlgoId)}
	}

	// Parse TPM hash algorithm
	hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId) // #nosec G115 -- TPM algorithm ID from CSR
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, nil, err
	}

	// Parse IAK public area (for verification)
	iakPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](unpacked.CsrContents.AttestPub)
	if err != nil {
		return nil, nil, err
	}
	if err := AssertDevIDKeyConformant(DevIDKeyAttestation, iakPub); err != nil {
		return nil, nil, err
	}

	// Parse IDevID public area (used for signing)
	idevidPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](unpacked.CsrContents.SigningPub)
	if err != nil {
		return nil, nil, err
	}
	if err := AssertDevIDKeyConformant(DevIDKeySigning, idevidPub); err != nil {
		return nil, nil, err
	}

	// Re-pack CSR contents to verify signature
	packedContents, err := PackIDevIDContent(&csr.CsrContents)
	if err != nil {
		return nil, nil, err
	}

	// Hash the packed contents
	h := hash.New()
	h.Write(packedContents)
	digest := h.Sum(nil)

	// Verify signature using IDevID key
	var pubKey crypto.PublicKey
	switch idevidPub.Type {
	case tpm2.TPMAlgRSA:
		pubKey, err = verifyRSASignatureStateless(idevidPub, digest, csr.Signature, signatureAlgorithm, hash)
	case tpm2.TPMAlgECC:
		pubKey, err = verifyECDSASignatureStateless(idevidPub, digest, csr.Signature)
	default:
		return nil, nil, ErrInvalidAKAttributes
	}

	if err != nil {
		return nil, nil, err
	}

	// The IAK must have certified the IDevID.
	//
	// Everything above concerns the IDevID's *possession*: the CSR is signed by
	// it, so the requester holds the private half. That is equally true of a key
	// generated in software. Only this certification shows the IDevID lives in
	// the same TPM as the attestation key -- which is the entire claim an IDevID
	// certificate makes.
	//
	// No qualifying data is demanded: the certification is produced when the
	// IDevID is created, long before a CA chooses a challenge. Freshness in this
	// ceremony comes from credential activation and the quote, both bound to
	// values the CA picks per session.
	if _, err := VerifyCertifyRaw(
		unpacked.CsrContents.SgnCertifyInfo,
		unpacked.CsrContents.SgnCertifyInfoSig,
		unpacked.CsrContents.AttestPub,
		unpacked.CsrContents.SigningPub,
		nil,
	); err != nil {
		return nil, nil, err
	}

	return pubKey, unpacked, nil
}

// VerifyTCG_CSR_IAK_Stateless verifies a TCG-CSR-IDEVID using the IAK enrollment strategy (stateless).
// This is a server-side verification that doesn't require TPM access.
//
// Per TCG TPM 2.0 Keys for Device Identity and Attestation Section 6.1.2:
// 1. Extract the IAK Public Key from the TCG-CSR-IDEVID
// 2. Verify the signature on the TCG-CSR-IDEVID using the IAK public key
// 3. Verify the attributes (TPMA_OBJECT bits) of the IAK Public Area:
//   - Must be Restricted, fixedTPM, fixedParent signing key
//
// Returns:
// - Public key of the IAK
// - Unpacked CSR structure
// - Error if validation fails
func VerifyTCG_CSR_IAK_Stateless(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (crypto.PublicKey, *UNPACKED_TCG_CSR_IDEVID, error) {

	// Unpack CSR to native Go types
	unpacked, err := UnpackIDevIDCSR(csr)
	if err != nil {
		return nil, nil, err
	}

	// Validate hash algorithm ID bounds before conversion (G115)
	if unpacked.CsrContents.HashAlgoId > math.MaxUint16 {
		return nil, nil, &errs.Message{Msg: fmt.Sprintf("hash algorithm ID too large: %d", unpacked.CsrContents.HashAlgoId)}
	}

	// Parse TPM hash algorithm
	hashAlgo := tpm2.TPMAlgID(unpacked.CsrContents.HashAlgoId) // #nosec G115 -- TPM algorithm ID from CSR
	hash, err := hashAlgo.Hash()
	if err != nil {
		return nil, nil, err
	}

	// Parse IAK public area from CSR
	iakPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](unpacked.CsrContents.AttestPub)
	if err != nil {
		return nil, nil, err
	}
	if err := AssertDevIDKeyConformant(DevIDKeyAttestation, iakPub); err != nil {
		return nil, nil, err
	}

	// Re-pack CSR contents to verify signature
	packedContents, err := PackIDevIDContent(&csr.CsrContents)
	if err != nil {
		return nil, nil, err
	}

	// Hash the packed contents
	h := hash.New()
	h.Write(packedContents)
	digest := h.Sum(nil)

	// Verify signature based on key type
	var pubKey crypto.PublicKey
	switch iakPub.Type {
	case tpm2.TPMAlgRSA:
		pubKey, err = verifyRSASignatureStateless(iakPub, digest, csr.Signature, signatureAlgorithm, hash)
	case tpm2.TPMAlgECC:
		pubKey, err = verifyECDSASignatureStateless(iakPub, digest, csr.Signature)
	default:
		return nil, nil, ErrInvalidAKAttributes
	}

	if err != nil {
		return nil, nil, err
	}

	return pubKey, unpacked, nil
}

// verifyRSASignatureStateless verifies an RSA signature (PKCS#1 v1.5 or PSS) without TPM access
func verifyRSASignatureStateless(
	pub *tpm2.TPMTPublic,
	digest, signature []byte,
	sigAlgo x509.SignatureAlgorithm,
	hash crypto.Hash) (*rsa.PublicKey, error) {

	rsaDetail, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, err
	}

	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		return nil, err
	}

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		return nil, err
	}

	// Determine signature scheme
	switch sigAlgo {
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		// RSA-PSS
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		}
		if err := rsa.VerifyPSS(rsaPub, hash, digest, signature, pssOpts); err != nil {
			return nil, ErrInvalidSignature
		}

	default:
		// PKCS#1 v1.5
		if err := rsa.VerifyPKCS1v15(rsaPub, hash, digest, signature); err != nil {
			return nil, ErrInvalidSignature
		}
	}

	return rsaPub, nil
}

// verifyECDSASignatureStateless verifies an ECDSA signature without TPM access
func verifyECDSASignatureStateless(
	pub *tpm2.TPMTPublic,
	digest, signature []byte) (*ecdsa.PublicKey, error) {

	ecdsaPub, err := eccPublicKey(pub)
	if err != nil {
		return nil, err
	}

	if !ecdsa.VerifyASN1(ecdsaPub, digest, signature) {
		return nil, ErrInvalidSignature
	}

	return ecdsaPub, nil
}

// ExtractPublicKeyFromTPMPublic extracts a crypto.PublicKey from TPM public area bytes
func ExtractPublicKeyFromTPMPublic(pubBytes []byte) (crypto.PublicKey, error) {
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubBytes)
	if err != nil {
		return nil, err
	}

	if pub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch
		rsaDetail, err := pub.Parameters.RSADetail()
		if err != nil {
			return nil, err
		}

		rsaUnique, err := pub.Unique.RSA()
		if err != nil {
			return nil, err
		}

		return tpm2.RSAPub(rsaDetail, rsaUnique)
	} else if pub.Type == tpm2.TPMAlgECC {
		return eccPublicKey(pub)
	}

	return nil, ErrInvalidAKAttributes
}

// Package-level convenience functions for server-side verification
// These match the function signatures expected by go-trustedca

// VerifyTCG_CSR_IDevID is a convenience wrapper for VerifyTCG_CSR_IDevID_Stateless.
// This provides compatibility with code expecting the stateless server-side verification.
func VerifyTCG_CSR_IDevID(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (crypto.PublicKey, *UNPACKED_TCG_CSR_IDEVID, error) {
	return VerifyTCG_CSR_IDevID_Stateless(csr, signatureAlgorithm)
}

// VerifyTCG_CSR_IAK is a convenience wrapper for VerifyTCG_CSR_IAK_Stateless.
// This provides compatibility with code expecting the stateless server-side verification.
func VerifyTCG_CSR_IAK(
	csr *TCG_CSR_IDEVID,
	signatureAlgorithm x509.SignatureAlgorithm) (crypto.PublicKey, *UNPACKED_TCG_CSR_IDEVID, error) {
	return VerifyTCG_CSR_IAK_Stateless(csr, signatureAlgorithm)
}

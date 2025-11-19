package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// Server-side (stateless) TCG-CSR verification functions.
// These functions don't require TPM access and can be used by ACME servers
// to verify TCG-CSR-IDEVID requests from clients.

// VerifyTCG_CSR_IDevID_Stateless verifies a TCG-CSR-IDEVID using stateless verification.
// This is a server-side verification that doesn't require TPM access.
//
// Per TCG TPM 2.0 Keys for Device Identity and Attestation Section 6.2.2:
// 1. Extract IDevID public key and verify the signature on TCG-CSR-IDEVID
// 2. Verify the attributes of the IDevID key public area (unrestricted, fixedTPM, fixedParent, signing)
// 3. Verify the attributes of the IAK public area (restricted, fixedTPM, fixedParent, signing)
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
		return nil, nil, fmt.Errorf("hash algorithm ID too large: %d", unpacked.CsrContents.HashAlgoId)
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

	// Verify IAK attributes (must be restricted)
	if !iakPub.ObjectAttributes.Restricted {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !iakPub.ObjectAttributes.FixedTPM {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !iakPub.ObjectAttributes.FixedParent {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !iakPub.ObjectAttributes.SignEncrypt {
		return nil, nil, ErrInvalidAKAttributes
	}

	// Parse IDevID public area (used for signing)
	idevidPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](unpacked.CsrContents.SigningPub)
	if err != nil {
		return nil, nil, err
	}

	// Verify IDevID attributes (must be unrestricted)
	if idevidPub.ObjectAttributes.Restricted {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !idevidPub.ObjectAttributes.FixedTPM {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !idevidPub.ObjectAttributes.FixedParent {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !idevidPub.ObjectAttributes.SignEncrypt {
		return nil, nil, ErrInvalidAKAttributes
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
	if idevidPub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch
		pubKey, err = verifyRSASignatureStateless(idevidPub, digest, csr.Signature, signatureAlgorithm, hash)
	} else if idevidPub.Type == tpm2.TPMAlgECC {
		pubKey, err = verifyECDSASignatureStateless(idevidPub, digest, csr.Signature)
	} else {
		return nil, nil, ErrInvalidAKAttributes
	}

	if err != nil {
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
		return nil, nil, fmt.Errorf("hash algorithm ID too large: %d", unpacked.CsrContents.HashAlgoId)
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

	// Verify IAK attributes per TCG spec
	if !iakPub.ObjectAttributes.Restricted {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !iakPub.ObjectAttributes.FixedTPM {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !iakPub.ObjectAttributes.FixedParent {
		return nil, nil, ErrInvalidAKAttributes
	}
	if !iakPub.ObjectAttributes.SignEncrypt {
		return nil, nil, ErrInvalidAKAttributes
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
	if iakPub.Type == tpm2.TPMAlgRSA { //nolint:staticcheck // QF1003: if-else preferred over switch
		pubKey, err = verifyRSASignatureStateless(iakPub, digest, csr.Signature, signatureAlgorithm, hash)
	} else if iakPub.Type == tpm2.TPMAlgECC {
		pubKey, err = verifyECDSASignatureStateless(iakPub, digest, csr.Signature)
	} else {
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

	ecDetail, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, err
	}

	crv, err := ecDetail.CurveID.Curve()
	if err != nil {
		return nil, err
	}

	eccUnique, err := pub.Unique.ECC()
	if err != nil {
		return nil, err
	}

	ecdsaPub := &ecdsa.PublicKey{
		Curve: crv,
		X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
		Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
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
		ecDetail, err := pub.Parameters.ECCDetail()
		if err != nil {
			return nil, err
		}

		crv, err := ecDetail.CurveID.Curve()
		if err != nil {
			return nil, err
		}

		eccUnique, err := pub.Unique.ECC()
		if err != nil {
			return nil, err
		}

		return &ecdsa.PublicKey{
			Curve: crv,
			X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
			Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
		}, nil
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

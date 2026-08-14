// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// TPM2_Certify verification failures.
//
// Each is distinct so a caller can tell a forged attestation from one that is
// genuine but describes a different key -- they are very different findings.
var (
	// ErrCertifyMalformed means the certifyInfo or signature would not parse.
	ErrCertifyMalformed = errors.New("tpm2: certify structure is malformed")

	// ErrCertifyNotTPMGenerated means the structure does not carry
	// TPM_GENERATED_VALUE, so it was not produced inside a TPM.
	//
	// This is the check that makes the whole mechanism work. A TPM will only
	// sign data beginning with that magic when it produced the data itself;
	// an unrestricted key can be asked to sign anything at all. Without this,
	// a caller with any signing key could hand-assemble bytes that decode as
	// an attestation for whatever object they liked.
	ErrCertifyNotTPMGenerated = errors.New("tpm2: attestation does not carry TPM_GENERATED_VALUE")

	// ErrCertifyWrongType means the structure attests something other than a
	// key certification -- a quote, say -- so it says nothing about the object
	// the caller is asking about.
	ErrCertifyWrongType = errors.New("tpm2: attestation is not a TPM2_Certify")

	// ErrCertifySignature means the signature over certifyInfo does not verify
	// under the attesting key.
	ErrCertifySignature = errors.New("tpm2: certify signature does not verify")

	// ErrCertifyNameMismatch means the certified Name is not the Name of the
	// key the caller asked about. The attestation is genuine but describes a
	// different object.
	ErrCertifyNameMismatch = errors.New("tpm2: certified name does not match the subject key")

	// ErrCertifyQualifyingDataMismatch means the caller-supplied nonce is not
	// the one inside the attestation, so the evidence may be a recording.
	ErrCertifyQualifyingDataMismatch = errors.New("tpm2: certify qualifying data does not match")

	// ErrCertifyAttesterUnrestricted means the attesting key is not a
	// restricted signing key.
	//
	// Only a restricted key is prevented by the TPM from signing arbitrary
	// external data. An unrestricted key can be asked to sign anything,
	// including bytes the caller composed to look like an attestation, so
	// accepting one would let the caller certify a key the TPM never saw.
	ErrCertifyAttesterUnrestricted = errors.New("tpm2: attesting key is not restricted")
)

// CertifyVerification is what a verified TPM2_Certify establishes.
type CertifyVerification struct {
	// SubjectName is the Name of the certified object, as the TPM computed it.
	SubjectName []byte

	// QualifyingData is the caller-supplied nonce the attestation carried.
	QualifyingData []byte

	// AttesterPublicKey is the attesting key, recovered from its public area.
	AttesterPublicKey crypto.PublicKey
}

// VerifyCertifyOptions configures VerifyCertify.
type VerifyCertifyOptions struct {
	// ExpectedQualifyingData, when set, must equal the attestation's extraData.
	//
	// This is what binds the evidence to one exchange. Leave it nil only when
	// freshness is established some other way; a verifier that never sets it
	// accepts a recording of any earlier certification.
	ExpectedQualifyingData []byte

	// AllowUnrestrictedAttester disables the restricted-key requirement.
	//
	// There is no good reason to set this outside tests: an unrestricted key
	// can sign attacker-chosen bytes, which is precisely the forgery this
	// verification exists to prevent.
	AllowUnrestrictedAttester bool
}

// VerifyCertify checks that attesterPub certified subjectPub, statelessly.
//
// This is the verifier half of [TPM2.CertifyKey]. It needs no TPM: everything
// it checks is contained in the signed structure, which is what lets a CA
// verify enrollment evidence from a device it has no access to.
//
// The five checks, in the order that matters:
//
//  1. The signature over certifyInfo verifies under the attesting key. Without
//     this nothing else means anything.
//  2. certifyInfo carries TPM_GENERATED_VALUE, so a TPM produced it rather
//     than the caller composing it.
//  3. The attesting key is restricted, so the TPM would refuse to sign
//     caller-supplied data with it -- which is what makes check 2 meaningful.
//  4. The structure is a certification, not a quote or a time attestation.
//  5. The certified Name equals the Name computed from subjectPub. This is the
//     binding: it is what says the attestation is about *this* key.
//
// Omitting 5 leaves a verifier that confirms a TPM certified *something*,
// which is the shape of the gap this closes. Omitting 2 or 3 leaves one that
// can be satisfied with a signature over hand-written bytes.
//
// certifyInfo and signature are the raw TPMS_ATTEST and TPMT_SIGNATURE
// produced by TPM2_Certify. attesterPub and subjectPub are marshalled
// TPMT_PUBLIC areas.
func VerifyCertify(
	certifyInfo []byte,
	signature []byte,
	attesterPub []byte,
	subjectPub []byte,
	opts *VerifyCertifyOptions,
) (*CertifyVerification, error) {
	if opts == nil {
		opts = &VerifyCertifyOptions{}
	}
	if len(certifyInfo) == 0 || len(signature) == 0 {
		return nil, fmt.Errorf("%w: certifyInfo and signature are both required",
			ErrCertifyMalformed)
	}

	attester, err := tpm2.Unmarshal[tpm2.TPMTPublic](attesterPub)
	if err != nil {
		return nil, fmt.Errorf("%w: attesting public area: %v", ErrCertifyMalformed, err)
	}
	subject, err := tpm2.Unmarshal[tpm2.TPMTPublic](subjectPub)
	if err != nil {
		return nil, fmt.Errorf("%w: subject public area: %v", ErrCertifyMalformed, err)
	}

	// The attesting key must be one the TPM will not sign external data with.
	if !opts.AllowUnrestrictedAttester {
		if !attester.ObjectAttributes.Restricted {
			return nil, ErrCertifyAttesterUnrestricted
		}
		if !attester.ObjectAttributes.SignEncrypt {
			return nil, fmt.Errorf("%w: attesting key cannot sign",
				ErrCertifyAttesterUnrestricted)
		}
	}

	sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrCertifyMalformed, err)
	}

	attesterKey, err := verifyCertifySignature(attester, certifyInfo, sig)
	if err != nil {
		return nil, err
	}

	// Parsed only after the signature holds: until then these are bytes the
	// caller chose, and reading fields out of them would be reading attacker
	// input. go-tpm checks the magic itself for the `gotpm:"check"` field, and
	// it is re-checked below so the failure names the reason.
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](certifyInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertifyNotTPMGenerated, err)
	}
	if attest.Magic != tpm2.TPMGeneratedValue {
		return nil, ErrCertifyNotTPMGenerated
	}
	if attest.Type != tpm2.TPMSTAttestCertify {
		return nil, fmt.Errorf("%w: type is 0x%04x", ErrCertifyWrongType, attest.Type)
	}

	info, err := attest.Attested.Certify()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertifyWrongType, err)
	}

	// The binding. ObjectName recomputes the Name from the public area the
	// same way the TPM does -- nameAlg followed by its digest over the area --
	// so an attacker cannot substitute a different key without changing it.
	expectedName, err := tpm2.ObjectName(subject)
	if err != nil {
		return nil, fmt.Errorf("%w: could not compute the subject name: %v",
			ErrCertifyMalformed, err)
	}
	if subtle.ConstantTimeCompare(info.Name.Buffer, expectedName.Buffer) != 1 {
		return nil, ErrCertifyNameMismatch
	}

	if opts.ExpectedQualifyingData != nil {
		if subtle.ConstantTimeCompare(
			attest.ExtraData.Buffer,
			opts.ExpectedQualifyingData,
		) != 1 {
			return nil, ErrCertifyQualifyingDataMismatch
		}
	}

	return &CertifyVerification{
		SubjectName:       info.Name.Buffer,
		QualifyingData:    attest.ExtraData.Buffer,
		AttesterPublicKey: attesterKey,
	}, nil
}

// VerifyCertifyRaw is [VerifyCertify] for evidence whose signature is the bare
// signature value rather than a marshalled TPMT_SIGNATURE.
//
// A TCG-CSR-IDEVID carries the certification that way: the packed CSR stores
// sgnCertifyInfoSignature as the raw value, with no algorithm alongside it. The
// scheme is therefore taken from the attesting key's own public area, which
// declares the scheme and hash it signs with -- and which is itself covered by
// the Name check, so it cannot be swapped for a weaker one without changing the
// Name the certification commits to.
func VerifyCertifyRaw(
	certifyInfo []byte,
	rawSignature []byte,
	attesterPub []byte,
	subjectPub []byte,
	opts *VerifyCertifyOptions,
) (*CertifyVerification, error) {
	attester, err := tpm2.Unmarshal[tpm2.TPMTPublic](attesterPub)
	if err != nil {
		return nil, fmt.Errorf("%w: attesting public area: %v", ErrCertifyMalformed, err)
	}

	sig, err := signatureFromScheme(attester, rawSignature)
	if err != nil {
		return nil, err
	}

	return VerifyCertify(certifyInfo, tpm2.Marshal(*sig), attesterPub, subjectPub, opts)
}

// signatureFromScheme rebuilds a TPMT_SIGNATURE from a raw signature value
// using the scheme the attesting key declares.
func signatureFromScheme(
	attester *tpm2.TPMTPublic,
	raw []byte,
) (*tpm2.TPMTSignature, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: the certification carries no signature", ErrCertifyMalformed)
	}

	switch attester.Type {
	case tpm2.TPMAlgRSA:
		detail, err := attester.Parameters.RSADetail()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
		}
		switch detail.Scheme.Scheme {
		case tpm2.TPMAlgRSASSA:
			scheme, schemeErr := detail.Scheme.Details.RSASSA()
			if schemeErr != nil {
				return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, schemeErr)
			}
			return &tpm2.TPMTSignature{
				SigAlg: tpm2.TPMAlgRSASSA,
				Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA,
					&tpm2.TPMSSignatureRSA{
						Hash: scheme.HashAlg,
						Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: raw},
					}),
			}, nil
		case tpm2.TPMAlgRSAPSS:
			scheme, schemeErr := detail.Scheme.Details.RSAPSS()
			if schemeErr != nil {
				return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, schemeErr)
			}
			return &tpm2.TPMTSignature{
				SigAlg: tpm2.TPMAlgRSAPSS,
				Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSAPSS,
					&tpm2.TPMSSignatureRSA{
						Hash: scheme.HashAlg,
						Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: raw},
					}),
			}, nil
		default:
			return nil, fmt.Errorf("%w: unsupported RSA scheme 0x%04x",
				ErrCertifyMalformed, detail.Scheme.Scheme)
		}

	case tpm2.TPMAlgECC:
		detail, err := attester.Parameters.ECCDetail()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
		}
		scheme, err := detail.Scheme.Details.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("%w: attesting key declares no ECDSA scheme: %v",
				ErrCertifyMalformed, err)
		}
		// A raw ECDSA signature from a TPM is r||s, each the curve's field size.
		if len(raw)%2 != 0 {
			return nil, fmt.Errorf("%w: ECDSA signature is %d bytes, not an r||s pair",
				ErrCertifyMalformed, len(raw))
		}
		half := len(raw) / 2
		return &tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash:       scheme.HashAlg,
					SignatureR: tpm2.TPM2BECCParameter{Buffer: raw[:half]},
					SignatureS: tpm2.TPM2BECCParameter{Buffer: raw[half:]},
				}),
		}, nil

	default:
		return nil, fmt.Errorf("%w: attesting key type 0x%04x cannot sign",
			ErrCertifyMalformed, attester.Type)
	}
}

// verifyCertifySignature checks the attesting key's signature over certifyInfo.
//
// TPM2_Certify signs the *digest* of the attestation structure, using the
// scheme named inside the signature itself, so the hash is taken from there
// rather than assumed.
func verifyCertifySignature(
	attester *tpm2.TPMTPublic,
	certifyInfo []byte,
	sig *tpm2.TPMTSignature,
) (crypto.PublicKey, error) {
	switch sig.SigAlg {
	case tpm2.TPMAlgRSASSA:
		rsassa, err := sig.Signature.RSASSA()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
		}
		hash, err := rsassa.Hash.Hash()
		if err != nil {
			return nil, fmt.Errorf("%w: unknown hash: %v", ErrCertifyMalformed, err)
		}
		pub, err := rsaPublicFromArea(attester)
		if err != nil {
			return nil, err
		}
		digest := digestOf(hash, certifyInfo)
		if err := rsa.VerifyPKCS1v15(pub, hash, digest, rsassa.Sig.Buffer); err != nil {
			return nil, ErrCertifySignature
		}
		return pub, nil

	case tpm2.TPMAlgRSAPSS:
		rsapss, err := sig.Signature.RSAPSS()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
		}
		hash, err := rsapss.Hash.Hash()
		if err != nil {
			return nil, fmt.Errorf("%w: unknown hash: %v", ErrCertifyMalformed, err)
		}
		pub, err := rsaPublicFromArea(attester)
		if err != nil {
			return nil, err
		}
		digest := digestOf(hash, certifyInfo)
		if err := rsa.VerifyPSS(pub, hash, digest, rsapss.Sig.Buffer, nil); err != nil {
			return nil, ErrCertifySignature
		}
		return pub, nil

	case tpm2.TPMAlgECDSA:
		ecsig, err := sig.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
		}
		hash, err := ecsig.Hash.Hash()
		if err != nil {
			return nil, fmt.Errorf("%w: unknown hash: %v", ErrCertifyMalformed, err)
		}
		pub, err := ecdsaPublicFromArea(attester)
		if err != nil {
			return nil, err
		}
		digest := digestOf(hash, certifyInfo)
		r := new(big.Int).SetBytes(ecsig.SignatureR.Buffer)
		s := new(big.Int).SetBytes(ecsig.SignatureS.Buffer)
		if !ecdsa.Verify(pub, digest, r, s) {
			return nil, ErrCertifySignature
		}
		return pub, nil

	default:
		return nil, fmt.Errorf("%w: unsupported signature algorithm 0x%04x",
			ErrCertifyMalformed, sig.SigAlg)
	}
}

// digestOf hashes data with the given hash.
func digestOf(hash crypto.Hash, data []byte) []byte {
	h := hash.New()
	h.Write(data)
	return h.Sum(nil)
}

// rsaPublicFromArea recovers an RSA public key from a TPMT_PUBLIC.
//
// The exponent is zero in the public area when it is the default, which is
// F4 (65537); taking it literally yields a key that verifies nothing.
func rsaPublicFromArea(pub *tpm2.TPMTPublic) (*rsa.PublicKey, error) {
	detail, err := pub.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
	}
	unique, err := pub.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
	}
	exponent := int(detail.Exponent)
	if exponent == 0 {
		exponent = 65537
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(unique.Buffer),
		E: exponent,
	}, nil
}

// ecdsaPublicFromArea recovers an ECDSA public key from a TPMT_PUBLIC.
func ecdsaPublicFromArea(pub *tpm2.TPMTPublic) (*ecdsa.PublicKey, error) {
	detail, err := pub.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
	}
	curve, err := detail.CurveID.Curve()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
	}
	unique, err := pub.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertifyMalformed, err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(unique.X.Buffer),
		Y:     new(big.Int).SetBytes(unique.Y.Buffer),
	}, nil
}

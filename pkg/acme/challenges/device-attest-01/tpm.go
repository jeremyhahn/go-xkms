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

package deviceattest01

import (
	"crypto/x509"
	"strconv"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The "tpm" attestation statement format
//
// The format is WebAuthn Level 2 section 8.3. Its evidence is a TPM2_Certify:
// certInfo is the TPMS_ATTEST the TPM produced when the AIK in x5c[0]
// certified the key whose TPMT_PUBLIC is pubArea, and sig is the AIK's
// signature over certInfo. What that proves is "the TPM holding this AIK holds
// the key in pubArea, and certified it for this challenge" -- which is only
// worth anything once the key being enrolled is known to be pubArea's key.
// That comparison needs the CSR, so it happens in BindCSRKey.
//
// Before this file the format was verified as a quote: the TPMS_ATTEST was
// never parsed, pubArea was never read, and freshness was a substring search
// for the key authorization anywhere in certInfo. None of that tied the
// evidence to a key.

// tpmStatementVersion is the only "ver" WebAuthn Level 2 section 8.3 defines:
// the TPM specification version the signature conforms to.
const tpmStatementVersion = "2.0"

// verifyTPMEvidence applies the WebAuthn Level 2 section 8.3 verification
// procedure to a "tpm" attestation statement, at challenge time.
//
// The caller has already anchored x5c to the configured roots, so x5c[0] is a
// certificate this server trusts; everything below is read from it. The checks:
//
//   - ver is "2.0" and x5c is present;
//   - x5c[0], the AIK certificate, meets section 8.3.1 (checkAIKCertificate);
//   - certInfo carries TPM_GENERATED_VALUE and is a TPM_ST_ATTEST_CERTIFY;
//   - its attested Name is Name(pubArea), computed with pubArea's nameAlg;
//   - its extraData is TPMExtraData(alg, key authorization);
//   - sig verifies over certInfo under x5c[0]'s key with alg.
//
// The last four are the TPM2_Certify binding pkg/attestation applies for every
// TPM carrier, so they are made by that gate rather than here.
//
// What is returned is the evidence those checks were made against. It is not
// an authorization: section 8.3 also requires that pubArea's key be the key
// being registered, and here that key is in the CSR (BindCSRKey).
func verifyTPMEvidence(attestObj *AttestationObject, _ AttestationVerifier, expectedKeyAuth string) (*VerifiedAttestation, error) {
	statement := attestObj.AttStatement
	if statement.Ver != tpmStatementVersion {
		return nil, &errs.Detail{Err: ErrTPMAttestationInvalid, Detail: "ver is " + strconv.Quote(statement.Ver) + ", not " + strconv.Quote(tpmStatementVersion)}
	}
	if len(statement.X5c) == 0 {
		return nil, &errs.Detail{Err: ErrTPMAttestationInvalid, Detail: "x5c is absent"}
	}
	aikDER, ok := statement.X5c[0].([]byte)
	if !ok {
		return nil, &errs.Detail{Err: ErrTPMAttestationInvalid, Detail: "the AIK certificate is not a byte string"}
	}
	aik, err := x509.ParseCertificate(aikDER)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTPMAttestationInvalid, Detail: "the AIK certificate does not parse", Cause: err}
	}
	if err := checkAIKCertificate(aik); err != nil {
		return nil, err
	}

	verified := &VerifiedAttestation{
		KeyAuthorization: expectedKeyAuth,
		Leaf:             aik,
		Algorithm:        statement.Alg,
		CertInfo:         statement.CertInfo,
		Signature:        statement.Sig,
		PubArea:          statement.PubArea,
	}
	evidence, err := verified.tpmEvidence()
	if err != nil {
		return nil, err
	}
	if err := attestation.VerifyInvariants(evidence); err != nil {
		return nil, &errs.Joined{Lead: ErrTPMAttestationInvalid, Cause: err}
	}
	return verified, nil
}

// tpmEvidence is this record's certification in the shape pkg/attestation's
// gate judges, without a subject key: the challenge verifies it as it stands,
// and BindCSRKey adds the CSR's key.
func (v *VerifiedAttestation) tpmEvidence() (*attestation.Evidence, error) {
	if len(v.CertInfo) == 0 || len(v.Signature) == 0 || len(v.PubArea) == 0 {
		return nil, &errs.Detail{Err: ErrTPMAttestationInvalid, Detail: "certInfo, sig and pubArea are all required"}
	}
	aik, err := v.verifiedLeaf()
	if err != nil {
		return nil, err
	}
	signatureAlgorithm, err := coseSignatureAlgorithm(v.Algorithm)
	if err != nil {
		return nil, err
	}
	extraData, err := TPMExtraData(v.Algorithm, v.KeyAuthorization)
	if err != nil {
		return nil, err
	}

	return &attestation.Evidence{
		Format:                    attestation.FormatTPM2,
		AttesterCertificate:       aik,
		CertifySignatureAlgorithm: signatureAlgorithm,
		SubjectPublicArea:         v.PubArea,
		CertifyInfo:               v.CertInfo,
		CertifySignature:          v.Signature,
		ExpectedChallenge:         extraData,
	}, nil
}

// checkAIKCertificate applies the WebAuthn Level 2 section 8.3.1 TPM
// attestation statement certificate requirements to x5c[0]:
//
//   - Version MUST be set to 3.
//   - Subject field MUST be set to empty.
//   - The Subject Alternative Name extension MUST be set as defined in the TCG
//     EK Credential Profile section 3.2.9: a directoryName naming the TPM's
//     manufacturer, model and version.
//   - The Extended Key Usage extension MUST contain tcg-kp-AIKCertificate
//     (2.23.133.8.3).
//   - The Basic Constraints extension MUST have the CA component set to false.
//
// The extended key usage is not checked here. It is what lets a verifier that
// sees only a certificate treat the key as a restricted TPM attestation key,
// so pkg/tpm2 requires it of every certificate-identified attester and the
// gate enforces it for this format with the rest of the certification.
//
// The authority information access and CRL distribution point extensions
// section 8.3.1 describes are OPTIONAL and are not required. The
// id-fido-gen-ce-aaguid comparison section 8.3 makes has nothing to compare
// against: an ACME attestation carries no authenticator data and so no AAGUID.
func checkAIKCertificate(aik *x509.Certificate) error {
	if aik.Version != 3 {
		return &errs.Detail{Err: ErrAIKCertificateInvalid, Detail: "version is " + strconv.Itoa(aik.Version) + ", not 3"}
	}
	if len(aik.Subject.Names) != 0 {
		return &errs.Detail{Err: ErrAIKCertificateInvalid, Detail: "the subject is not empty"}
	}
	tpm := certstore.ParseTCGAttributes(aik)
	if tpm.Manufacturer == "" || tpm.Model == "" || tpm.Version == "" {
		return &errs.Detail{
			Err:    ErrAIKCertificateInvalid,
			Detail: "the subjectAltName does not name the TPM manufacturer, model and version",
		}
	}
	if aik.IsCA {
		return &errs.Detail{Err: ErrAIKCertificateInvalid, Detail: "basicConstraints asserts a CA"}
	}
	return nil
}

// coseSignatureAlgorithm is the X.509 signature algorithm a COSE algorithm
// identifier names, which is how sig is verified under the AIK certificate.
func coseSignatureAlgorithm(alg int64) (x509.SignatureAlgorithm, error) {
	signatureAlgorithm := webauthncose.SigAlgFromCOSEAlg(webauthncose.COSEAlgorithmIdentifier(alg))
	if signatureAlgorithm == x509.UnknownSignatureAlgorithm {
		return x509.UnknownSignatureAlgorithm, &errs.Detail{
			Err:    ErrTPMAttestationInvalid,
			Detail: "alg " + strconv.FormatInt(alg, 10) + " is not a COSE signature algorithm",
		}
	}
	return signatureAlgorithm, nil
}

// TPMExtraData is the extraData a TPM2_Certify must carry to answer a
// device-attest-01 challenge with a "tpm" attestation statement: the hash of
// the ACME key authorization under the hash alg employs.
//
// WebAuthn Level 2 section 8.3 requires "extraData is set to the hash of
// attToBeSigned using the hash algorithm employed in alg", where attToBeSigned
// is authenticatorData || clientDataHash. draft-ietf-acme-device-attest-10
// ("device-attest-01 Challenge") has the client produce the attestation over
// the key authorization in place of that pair, with no authenticator data, so
// attToBeSigned is the key authorization itself.
//
// For the SHA-256 algorithms this equals DICENonce. It is a separate function
// because here alg chooses the hash, and a device signing with ES384 answers
// with SHA-384.
//
// Exported for the same reason DICENonce is: a device, a provisioning tool
// and this verifier have to agree on these bytes exactly.
func TPMExtraData(alg int64, keyAuth string) ([]byte, error) {
	if keyAuth == "" {
		return nil, &errs.Detail{Err: ErrTPMAttestationInvalid, Detail: "no key authorization to bind the tpm attestation to"}
	}
	if _, err := coseSignatureAlgorithm(alg); err != nil {
		return nil, err
	}
	hash := webauthncose.HasherFromCOSEAlg(webauthncose.COSEAlgorithmIdentifier(alg))
	hash.Write([]byte(keyAuth))
	return hash.Sum(nil), nil
}

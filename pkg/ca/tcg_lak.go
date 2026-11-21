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

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// LAKCertificationEvidence is the TPM2_Certify proof that a Local
// Attestation Key (LAK) is resident in the same TPM as the Initial
// Attestation Key (IAK) that certified it, per TCG TPM 2.0 Keys for Device
// Identity and Attestation v1.10 r9 §5.3/§6.3 "Owner Creation of a LAK
// Certificate based on an IAK Certificate" (go-xkms#715).
type LAKCertificationEvidence struct {
	// CertifyInfo is the raw TPMS_ATTEST produced by TPM2_Certify over the
	// LAK's public area (pkg/tpm2.TPM2.CertifyLAK's CertifyResult.CertifyInfo).
	CertifyInfo []byte

	// Signature is the IAK's signature over CertifyInfo, in the ordinary
	// X.509 form matching SignatureAlgorithm -- ASN.1 DER for ECDSA, the raw
	// big-endian value for RSA -- not a marshalled TPMT_SIGNATURE.
	// (CertifyResult.Signature is already in this form.)
	Signature []byte

	// SignatureAlgorithm is the X.509 form of the algorithm the IAK signed
	// CertifyInfo with.
	SignatureAlgorithm x509.SignatureAlgorithm

	// IAKCertificate is the device's own IAK certificate, previously issued
	// by SignTCGCSRIDevID. Its chain is verified against the certificate
	// about to sign the LAK (resolveTCGSigner's signingCert) and its
	// tcg-kp-AIKCertificate EKU is what makes it eligible to attest a LAK
	// (tpm2.VerifyCertifyByCertificate).
	IAKCertificate *x509.Certificate

	// LAKPublicArea is the LAK's marshalled TPMT_PUBLIC: the subject
	// TPM2_Certify names (CertifyResult.AttestedKeyPublicArea).
	LAKPublicArea []byte

	// Nonce is the qualifying data the caller expects inside CertifyInfo,
	// binding the evidence to this enrollment.
	Nonce []byte
}

// IssueLAKCertificate issues a Local Attestation Key certificate in the
// WebAuthn Level 2 §8.3.1 "TPM Attestation Statement Certificate
// Requirements" profile (go-xkms#715):
//
//   - an empty Subject (requirement 2);
//   - a critical subjectAltName directoryName carrying
//     tcg-at-tpmManufacturer, tcg-at-tpmModel and tcg-at-tpmVersion
//     (requirement 3, request.TPMManufacturer/TPMModel/TPMFirmwareVersion);
//   - the tcg-kp-AIKCertificate (2.23.133.8.3) Extended Key Usage
//     (requirement 4);
//   - Basic Constraints CA:false (requirement 5).
//
// This is the resolution TCG DevID v1 r12/v1.10 r9 §8 and WebAuthn §8.3.1
// reach when they disagree about the Subject: the IAK keeps its TCG
// DevID-shaped certificate (a unique X.500 Subject) unchanged, and a separate
// LAK -- certified by the IAK via TPM2_Certify per §5.3/§6.3 -- carries the
// empty-Subject certificate a strict WebAuthn relying party requires. xkey's
// TPM-backed WebAuthn/FIDO2 authenticator attests with the LAK, never the
// IAK.
//
// Before issuing, this verifies:
//  1. evidence.IAKCertificate chains to the certificate that will sign the
//     LAK (resolveTCGSigner's signingCert -- this CA's own issuing
//     certificate, or the tenant's issuer certificate in multi-tenant mode)
//     and is within its validity period.
//  2. The TPM2_Certify evidence itself (tpm2.VerifyCertifyByCertificate):
//     the IAK certificate carries tcg-kp-AIKCertificate, the signature over
//     CertifyInfo verifies under the IAK's certified public key,
//     CertifyInfo carries TPM_GENERATED_VALUE, is a TPM2_Certify (not a
//     quote), and its certified Name matches evidence.LAKPublicArea.
//
// Returns ErrNotInitialized if the CA has not been initialized.
// Returns ErrTCGLAKEvidenceRequired if evidence or evidence.IAKCertificate is
// nil.
// Returns ErrTCGLAKDeviceAttributesRequired if request is missing
// TPMManufacturer, TPMModel or TPMFirmwareVersion.
// Returns ErrTCGIAKUntrusted if the IAK certificate does not chain to the
// signing certificate or is expired.
// Returns ErrTCGCSRVerificationFailed if the TPM2_Certify evidence does not
// verify.
// Returns ErrTCGInvalidPublicKey if the LAK's public area names an
// unsupported key type.
//
// Thread-safe: Yes
func (ca *CA) IssueLAKCertificate(
	ctx context.Context,
	request *CertificateRequest,
	evidence *LAKCertificationEvidence,
) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	if evidence == nil || evidence.IAKCertificate == nil {
		return nil, ErrTCGLAKEvidenceRequired
	}
	if request.TPMManufacturer == "" || request.TPMModel == "" || request.TPMFirmwareVersion == "" {
		return nil, ErrTCGLAKDeviceAttributesRequired
	}
	if err := ValidateTCGTPMManufacturer(request.TPMManufacturer); err != nil {
		return nil, err
	}

	signer, signingCert, _, err := ca.resolveTCGSigner(ctx, request)
	if err != nil {
		return nil, err
	}

	if err := ca.verifyIAKTrustedForLAK(evidence.IAKCertificate, signingCert); err != nil {
		return nil, err
	}

	if _, err := tpm2.VerifyCertifyByCertificate(
		evidence.CertifyInfo,
		evidence.Signature,
		evidence.SignatureAlgorithm,
		evidence.IAKCertificate,
		evidence.LAKPublicArea,
		&tpm2.VerifyCertifyOptions{ExpectedQualifyingData: evidence.Nonce},
	); err != nil {
		return nil, &errs.Detail{Err: ErrTCGCSRVerificationFailed, Detail: fmt.Sprintf("LAK TPM2_Certify evidence: %v", err)}
	}

	lakPubKey, err := tpm2.ExtractPublicKeyFromTPMPublic(evidence.LAKPublicArea)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTCGIAKKeyExtraction, Detail: fmt.Sprintf("LAK public area: %v", err)}
	}
	switch lakPubKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, ErrTCGInvalidPublicKey
	}

	sigAlg := determineSignatureAlgorithm(signer.Public())

	serial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSerialGenerationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	profile, err := ca.Profiles().Get(ProfileNameTCGLocalAK)
	if err != nil {
		return nil, err
	}

	directoryNames := []pkix.Name{tpmDeviceDirectoryName(
		request.TPMManufacturer, request.TPMModel, request.TPMFirmwareVersion)}

	cert, err := ca.issueTCGCertificate(ctx, signer, signingCert, &CertificateSpec{
		Serial:             serial,
		Subject:            pkix.Name{},
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		PublicKey:          lakPubKey,
		SignatureAlgorithm: sigAlg,
		Profile:            profile,
		Request:            request,
		DirectoryNames:     directoryNames,
	})
	if err != nil {
		return nil, &errs.Detail{Err: ErrTCGCertIssuanceFailed, Detail: fmt.Sprintf("lak: %v", err)}
	}

	if ca.certStore != nil {
		if err := ca.certStore.StoreCertificate(cert); err != nil {
			return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("%v", err)}
		}
	}

	return cert, nil
}

// verifyIAKTrustedForLAK verifies that iakCert chains to signingCert -- the
// certificate about to sign the LAK -- and is within its validity period. A
// relying party trusts the LAK precisely because it trusts signingCert, so
// this is "chains to a trusted root" for every mode SignTCGCSRIDevID itself
// supports: signingCert is this CA's own issuing certificate in the ordinary
// case, or the tenant's issuer certificate in multi-tenant (external-signer)
// mode.
//
// Revocation is deliberately not checked here, matching every other TCG
// issuance path in this file (IssueEKCertificate, IssueAKCertificate,
// SignTCGCSRIDevID): none treats a credential's own revocation status as a
// precondition of issuing a *different* credential from it, and a relying
// party verifying the issued LAK certificate later still checks revocation of
// the LAK itself through the ordinary certstore/Verify path.
func (ca *CA) verifyIAKTrustedForLAK(iakCert, signingCert *x509.Certificate) error {
	if signingCert == nil {
		return ErrTCGIAKUntrusted
	}

	roots := x509.NewCertPool()
	roots.AddCert(signingCert)
	if _, err := iakCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return &errs.Joined{Lead: ErrTCGIAKUntrusted, Cause: err}
	}

	return nil
}

// tpmDeviceDirectoryName is the subjectAltName directoryName WebAuthn Level 2
// §8.3.1 requirement 3 requires on a "tpm" format attestation certificate:
// tcg-at-tpmManufacturer, tcg-at-tpmModel and tcg-at-tpmVersion identifying
// the TPM chip itself -- not the host platform, which tcg-at-platformModel
// (CreatePlatformModelExtension) names separately.
func tpmDeviceDirectoryName(manufacturer, model, firmwareVersion string) pkix.Name {
	return pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: OIDTCGAttributeTPMManufacturer, Value: manufacturer},
			{Type: OIDTCGAttributeTPMModel, Value: model},
			{Type: OIDTCGAttributeTPMVersion, Value: firmwareVersion},
		},
	}
}

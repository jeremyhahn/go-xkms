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

package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time interface compliance check for TCGCA.
var _ TCGCA = (*CA)(nil)
var _ IAKCertificateReader = (*CA)(nil)

// tcgNotAfter is the indefinite validity time per TCG TPM 2.0 Keys for Device
// Identity and Attestation Section 8.1. Devices possessing EK/AK/IDevID
// certificates are expected to operate indefinitely into the future.
var tcgNotAfter = func() time.Time {
	t, err := time.Parse("20060102150405Z", "99991231235959Z")
	if err != nil {
		panic("failed to parse TCG notAfter time")
	}
	return t
}()

// IssueEKCertificate issues an Endorsement Key certificate per TCG EK Credential Profile.
//
// Per TCG TPM 2.0 Keys for Device Identity and Attestation Section 8.1:
//   - Devices possessing an EK certificate are expected to operate indefinitely
//   - NotAfter SHOULD use the value 99991231235959Z
//   - Key usage is limited to KeyEncipherment (encryption EKs)
//
// If request.Signer and request.IssuerCert are set, uses them for signing (multi-tenant mode).
// Otherwise, uses the CA's internal signer and certificate.
func (ca *CA) IssueEKCertificate(ctx context.Context, request *CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	if ekPubKey == nil {
		return nil, ErrTCGInvalidPublicKey
	}

	// The TCG EK Credential Profile admits RSA and ECC endorsement keys only.
	switch ekPubKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, ErrTCGInvalidPublicKey
	}

	// Resolve signer and issuer certificate
	signer, signingCert, issuerKeyStoreType, err := ca.resolveTCGSigner(ctx, request)
	if err != nil {
		return nil, err
	}

	sigAlg := determineSignatureAlgorithm(signer.Public())

	// Generate serial number
	serial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSerialGenerationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	// Build TCG-compliant EK certificate extensions. The tcg-kp-EKCertificate
	// marker is not one of them: it is an Extended Key Usage purpose, and the
	// tcg-ek profile's UnknownExtKeyUsage (tcgEKCertificateExtKeyUsage) puts it
	// in the certificate's standard ExtKeyUsage extension, where
	// requireTCGEKCertificateEKU looks for it. Writing it here as a standalone
	// extension under the OID's own Id, which this function once did, put the
	// marker somewhere that check -- and any relying party's own EKU check --
	// does not look.
	var extraExtensions []pkix.Extension

	// Add TCG TPM Specification extension
	specExt, err := CreateTPMSpecificationExtension(TCGTPMSpecification{
		Family:   "2.0",
		Level:    0,
		Revision: 0,
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "tpm specification", Cause: err}
	}
	extraExtensions = append(extraExtensions, specExt)

	// The TPM manufacturer this endorsement key belongs to, as the TCG EK
	// Credential Profile places it: tcg-at-tpmManufacturer inside a
	// subjectAltName directoryName. A DevID enrollment reads it back out of
	// this certificate to build the hardwareModuleName of TCG DevID v1 r12
	// §8.1 (TCGTPMManufacturer), so it must be written where that reader
	// looks. It was once a bare extension under the attribute's own OID,
	// which no reader recognises, and every IDevID enrollment of a TPM
	// endorsed here was refused with ErrTCGEKManufacturerUnknown.
	var directoryNames []pkix.Name
	if request.TPMManufacturer != "" {
		if err := ValidateTCGTPMManufacturer(request.TPMManufacturer); err != nil {
			return nil, err
		}
		directoryNames = append(directoryNames, tpmManufacturerDirectoryName(request.TPMManufacturer))
	}

	// The device's model. It was written under tcg-at-tpmModel (2.23.133.2.2)
	// and the device serial under tcg-at-tpmVersion (2.23.133.2.3), which name
	// the TPM's own model and firmware version rather than the platform's.
	if request.ProdModel != "" {
		modelExt, err := CreatePlatformModelExtension(request.ProdModel)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "platform model", Cause: err}
		}
		extraExtensions = append(extraExtensions, modelExt)
	}

	// The permanent identifier is an RFC 4043 otherName inside subjectAltName,
	// not a standalone extension under the otherName's own OID -- an encoding
	// no relying party looks for. The assigner stays absent: the TCG assigner
	// tcg-on-ekPermIdSha256 asserts the value is a digest of an EK certificate,
	// which a caller-supplied identifier is not.
	var otherNames []OtherName
	if request.PermanentID != "" {
		permID, err := MarshalPermanentIdentifier(request.PermanentID, nil)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "permanent identifier", Cause: err}
		}
		otherNames = append(otherNames, OtherName{TypeID: OIDPermanentIdentifier, Value: permID})
	}

	// Add Trusted Platform extensions
	keyStoreExt, err := CreateTPKeyStoreExtension("TPM2")
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "key store", Cause: err}
	}
	extraExtensions = append(extraExtensions, keyStoreExt)

	if issuerKeyStoreType != "" {
		issuerKeyStoreExt, err := CreateTPIssuerKeyStoreExtension(issuerKeyStoreType)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "issuer key store", Cause: err}
		}
		extraExtensions = append(extraExtensions, issuerKeyStoreExt)
	}

	// Issue the EK certificate per the TCG EK Credential Profile. The profile
	// owns the key usage (KeyEncipherment: an endorsement key is an encryption
	// key) and the extended key usage; the TCG device attributes assembled
	// above ride along as caller extensions.
	//
	// NotBefore is backdated by 1 minute to handle clock skew between server
	// and client.
	profile, err := ca.Profiles().Get(ProfileNameTCGEndorsementKey)
	if err != nil {
		return nil, err
	}

	ekSubject := request.Subject.ToPkixName()
	applyDeviceSerialNumber(&ekSubject, []byte(request.ProdSerial))
	ekSubject, _, err = StampTenant(request.TenantID, ekSubject, nil)
	if err != nil {
		return nil, err
	}

	cert, err := ca.issueTCGCertificate(signer, signingCert, &CertificateSpec{
		Serial:             serial,
		Subject:            ekSubject,
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		PublicKey:          ekPubKey,
		SignatureAlgorithm: sigAlg,
		Profile:            profile,
		Request:            request,
		SANS:               request.SANS,
		ExtraExtensions:    extraExtensions,
		OtherNames:         otherNames,
		DirectoryNames:     directoryNames,
	})
	if err != nil {
		return nil, err
	}

	// Store the certificate
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("%v", err)}
	}

	return cert, nil
}

// IssueAKCertificate issues an Attestation Key certificate per TCG specifications.
//
// Per TCG TPM 2.0 Keys for Device Identity and Attestation:
//   - AK certificates include TPM-specific policy OIDs
//   - NotAfter SHOULD use 99991231235959Z for indefinite validity
//   - Key usage is limited to digital signature (attestation, quotes)
func (ca *CA) IssueAKCertificate(ctx context.Context, request *CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	if pubKey == nil {
		return nil, ErrTCGInvalidPublicKey
	}

	// An attestation key may be RSA, ECC or Ed25519.
	switch pubKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, ErrTCGInvalidPublicKey
	}

	// Resolve signer and issuer certificate
	signer, signingCert, _, err := ca.resolveTCGSigner(ctx, request)
	if err != nil {
		return nil, err
	}

	sigAlg := determineSignatureAlgorithm(signer.Public())

	// Generate serial number
	serial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return nil, &errs.Detail{Err: ErrSerialGenerationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	// Issue the AK certificate per TCG specifications. The profile owns the
	// digital-signature key usage an attestation key needs for quotes, the TCG
	// policy OIDs asserting TPM residency and fixed attributes, and the
	// tcg-kp-AIKCertificate Extended Key Usage marker
	// (tcgAIKCertificateExtKeyUsage) -- it does not appear as an ExtraExtensions
	// entry here because WebAuthn L2 §8.3.1 requires it inside the standard
	// ExtKeyUsage extension, not as a standalone extension of its own.
	//
	// NotBefore is backdated by 1 minute to handle clock skew.
	profile, err := ca.Profiles().Get(ProfileNameTCGAttestationKey)
	if err != nil {
		return nil, err
	}

	akSubject, _, err := StampTenant(request.TenantID, request.Subject.ToPkixName(), nil)
	if err != nil {
		return nil, err
	}

	cert, err := ca.issueTCGCertificate(signer, signingCert, &CertificateSpec{
		Serial:             serial,
		Subject:            akSubject,
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		PublicKey:          pubKey,
		SignatureAlgorithm: sigAlg,
		Profile:            profile,
		Request:            request,
		SANS:               request.SANS,
	})
	if err != nil {
		return nil, err
	}

	// Store the certificate
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return nil, &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("%v", err)}
	}

	return cert, nil
}

// IAKCommonNamePrefix distinguishes an Initial Attestation Key certificate
// from the IDevID certificate issued in the same TCG-CSR-IDEVID enrollment.
const IAKCommonNamePrefix = "iak-"

// IAKCommonName returns the subject common name under which the IAK
// certificate for the device identified by its product model and serial
// number is issued and stored: "iak-<model>-<serial>".
//
// The IDevID certificate of the same device carries the caller's subject
// (the ACME enroll-01 path uses "<model>-<serial>"). The certificate store
// keys records by common name, so the two certificates of one enrollment
// must not share a subject; TCG DevID §8 permits the IAK subject to differ
// from the IDevID subject. This function is the single definition of the
// IAK name: issuance (SignTCGCSRIDevID) and lookup (IAKCertificate) both
// go through it.
func IAKCommonName(model, serial string) string {
	return IAKCommonNamePrefix + model + "-" + serial
}

// IAKCertificate returns the Initial Attestation Key certificate issued to
// the device identified by its product model and serial number, as recorded
// by SignTCGCSRIDevID.
//
// Returns ErrNotInitialized if the CA has not been initialized.
// Returns ErrCertificateNotFound (with the looked-up name as detail) when the
// store holds no IAK record for the device. Devices enrolled before the IAK
// record was kept apart from the IDevID record have no such record until
// they re-enroll or the certificate is re-issued.
//
// Thread-safe: Yes
func (ca *CA) IAKCertificate(ctx context.Context, model, serial string) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	cn := IAKCommonName(model, serial)
	if ca.certStore == nil {
		return nil, &errs.Detail{Err: ErrCertificateNotFound, Detail: cn}
	}
	cert, err := ca.certStore.GetCertificate(cn)
	if err != nil || cert == nil {
		return nil, &errs.Detail{Err: ErrCertificateNotFound, Detail: cn}
	}
	return cert, nil
}

// SignTCGCSRIDevID verifies and signs a TCG-CSR-IDEVID for device identity enrollment.
//
// This method:
//  1. Verifies the TCG-CSR-IDEVID signature (tries RSA-PSS then ECDSA)
//  2. Extracts IAK and IDevID public keys from TPM public areas
//  3. Issues an IAK certificate with TCG AIK extensions under the subject
//     IAKCommonName(model, serial) -- the request subject with its common
//     name replaced -- so that it is stored apart from the IDevID record
//  4. Issues an IDevID certificate with permanent identifier extension
//     under the request subject, unchanged
func (ca *CA) SignTCGCSRIDevID(
	ctx context.Context,
	tcgCSR *tpm2.TCG_CSR_IDEVID,
	request *CertificateRequest) (iakDER, idevidDER []byte, err error) {

	if !ca.initialized.Load() {
		return nil, nil, ErrNotInitialized
	}
	if tcgCSR == nil {
		return nil, nil, ErrInvalidCSR
	}

	// Verify the TCG-CSR-IDEVID - try multiple signature algorithms
	var pubKey crypto.PublicKey
	var unpacked *tpm2.UNPACKED_TCG_CSR_IDEVID

	sigAlgos := []x509.SignatureAlgorithm{
		x509.SHA256WithRSAPSS,
		x509.ECDSAWithSHA256,
	}

	for _, sigAlgo := range sigAlgos {
		pubKey, unpacked, err = tpm2.VerifyTCG_CSR_IDevID_Stateless(tcgCSR, sigAlgo)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrTCGCSRVerificationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	// The same gate the generic CSR carrier answers to.
	//
	// Two carriers exist because the evidence formats are externally defined
	// standards -- TCG-CSR-IDEVID here, PKCS#10 plus format-tagged evidence
	// there -- but only one place decides whether evidence is good enough to
	// sign. Before this, each route reached its own conclusion by its own
	// route, and they had already drifted apart.
	//
	// No expected challenge: this certification is produced when the IDevID is
	// created, long before a CA picks one. Freshness in this ceremony comes
	// from credential activation and the quote, both bound to values chosen
	// in-session.
	if err := attestation.VerifyInvariants(&attestation.Evidence{
		Format:             attestation.FormatTPM2,
		AttesterPublicArea: unpacked.CsrContents.AttestPub,
		SubjectPublicArea:  unpacked.CsrContents.SigningPub,
		CertifyInfo:        unpacked.CsrContents.SgnCertifyInfo,
		CertifySignature:   unpacked.CsrContents.SgnCertifyInfoSig,
	}); err != nil {
		return nil, nil, &errs.Detail{
			Err:    ErrTCGCSRVerificationFailed,
			Detail: fmt.Sprintf("%v", err),
		}
	}

	// Extract IAK public key from TPM public area
	iakPubKey, err := tpm2.ExtractPublicKeyFromTPMPublic(unpacked.CsrContents.AttestPub)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrTCGIAKKeyExtraction, Detail: fmt.Sprintf("%v", err)}
	}

	// Get the CA signer and issuing certificate
	signer, signingCert, issuerKeyStoreType, err := ca.resolveTCGSigner(ctx, request)
	if err != nil {
		return nil, nil, err
	}

	sigAlg := determineSignatureAlgorithm(signer.Public())

	// The two subjectAltName otherNames TCG DevID v1 r12 §8.1 requires on both
	// credentials, derived from the endorsement key certificate the CSR carries
	// (§6.2.2 step 4b makes that certificate part of the request).
	//
	// This is a SHALL, so a CSR from which they cannot be derived is refused
	// rather than certified without them.
	ekCert, ekIntermediates, err := parseEKCertificateChain(unpacked.CsrContents.EkCert)
	if err != nil {
		return nil, nil, err
	}
	if err := ca.verifyEKCertificateChain(ekCert, ekIntermediates); err != nil {
		return nil, nil, err
	}
	deviceIdentity, err := TCGDeviceIdentityFromEKCertificate(ekCert, request.TPMManufacturer)
	if err != nil {
		return nil, nil, err
	}
	otherNames, err := deviceIdentity.OtherNames()
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "subject alternative name", Cause: err}
	}

	// Build IAK certificate extensions
	iakExtensions, err := buildIAKExtensions(unpacked, issuerKeyStoreType)
	if err != nil {
		return nil, nil, err
	}

	// Generate IAK serial number
	iakSerial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrSerialGenerationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	// Issue the IAK certificate. The IAK profile owns its digital-signature key
	// usage and the TCG residency and fixed-attribute policies.
	iakProfile, err := ca.Profiles().Get(ProfileNameTCGInitialAK)
	if err != nil {
		return nil, nil, err
	}

	// The IAK is stored under its own common name. The certificate store keys
	// records by Subject.CommonName; issuing the IAK with the request subject
	// made the IDevID stored a few lines below overwrite it, leaving the CA
	// unable to list, revoke or return the IAK it had signed (#371).
	iakSubject := request.Subject.ToPkixName()
	iakSubject.CommonName = IAKCommonName(
		string(unpacked.CsrContents.ProdModel),
		string(unpacked.CsrContents.ProdSerial))
	applyDeviceSerialNumber(&iakSubject, unpacked.CsrContents.ProdSerial)
	iakSubject, _, err = StampTenant(request.TenantID, iakSubject, nil)
	if err != nil {
		return nil, nil, err
	}

	iakCert, err := ca.issueTCGCertificate(signer, signingCert, &CertificateSpec{
		Serial:             iakSerial,
		Subject:            iakSubject,
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		PublicKey:          iakPubKey,
		SignatureAlgorithm: sigAlg,
		Profile:            iakProfile,
		Request:            request,
		ExtraExtensions:    iakExtensions,
		OtherNames:         otherNames,
	})
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrTCGCertIssuanceFailed, Detail: fmt.Sprintf("iak: %v", err)}
	}

	// Build IDevID certificate extensions and append any caller-supplied extras
	// (e.g. the SDN network-zone extension from the platform layer).
	idevidExtensions, err := buildIDevIDExtensions(unpacked, issuerKeyStoreType)
	if err != nil {
		return nil, nil, err
	}
	if len(request.ExtraExtensions) > 0 {
		idevidExtensions = append(idevidExtensions, request.ExtraExtensions...)
	}

	idevidSubject := request.Subject.ToPkixName()
	applyDeviceSerialNumber(&idevidSubject, unpacked.CsrContents.ProdSerial)
	idevidSubject, _, err = StampTenant(request.TenantID, idevidSubject, nil)
	if err != nil {
		return nil, nil, err
	}

	// Generate IDevID serial number
	idevidSerial, err := ca.serialGen.Generate(ctx)
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrSerialGenerationFailed, Detail: fmt.Sprintf("%v", err)}
	}

	// Issue the IDevID certificate. Its profile adds key encipherment to the
	// IAK's digital-signature key usage because a device identity both
	// authenticates the device and establishes keys with it.
	idevidProfile, err := ca.Profiles().Get(ProfileNameTCGDeviceIdentity)
	if err != nil {
		return nil, nil, err
	}

	idevidCert, err := ca.issueTCGCertificate(signer, signingCert, &CertificateSpec{
		Serial:             idevidSerial,
		Subject:            idevidSubject,
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		PublicKey:          pubKey,
		SignatureAlgorithm: sigAlg,
		Profile:            idevidProfile,
		Request:            request,
		SANS:               request.SANS,
		ExtraExtensions:    idevidExtensions,
		OtherNames:         otherNames,
	})
	if err != nil {
		return nil, nil, &errs.Detail{Err: ErrTCGCertIssuanceFailed, Detail: fmt.Sprintf("idevid: %v", err)}
	}

	// Persist both issued certs to the CA's certificate store so they
	// appear in ListCertificates, can be revoked, and are available for
	// post-issuance hooks (DNS registration, SDN VLAN transition, etc.).
	// Without this, ACME enroll-01 silently signs+returns certs to the
	// device while the CA forgets they exist — devices end up with valid
	// certs the CA can never revoke, list, or audit. Matches SignCSR's
	// post-signing storage call (ca.go:1349). The two subjects differ (see
	// iakSubject above), so the second store does not replace the first.
	if ca.certStore != nil {
		if storeErr := ca.certStore.StoreCertificate(iakCert); storeErr != nil {
			return nil, nil, &errs.Detail{Err: ErrTCGCertIssuanceFailed, Detail: fmt.Sprintf("store iak: %v", storeErr)}
		}
		if storeErr := ca.certStore.StoreCertificate(idevidCert); storeErr != nil {
			return nil, nil, &errs.Detail{Err: ErrTCGCertIssuanceFailed, Detail: fmt.Sprintf("store idevid: %v", storeErr)}
		}
	}

	return iakCert.Raw, idevidCert.Raw, nil
}

// resolveTCGSigner determines the signer, signing certificate, and issuer keystore
// type for a TCG certificate operation. If the request provides an external signer
// and issuer cert (multi-tenant mode), those are used. Otherwise the CA's internal
// signer is used.
func (ca *CA) resolveTCGSigner(ctx context.Context, request *CertificateRequest) (crypto.Signer, *x509.Certificate, string, error) {
	if request.Signer != nil && request.IssuerCert != nil {
		return request.Signer, request.IssuerCert, "external", nil
	}
	if request.Signer != nil {
		return nil, nil, "", ErrTCGInvalidIssuer
	}

	// Use internal CA signer
	ca.mu.RLock()
	signingCert := ca.getIssuingCertificate()
	ca.mu.RUnlock()

	if signingCert == nil {
		return nil, nil, "", ErrCertificateNotFound
	}

	signer, err := ca.getSigner(ctx)
	if err != nil {
		return nil, nil, "", &errs.Detail{Err: ErrSigningFailed, Detail: fmt.Sprintf("%v", err)}
	}

	issuerKeyStoreType := ""
	issuingIdentity := ca.config.IssuingIdentity()
	if issuingIdentity != nil {
		issuerKeyStoreType = string(issuingIdentity.GetStoreType())
	}

	return signer, signingCert, issuerKeyStoreType, nil
}

// issueTCGCertificate issues one TCG credential through the CA's canonical
// issuance path.
//
// The CA's issuing identity supplies the revocation and Authority Information
// Access endpoints, exactly as it does for the root, intermediate and
// end-entity paths — a TPM credential is a certificate this CA is responsible
// for revoking like any other. A credential signed with a caller-supplied
// Signer belongs to a different issuer whose CRL and OCSP services this CA
// cannot speak for, so that path carries no identity; this is the same rule
// SignCSR applies.
func (ca *CA) issueTCGCertificate(
	signer crypto.Signer,
	signingCert *x509.Certificate,
	spec *CertificateSpec,
) (*x509.Certificate, error) {
	issuer := &Issuer{Signer: signer, Certificate: signingCert}
	if spec.Request == nil || spec.Request.Signer == nil {
		issuer.Identity = ca.config.IssuingIdentity()
	}
	cert, err := issuer.Issue(rand.Reader, spec)
	if err != nil {
		return nil, &errs.Detail{Err: ErrTCGCertIssuanceFailed, Detail: fmt.Sprintf("%v", err)}
	}
	return cert, nil
}

// applyDeviceSerialNumber writes the device's serial number into the subject
// distinguished name, where TCG DevID v1 r12 §8.1 (spec text line 2800) asks
// for it: "The subject field's DN encoding SHOULD include the 'serialNumber'
// attribute with the device's unique serial number."
//
// A serial number the caller set explicitly is left alone; the CSR's product
// serial is what the device asserted about itself and the caller's subject is
// the CA's own decision about the same device.
func applyDeviceSerialNumber(subject *pkix.Name, prodSerial []byte) {
	if subject.SerialNumber != "" || len(prodSerial) == 0 {
		return
	}
	subject.SerialNumber = string(prodSerial)
}

// buildIAKExtensions builds the extensions for an IAK certificate.
//
// The TCG policy assertions -- tcg-cap-verifiedTPMResidency and
// tcg-cap-verifiedTPMRestricted -- are NOT here. TCG DevID v1 r12 §8.2 (spec
// text lines 3000-3013) defines them as certificate POLICY object identifiers
// carrying "No data", and the IAK profile stamps them into certificatePolicies.
// They were also written as standalone boolean-valued extensions, an encoding
// §8.2 does not define and no relying party reads.
//
// Nor is the tcg-kp-AIKCertificate marker (2.23.133.8.3) here. WebAuthn L2
// §8.3.1 and go-webauthn's "tpm" attestation format verifier both require it
// inside the certificate's standard ExtKeyUsage extension, which is what the
// tcg-iak profile's UnknownExtKeyUsage produces (tcgAIKCertificateExtKeyUsage
// via NewTCGInitialAttestationKeyProfile). Writing it here as a standalone
// extension under the OID's own Id, which this function once did, put the
// marker somewhere no such verifier looks.
//
// Every extension below is mandatory for the credential, so a failure to build
// one refuses issuance rather than issuing a certificate that asserts less than
// the CA verified.
func buildIAKExtensions(unpacked *tpm2.UNPACKED_TCG_CSR_IDEVID, issuerKeyStoreType string) ([]pkix.Extension, error) {
	return buildPlatformExtensions(unpacked, issuerKeyStoreType)
}

// buildIDevIDExtensions builds the extensions for an IDevID certificate.
//
// The RFC 4108 hardwareModuleName and RFC 4043 permanentIdentifier that TCG
// DevID v1 r12 §8.1 requires are not here either: both are subjectAltName
// otherNames, carried through CertificateSpec.OtherNames so that one extension
// holds them alongside the certificate's DNS and IP names.
func buildIDevIDExtensions(unpacked *tpm2.UNPACKED_TCG_CSR_IDEVID, issuerKeyStoreType string) ([]pkix.Extension, error) {
	return buildPlatformExtensions(unpacked, issuerKeyStoreType)
}

// buildPlatformExtensions builds the device and keystore extensions shared by
// the IAK and IDevID certificates of one enrollment.
//
// The product model is written under tcg-at-platformModel (2.23.133.2.5). It
// was written under tcg-at-tpmModel (2.23.133.2.2) and the product serial under
// tcg-at-tpmVersion (2.23.133.2.3), which name the TPM's own model and firmware
// version -- a reader taking those at face value would attribute the device's
// model to its TPM. The product serial has no extension at all: TCG DevID v1
// r12 §8.1 (spec text line 2800) puts it in the subject, "The subject field's DN
// encoding SHOULD include the 'serialNumber' attribute with the device's unique
// serial number", which is where SignTCGCSRIDevID now writes it.
func buildPlatformExtensions(
	unpacked *tpm2.UNPACKED_TCG_CSR_IDEVID,
	issuerKeyStoreType string,
) ([]pkix.Extension, error) {
	var extensions []pkix.Extension

	if len(unpacked.CsrContents.ProdModel) > 0 {
		ext, err := CreatePlatformModelExtension(string(unpacked.CsrContents.ProdModel))
		if err != nil {
			return nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "platform model", Cause: err}
		}
		extensions = append(extensions, ext)
	}

	ext, err := CreateTPKeyStoreExtension("TPM2")
	if err != nil {
		return nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "key store", Cause: err}
	}
	extensions = append(extensions, ext)

	if issuerKeyStoreType != "" {
		ext, err := CreateTPIssuerKeyStoreExtension(issuerKeyStoreType)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrTCGMandatoryExtension, Detail: "issuer key store", Cause: err}
		}
		extensions = append(extensions, ext)
	}

	return extensions, nil
}

// VerifyQuote verifies a TPM quote signature and validates that the nonce matches.
//
// This is the primary method for remote attestation verification per TCG
// specifications. The verification process:
//  1. Validates that the returned nonce matches the expected nonce
//  2. Computes a SHA-256 digest of the quoted data
//  3. Verifies the signature using the AK's public key
//
// The AK public key is resolved from attrs.TPMAttributes.PublicKeyBytes when
// present, falling back to the certificate stored in the certificate store.
func (ca *CA) VerifyQuote(attrs *types.KeyAttributes, quote *tpm2.Quote, nonce []byte) error {
	if !ca.initialized.Load() {
		return ErrNotInitialized
	}
	if attrs == nil || quote == nil {
		return &errs.Detail{Err: ErrInvalidCSR, Detail: "attrs and quote must not be nil"}
	}

	// Verify the nonce matches.
	if !bytes.Equal(quote.Nonce, nonce) {
		return &errs.Detail{Err: ErrInvalidSignature, Detail: "nonce mismatch"}
	}

	// Compute digest of quoted data.
	digest := sha256.Sum256(quote.Quoted)

	// Resolve the AK public key.
	var pubKey crypto.PublicKey
	var err error

	if attrs.TPMAttributes != nil && len(attrs.TPMAttributes.PublicKeyBytes) > 0 {
		pubKey, err = x509.ParsePKIXPublicKey(attrs.TPMAttributes.PublicKeyBytes)
		if err != nil {
			return &errs.Detail{Err: ErrInvalidSignature, Detail: fmt.Sprintf("failed to parse AK public key from TPM attributes: %v", err)}
		}
	} else {
		// Fall back to the certificate store.
		cert, err := ca.certStore.GetCertificate(attrs.CN)
		if err != nil {
			return &errs.Detail{Err: ErrCertificateNotFound, Detail: fmt.Sprintf("AK certificate not found for CN %q: %v", attrs.CN, err)}
		}
		pubKey = cert.PublicKey
	}

	// Verify the signature based on key type.
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		// Try RSA-PSS first (preferred for TPM), then fall back to PKCS1v15.
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}
		if err = rsa.VerifyPSS(key, crypto.SHA256, digest[:], quote.Signature, pssOpts); err != nil {
			err = rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], quote.Signature)
		}
		if err != nil {
			return &errs.Detail{Err: ErrInvalidSignature, Detail: "RSA quote signature verification failed"}
		}

	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], quote.Signature) {
			return &errs.Detail{Err: ErrInvalidSignature, Detail: "ECDSA quote signature verification failed"}
		}

	case ed25519.PublicKey:
		if !ed25519.Verify(key, digest[:], quote.Signature) {
			return &errs.Detail{Err: ErrInvalidSignature, Detail: "Ed25519 quote signature verification failed"}
		}

	default:
		return &errs.Detail{Err: ErrInvalidSignature, Detail: fmt.Sprintf("unsupported AK key type %T", pubKey)}
	}

	return nil
}

// ImportEndorsementKeyCertificate imports a manufacturer-provided EK certificate
// into the CA's certificate store.
//
// The certificate is validated for the presence of the TCG EK OID extension
// (OIDTCGKpEKCertificate). An absent OID logs a warning but is not treated as
// an error, to accommodate non-standard manufacturer certificates.
func (ca *CA) ImportEndorsementKeyCertificate(cert *x509.Certificate) error {
	if !ca.initialized.Load() {
		return ErrNotInitialized
	}
	if cert == nil {
		return &errs.Detail{Err: ErrInvalidCertificate, Detail: "nil EK certificate"}
	}

	// Warn when the TCG EK OID is absent; some manufacturer certs omit it.
	if !evidence.HasEKCertificateEKU(cert) {
		slog.Warn("ca: importing EK certificate without TCG EK OID extension",
			"cn", cert.Subject.CommonName)
	}

	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return &errs.Detail{Err: ErrStorageError, Detail: fmt.Sprintf("failed to store EK certificate: %v", err)}
	}

	return nil
}

// EndorsementKeyCertificate retrieves an EK certificate from the certificate
// store by Common Name.
//
// Logs a warning when the retrieved certificate does not carry the TCG EK OID
// extension, consistent with ImportEndorsementKeyCertificate behaviour.
func (ca *CA) EndorsementKeyCertificate(cn string) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}

	cert, err := ca.certStore.GetCertificate(cn)
	if err != nil {
		return nil, &errs.Detail{Err: ErrCertificateNotFound, Detail: fmt.Sprintf("EK certificate not found for CN %q: %v", cn, err)}
	}

	// Warn when the TCG EK OID is absent.
	if !evidence.HasEKCertificateEKU(cert) {
		slog.Warn("ca: retrieved EK certificate without TCG EK OID extension",
			"cn", cn)
	}

	return cert, nil
}

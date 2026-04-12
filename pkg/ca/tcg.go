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

	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time interface compliance check for TCGCA.
var _ TCGCA = (*CA)(nil)

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
func (ca *CA) IssueEKCertificate(request *CertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	if ekPubKey == nil {
		return nil, ErrTCGInvalidPublicKey
	}

	// Determine key algorithm from public key
	var keyAlgorithm x509.PublicKeyAlgorithm
	switch ekPubKey.(type) {
	case *rsa.PublicKey:
		keyAlgorithm = x509.RSA
	case *ecdsa.PublicKey:
		keyAlgorithm = x509.ECDSA
	default:
		return nil, ErrTCGInvalidPublicKey
	}

	// Resolve signer and issuer certificate
	signer, signingCert, issuerKeyStoreType, err := ca.resolveTCGSigner(request)
	if err != nil {
		return nil, err
	}

	sigAlg := determineSignatureAlgorithm(signer.Public())

	// Generate serial number
	serial, err := ca.serialGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerialGenerationFailed, err)
	}

	// Build TCG-compliant EK certificate extensions
	extraExtensions := []pkix.Extension{
		{
			// TCG EK Certificate marker (tcg-kp-EKCertificate)
			Id:       OIDTCGKpEKCertificate,
			Critical: false,
			Value:    []byte{},
		},
	}

	// Add TCG TPM Specification extension
	if specExt, err := CreateTPMSpecificationExtension(TCGTPMSpecification{
		Family:   "2.0",
		Level:    0,
		Revision: 0,
	}); err == nil {
		extraExtensions = append(extraExtensions, specExt)
	}

	// Add TPM device information extensions if provided
	if request.ProdModel != "" {
		if modelExt, err := CreateTPMModelExtension(request.ProdModel); err == nil {
			extraExtensions = append(extraExtensions, modelExt)
		}
	}
	if request.ProdSerial != "" {
		if versionExt, err := CreateTPMVersionExtension(request.ProdSerial); err == nil {
			extraExtensions = append(extraExtensions, versionExt)
		}
	}

	// Add Permanent Identifier extension if provided
	if request.PermanentID != "" {
		if permIDExt, err := CreatePermanentIdentifierExtension(request.PermanentID, nil); err == nil {
			extraExtensions = append(extraExtensions, permIDExt)
		}
	}

	// Add Trusted Platform extensions
	if keyStoreExt, err := CreateTPKeyStoreExtension("TPM2"); err == nil {
		extraExtensions = append(extraExtensions, keyStoreExt)
	}
	if issuerKeyStoreType != "" {
		if issuerKeyStoreExt, err := CreateTPIssuerKeyStoreExtension(issuerKeyStoreType); err == nil {
			extraExtensions = append(extraExtensions, issuerKeyStoreExt)
		}
	}

	// Create EK certificate template per TCG EK Credential Profile.
	// NotBefore is backdated by 1 minute to handle clock skew between server and client.
	template := &x509.Certificate{
		Version:            3,
		SerialNumber:       serial,
		Subject:            request.Subject.ToPkixName(),
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		SignatureAlgorithm: sigAlg,
		PublicKeyAlgorithm: keyAlgorithm,
		PublicKey:          ekPubKey,
		Issuer:             signingCert.Subject,
		AuthorityKeyId:     signingCert.SubjectKeyId,
		// Per TCG EK Credential Profile: KeyUsage is KeyEncipherment for encryption EKs
		KeyUsage:        x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtraExtensions: extraExtensions,
		IsCA:            false,
	}

	// Add SANs if provided
	if request.SANS != nil {
		addSANsToTemplate(template, request.SANS)
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, signingCert, ekPubKey, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCGCertIssuanceFailed, err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCGCertIssuanceFailed, err)
	}

	// Store the certificate
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageError, err)
	}

	return cert, nil
}

// IssueAKCertificate issues an Attestation Key certificate per TCG specifications.
//
// Per TCG TPM 2.0 Keys for Device Identity and Attestation:
//   - AK certificates include TPM-specific policy OIDs
//   - NotAfter SHOULD use 99991231235959Z for indefinite validity
//   - Key usage is limited to digital signature (attestation, quotes)
func (ca *CA) IssueAKCertificate(request *CertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	if !ca.initialized.Load() {
		return nil, ErrNotInitialized
	}
	if pubKey == nil {
		return nil, ErrTCGInvalidPublicKey
	}

	// Determine key algorithm from public key
	var keyAlgorithm x509.PublicKeyAlgorithm
	switch pubKey.(type) {
	case *rsa.PublicKey:
		keyAlgorithm = x509.RSA
	case *ecdsa.PublicKey:
		keyAlgorithm = x509.ECDSA
	case ed25519.PublicKey:
		keyAlgorithm = x509.Ed25519
	default:
		return nil, ErrTCGInvalidPublicKey
	}

	// Resolve signer and issuer certificate
	signer, signingCert, _, err := ca.resolveTCGSigner(request)
	if err != nil {
		return nil, err
	}

	sigAlg := determineSignatureAlgorithm(signer.Public())

	// Generate serial number
	serial, err := ca.serialGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSerialGenerationFailed, err)
	}

	// Build TCG-compliant AK certificate extensions
	extraExtensions := []pkix.Extension{
		{
			// TCG AIK Certificate marker (TPM 1.2 compatible, required for WebAuthn)
			Id:       OIDTCGKpAIKCertificate,
			Critical: false,
			Value:    []byte{},
		},
	}

	// Create AK certificate template per TCG specifications.
	// NotBefore is backdated by 1 minute to handle clock skew.
	template := &x509.Certificate{
		Version:            3,
		SerialNumber:       serial,
		Subject:            request.Subject.ToPkixName(),
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		SignatureAlgorithm: sigAlg,
		PublicKeyAlgorithm: keyAlgorithm,
		PublicKey:          pubKey,
		Issuer:             signingCert.Subject,
		AuthorityKeyId:     signingCert.SubjectKeyId,
		// Per TCG: AK is used for digital signatures (attestation, quotes)
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// TCG policy OIDs indicating TPM residency and fixed attributes
		// Using Policies field for Go 1.24+ compatibility
		Policies: []x509.OID{
			TCGVerifiedTPMResidencyPolicy,
			TCGVerifiedTPMFixedPolicy,
		},
		ExtraExtensions: extraExtensions,
		IsCA:            false,
	}

	// Add SANs if provided
	if request.SANS != nil {
		addSANsToTemplate(template, request.SANS)
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, signingCert, pubKey, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCGCertIssuanceFailed, err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTCGCertIssuanceFailed, err)
	}

	// Store the certificate
	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStorageError, err)
	}

	return cert, nil
}

// SignTCGCSRIDevID verifies and signs a TCG-CSR-IDEVID for device identity enrollment.
//
// This method:
//  1. Verifies the TCG-CSR-IDEVID signature (tries RSA-PSS then ECDSA)
//  2. Extracts IAK and IDevID public keys from TPM public areas
//  3. Issues an IAK certificate with TCG AIK extensions
//  4. Issues an IDevID certificate with permanent identifier extension
func (ca *CA) SignTCGCSRIDevID(
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
		return nil, nil, fmt.Errorf("%w: %v", ErrTCGCSRVerificationFailed, err)
	}

	// Extract IAK public key from TPM public area
	iakPubKey, err := tpm2.ExtractPublicKeyFromTPMPublic(unpacked.CsrContents.AttestPub)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrTCGIAKKeyExtraction, err)
	}

	// Get the CA signer and issuing certificate
	signer, signingCert, issuerKeyStoreType, err := ca.resolveTCGSigner(request)
	if err != nil {
		return nil, nil, err
	}

	sigAlg := determineSignatureAlgorithm(signer.Public())

	// Build IAK certificate extensions
	iakExtensions := buildIAKExtensions(unpacked, issuerKeyStoreType)

	// Generate IAK serial number
	iakSerial, err := ca.serialGen.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSerialGenerationFailed, err)
	}

	// Create IAK certificate template
	iakTemplate := &x509.Certificate{
		SerialNumber:       iakSerial,
		Subject:            request.Subject.ToPkixName(),
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		SignatureAlgorithm: sigAlg,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		Policies: []x509.OID{
			TCGVerifiedTPMResidencyPolicy,
			TCGVerifiedTPMFixedPolicy,
		},
		ExtraExtensions: iakExtensions,
		IsCA:            false,
		Issuer:          signingCert.Subject,
		AuthorityKeyId:  signingCert.SubjectKeyId,
	}

	iakCertDER, err := x509.CreateCertificate(rand.Reader, iakTemplate, signingCert, iakPubKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: iak: %v", ErrTCGCertIssuanceFailed, err)
	}

	// Build IDevID certificate extensions
	idevidExtensions := buildIDevIDExtensions(unpacked, issuerKeyStoreType)

	// Generate IDevID serial number
	idevidSerial, err := ca.serialGen.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSerialGenerationFailed, err)
	}

	// Create IDevID certificate template
	idevidTemplate := &x509.Certificate{
		SerialNumber:       idevidSerial,
		Subject:            request.Subject.ToPkixName(),
		NotBefore:          time.Now().Add(-1 * time.Minute),
		NotAfter:           tcgNotAfter,
		SignatureAlgorithm: sigAlg,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		Policies: []x509.OID{
			TCGVerifiedTPMResidencyPolicy,
			TCGVerifiedTPMFixedPolicy,
		},
		ExtraExtensions: idevidExtensions,
		IsCA:            false,
		Issuer:          signingCert.Subject,
		AuthorityKeyId:  signingCert.SubjectKeyId,
	}

	// Add SANs to IDevID certificate if provided
	if request.SANS != nil {
		addSANsToTemplate(idevidTemplate, request.SANS)
	}

	idevidCertDER, err := x509.CreateCertificate(rand.Reader, idevidTemplate, signingCert, pubKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: idevid: %v", ErrTCGCertIssuanceFailed, err)
	}

	return iakCertDER, idevidCertDER, nil
}

// resolveTCGSigner determines the signer, signing certificate, and issuer keystore
// type for a TCG certificate operation. If the request provides an external signer
// and issuer cert (multi-tenant mode), those are used. Otherwise the CA's internal
// signer is used.
func (ca *CA) resolveTCGSigner(request *CertificateRequest) (crypto.Signer, *x509.Certificate, string, error) {
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

	signer, err := ca.getSigner()
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	issuerKeyStoreType := ""
	issuingIdentity := ca.config.IssuingIdentity()
	if issuingIdentity != nil {
		issuerKeyStoreType = string(issuingIdentity.KeystoreType)
	}

	return signer, signingCert, issuerKeyStoreType, nil
}

// addSANsToTemplate adds Subject Alternative Names from a SubjectAlternativeNames
// to a certificate template.
func addSANsToTemplate(template *x509.Certificate, sans *SubjectAlternativeNames) {
	if sans == nil {
		return
	}
	template.DNSNames = append(template.DNSNames, sans.DNS...)
	template.EmailAddresses = append(template.EmailAddresses, sans.Email...)
	template.IPAddresses = append(template.IPAddresses, sans.ParseIPs()...)
	template.URIs = append(template.URIs, sans.ParseURIs()...)
}

// buildIAKExtensions builds the TCG extensions for an IAK certificate.
func buildIAKExtensions(unpacked *tpm2.UNPACKED_TCG_CSR_IDEVID, issuerKeyStoreType string) []pkix.Extension {
	extensions := []pkix.Extension{
		{
			// TCG AIK Certificate marker
			Id:       OIDTCGKpAIKCertificate,
			Critical: false,
			Value:    []byte{},
		},
	}

	// Add TPM model extension if available
	if len(unpacked.CsrContents.ProdModel) > 0 {
		if ext, err := CreateTPMModelExtension(string(unpacked.CsrContents.ProdModel)); err == nil {
			extensions = append(extensions, ext)
		}
	}

	// Add TPM version/serial extension if available
	if len(unpacked.CsrContents.ProdSerial) > 0 {
		if ext, err := CreateTPMVersionExtension(string(unpacked.CsrContents.ProdSerial)); err == nil {
			extensions = append(extensions, ext)
		}
	}

	// Add Verified TPM Residency extension (key proven to reside in TPM)
	if ext, err := CreateVerifiedTPMResidencyExtension(true); err == nil {
		extensions = append(extensions, ext)
	}

	// Add Verified TPM Fixed extension (key is non-migratable)
	if ext, err := CreateVerifiedTPMFixedExtension(true); err == nil {
		extensions = append(extensions, ext)
	}

	// Add Trusted Platform extensions
	if ext, err := CreateTPKeyStoreExtension("TPM2"); err == nil {
		extensions = append(extensions, ext)
	}
	if issuerKeyStoreType != "" {
		if ext, err := CreateTPIssuerKeyStoreExtension(issuerKeyStoreType); err == nil {
			extensions = append(extensions, ext)
		}
	}

	return extensions
}

// buildIDevIDExtensions builds the TCG extensions for an IDevID certificate.
func buildIDevIDExtensions(unpacked *tpm2.UNPACKED_TCG_CSR_IDEVID, issuerKeyStoreType string) []pkix.Extension {
	var extensions []pkix.Extension

	// Add TPM model extension
	if len(unpacked.CsrContents.ProdModel) > 0 {
		if ext, err := CreateTPMModelExtension(string(unpacked.CsrContents.ProdModel)); err == nil {
			extensions = append(extensions, ext)
		}
	}

	// Add TPM version extension
	if len(unpacked.CsrContents.ProdSerial) > 0 {
		if ext, err := CreateTPMVersionExtension(string(unpacked.CsrContents.ProdSerial)); err == nil {
			extensions = append(extensions, ext)
		}
	}

	// Build permanent identifier from product model and serial
	permanentID := fmt.Sprintf("%s-%s",
		string(unpacked.CsrContents.ProdModel),
		string(unpacked.CsrContents.ProdSerial))
	if ext, err := CreatePermanentIdentifierExtension(permanentID, nil); err == nil {
		extensions = append(extensions, ext)
	}

	// Add Verified TPM Residency extension
	if ext, err := CreateVerifiedTPMResidencyExtension(true); err == nil {
		extensions = append(extensions, ext)
	}

	// Add Verified TPM Fixed extension
	if ext, err := CreateVerifiedTPMFixedExtension(true); err == nil {
		extensions = append(extensions, ext)
	}

	// Add Trusted Platform extensions
	if ext, err := CreateTPKeyStoreExtension("TPM2"); err == nil {
		extensions = append(extensions, ext)
	}
	if issuerKeyStoreType != "" {
		if ext, err := CreateTPIssuerKeyStoreExtension(issuerKeyStoreType); err == nil {
			extensions = append(extensions, ext)
		}
	}

	return extensions
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
		return fmt.Errorf("%w: attrs and quote must not be nil", ErrInvalidCSR)
	}

	// Verify the nonce matches.
	if !bytes.Equal(quote.Nonce, nonce) {
		return fmt.Errorf("%w: nonce mismatch", ErrInvalidSignature)
	}

	// Compute digest of quoted data.
	digest := sha256.Sum256(quote.Quoted)

	// Resolve the AK public key.
	var pubKey crypto.PublicKey
	var err error

	if attrs.TPMAttributes != nil && len(attrs.TPMAttributes.PublicKeyBytes) > 0 {
		pubKey, err = x509.ParsePKIXPublicKey(attrs.TPMAttributes.PublicKeyBytes)
		if err != nil {
			return fmt.Errorf("%w: failed to parse AK public key from TPM attributes: %v",
				ErrInvalidSignature, err)
		}
	} else {
		// Fall back to the certificate store.
		cert, err := ca.certStore.GetCertificate(attrs.CN)
		if err != nil {
			return fmt.Errorf("%w: AK certificate not found for CN %q: %v",
				ErrCertificateNotFound, attrs.CN, err)
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
			return fmt.Errorf("%w: RSA quote signature verification failed", ErrInvalidSignature)
		}

	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], quote.Signature) {
			return fmt.Errorf("%w: ECDSA quote signature verification failed", ErrInvalidSignature)
		}

	case ed25519.PublicKey:
		if !ed25519.Verify(key, digest[:], quote.Signature) {
			return fmt.Errorf("%w: Ed25519 quote signature verification failed", ErrInvalidSignature)
		}

	default:
		return fmt.Errorf("%w: unsupported AK key type %T", ErrInvalidSignature, pubKey)
	}

	return nil
}

// ImportEndorsementKeyCertificate imports a manufacturer-provided EK certificate
// into the CA's certificate store.
//
// The certificate is validated for the presence of the TCG EK OID extension
// (OIDTCGEKCertificate). An absent OID logs a warning but is not treated as
// an error, to accommodate non-standard manufacturer certificates.
func (ca *CA) ImportEndorsementKeyCertificate(cert *x509.Certificate) error {
	if !ca.initialized.Load() {
		return ErrNotInitialized
	}
	if cert == nil {
		return fmt.Errorf("%w: nil EK certificate", ErrInvalidCertificate)
	}

	// Warn when the TCG EK OID is absent; some manufacturer certs omit it.
	hasEKOID := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGEKCertificate) {
			hasEKOID = true
			break
		}
	}
	if !hasEKOID {
		slog.Warn("ca: importing EK certificate without TCG EK OID extension",
			"cn", cert.Subject.CommonName)
	}

	if err := ca.certStore.StoreCertificate(cert); err != nil {
		return fmt.Errorf("%w: failed to store EK certificate: %v", ErrStorageError, err)
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
		return nil, fmt.Errorf("%w: EK certificate not found for CN %q: %v",
			ErrCertificateNotFound, cn, err)
	}

	// Warn when the TCG EK OID is absent.
	hasEKOID := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDTCGEKCertificate) {
			hasEKOID = true
			break
		}
	}
	if !hasEKOID {
		slog.Warn("ca: retrieved EK certificate without TCG EK OID extension",
			"cn", cn)
	}

	return cert, nil
}

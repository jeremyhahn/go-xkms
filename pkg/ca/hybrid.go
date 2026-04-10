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

// Package ca provides hybrid certificate support per ITU-T X.509 (2019) Amendment 1.
//
// Hybrid certificates contain both a classical (ECDSA, RSA, Ed25519) signature
// and a post-quantum (ML-DSA) alternative signature. This enables a smooth
// migration to post-quantum cryptography: systems that understand the alternative
// signature extensions can verify both signatures, while legacy systems can
// verify the classical signature and ignore the unknown extensions.
//
// The alternative signature is carried in three X.509v3 extensions:
//
//   - subjectAltPublicKeyInfo (OID 2.5.29.72): The quantum public key
//   - altSignatureAlgorithm  (OID 2.5.29.73): The quantum signature algorithm
//   - altSignatureValue      (OID 2.5.29.74): The quantum signature
//
// These OIDs are defined in ITU-T Recommendation X.509 (2019) Amendment 1
// for hybrid/composite digital signature certificates.
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/quantum"
)

// OIDs for hybrid certificate extensions per ITU-T X.509 (2019) Amendment 1.
var (
	oidSubjectAltPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}
	oidAltSignatureAlgorithm   = asn1.ObjectIdentifier{2, 5, 29, 73}
	oidAltSignatureValue       = asn1.ObjectIdentifier{2, 5, 29, 74}
)

// Hybrid certificate error types.

// HybridCertError indicates an error during hybrid certificate operations.
type HybridCertError struct {
	Op  string
	Err error
}

func (e *HybridCertError) Error() string {
	return "ca: hybrid cert " + e.Op + ": " + e.Err.Error()
}

func (e *HybridCertError) Unwrap() error {
	return e.Err
}

// HybridVerificationError indicates hybrid certificate verification failed.
type HybridVerificationError struct {
	Component string // "classical" or "quantum"
	Reason    string
}

func (e *HybridVerificationError) Error() string {
	return "ca: hybrid verification " + e.Component + ": " + e.Reason
}

// CreateHybridCertificate creates an X.509 certificate that contains both
// a classical digital signature and an ML-DSA alternative signature.
//
// The process follows ITU-T X.509 (2019) Amendment 1:
//
//  1. Build the certificate template with quantum alternative extensions
//     (subjectAltPublicKeyInfo and altSignatureAlgorithm)
//  2. Create an initial certificate with classical signing (to get a valid TBS)
//  3. Sign the TBS with the quantum key to produce altSignatureValue
//  4. Add the altSignatureValue extension to the template
//  5. Re-create the certificate with the classical key (final version with all extensions)
//
// Parameters:
//   - template: The certificate template
//   - parent: The issuer certificate (for self-signed, pass template)
//   - classicalKey: The classical signing key (ECDSA, RSA, or Ed25519)
//   - quantumKey: The ML-DSA signing key
//
// Returns the DER-encoded hybrid certificate or an error.
func CreateHybridCertificate(
	template, parent *x509.Certificate,
	classicalKey crypto.Signer,
	quantumKey *quantum.MLDSAPrivateKey,
) ([]byte, error) {

	if template == nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("template certificate is nil")}
	}
	if parent == nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("parent certificate is nil")}
	}
	if classicalKey == nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("classical key is nil")}
	}
	if quantumKey == nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("quantum key is nil")}
	}

	// Determine the quantum signature algorithm OID
	quantumAlgOID, err := quantumAlgorithmOID(quantumKey.Algorithm)
	if err != nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("quantum algorithm OID: %w", err)}
	}

	// Build the subjectAltPublicKeyInfo extension value.
	// This embeds the quantum public key in the certificate.
	altPubKeyExt, err := buildAltPublicKeyInfoExtension(quantumKey.PublicKey, quantumAlgOID)
	if err != nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("build alt public key info: %w", err)}
	}

	// Build the altSignatureAlgorithm extension value.
	altSigAlgExt, err := buildAltSignatureAlgorithmExtension(quantumAlgOID)
	if err != nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("build alt signature algorithm: %w", err)}
	}

	// Create a working copy of the template so we do not mutate the caller's template.
	// We do a shallow copy and rebuild the ExtraExtensions slice.
	workingTemplate := *template
	workingTemplate.ExtraExtensions = make([]pkix.Extension, len(template.ExtraExtensions), len(template.ExtraExtensions)+3)
	copy(workingTemplate.ExtraExtensions, template.ExtraExtensions)

	// Add the quantum alt public key and algorithm extensions
	workingTemplate.ExtraExtensions = append(workingTemplate.ExtraExtensions, altPubKeyExt, altSigAlgExt)

	// Step 1: Create the initial certificate with classical signature.
	// This gives us a properly structured TBS to sign with the quantum key.
	initialDER, err := x509.CreateCertificate(
		rand.Reader,
		&workingTemplate,
		parent,
		classicalKey.Public(),
		classicalKey,
	)
	if err != nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("create initial certificate: %w", err)}
	}

	// Step 2: Extract the TBS from the initial certificate and sign with quantum key.
	tbsRaw, err := extractTBS(initialDER)
	if err != nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("extract TBS: %w", err)}
	}

	// Sign the TBS with the quantum key (ML-DSA operates on the full message, no pre-hashing)
	quantumSig, err := quantumKey.Sign(nil, tbsRaw, crypto.Hash(0))
	if err != nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("quantum signing: %w", err)}
	}

	// Step 3: Build the altSignatureValue extension containing the quantum signature.
	altSigValueExt, err := buildAltSignatureValueExtension(quantumSig)
	if err != nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("build alt signature value: %w", err)}
	}

	// Step 4: Add altSignatureValue and re-sign with the classical key.
	// This produces the final certificate with all three hybrid extensions.
	workingTemplate.ExtraExtensions = append(workingTemplate.ExtraExtensions, altSigValueExt)

	finalDER, err := x509.CreateCertificate(
		rand.Reader,
		&workingTemplate,
		parent,
		classicalKey.Public(),
		classicalKey,
	)
	if err != nil {
		return nil, &HybridCertError{Op: "create", Err: fmt.Errorf("create final certificate: %w", err)}
	}

	return finalDER, nil
}

// VerifyHybridCertificate verifies both the classical and quantum signatures
// on a hybrid certificate.
//
// The classical signature is verified using Go's standard x509 library.
// The quantum signature is extracted from the altSignatureValue extension
// and verified against the TBS (minus the altSignatureValue extension)
// using the issuer's ML-DSA public key.
//
// Parameters:
//   - certDER: The DER-encoded hybrid certificate
//   - classicalIssuer: The issuer's classical certificate (for classical verification)
//   - quantumIssuerPubKey: The issuer's ML-DSA public key (for quantum verification)
//
// Returns nil if both signatures verify, or an error describing the failure.
func VerifyHybridCertificate(
	certDER []byte,
	classicalIssuer *x509.Certificate,
	quantumIssuerPubKey *quantum.MLDSAPublicKey,
) error {

	if len(certDER) == 0 {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("empty certificate data")}
	}
	if classicalIssuer == nil {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("classical issuer is nil")}
	}
	if quantumIssuerPubKey == nil {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("quantum issuer public key is nil")}
	}

	// Step 1: Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("parse certificate: %w", err)}
	}

	// Step 2: Verify the classical signature
	if err := cert.CheckSignatureFrom(classicalIssuer); err != nil {
		return &HybridVerificationError{
			Component: "classical",
			Reason:    err.Error(),
		}
	}

	// Step 3: Extract the alternative signature extensions
	var altSigAlgExt, altSigValueExt *pkix.Extension
	for i := range cert.Extensions {
		ext := &cert.Extensions[i]
		if ext.Id.Equal(oidAltSignatureAlgorithm) {
			altSigAlgExt = ext
		}
		if ext.Id.Equal(oidAltSignatureValue) {
			altSigValueExt = ext
		}
	}

	if altSigAlgExt == nil {
		return &HybridVerificationError{
			Component: "quantum",
			Reason:    "altSignatureAlgorithm extension not found",
		}
	}
	if altSigValueExt == nil {
		return &HybridVerificationError{
			Component: "quantum",
			Reason:    "altSignatureValue extension not found",
		}
	}

	// Step 4: Parse the algorithm from altSignatureAlgorithm
	var algID pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(altSigAlgExt.Value, &algID); err != nil {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("parse alt signature algorithm: %w", err)}
	}

	algorithm, err := oidToQuantumAlgorithm(algID.Algorithm)
	if err != nil {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("resolve quantum algorithm: %w", err)}
	}

	// Step 5: Parse the quantum signature from altSignatureValue
	var sigBitString asn1.BitString
	if _, err := asn1.Unmarshal(altSigValueExt.Value, &sigBitString); err != nil {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("parse alt signature value: %w", err)}
	}

	// Step 6: Extract the TBS that was signed by the quantum key.
	// The quantum key signed the TBS from the initial certificate which
	// included altPublicKeyInfo and altSignatureAlgorithm but NOT altSignatureValue.
	// We need to reconstruct that TBS by removing the altSignatureValue extension
	// and re-encoding.
	tbsForQuantum, err := extractTBSWithoutExtension(certDER, oidAltSignatureValue)
	if err != nil {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("extract TBS for quantum verification: %w", err)}
	}

	// Step 7: Verify the quantum signature
	valid, err := verifyMLDSASignature(algorithm, quantumIssuerPubKey.Key, tbsForQuantum, sigBitString.Bytes)
	if err != nil {
		return &HybridCertError{Op: "verify", Err: fmt.Errorf("quantum signature verification: %w", err)}
	}
	if !valid {
		return &HybridVerificationError{
			Component: "quantum",
			Reason:    "signature verification failed",
		}
	}

	return nil
}

// buildAltPublicKeyInfoExtension builds the subjectAltPublicKeyInfo extension
// containing the quantum public key per ITU-T X.509 (2019) Amendment 1.
//
// SubjectAltPublicKeyInfo ::= SubjectPublicKeyInfo
// SubjectPublicKeyInfo ::= SEQUENCE {
//
//	algorithm AlgorithmIdentifier,
//	subjectPublicKey BIT STRING
//
// }
func buildAltPublicKeyInfoExtension(pubKey *quantum.MLDSAPublicKey, algOID asn1.ObjectIdentifier) (pkix.Extension, error) {
	spki := publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: algOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     pubKey.Key,
			BitLength: len(pubKey.Key) * 8,
		},
	}

	value, err := asn1.Marshal(spki)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal alt public key info: %w", err)
	}

	return pkix.Extension{
		Id:       oidSubjectAltPublicKeyInfo,
		Critical: false,
		Value:    value,
	}, nil
}

// buildAltSignatureAlgorithmExtension builds the altSignatureAlgorithm extension
// per ITU-T X.509 (2019) Amendment 1.
//
// AltSignatureAlgorithm ::= AlgorithmIdentifier
func buildAltSignatureAlgorithmExtension(algOID asn1.ObjectIdentifier) (pkix.Extension, error) {
	algID := pkix.AlgorithmIdentifier{
		Algorithm: algOID,
	}

	value, err := asn1.Marshal(algID)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal alt signature algorithm: %w", err)
	}

	return pkix.Extension{
		Id:       oidAltSignatureAlgorithm,
		Critical: false,
		Value:    value,
	}, nil
}

// buildAltSignatureValueExtension builds the altSignatureValue extension
// per ITU-T X.509 (2019) Amendment 1.
//
// AltSignatureValue ::= BIT STRING
func buildAltSignatureValueExtension(signature []byte) (pkix.Extension, error) {
	bs := asn1.BitString{
		Bytes:     signature,
		BitLength: len(signature) * 8,
	}

	value, err := asn1.Marshal(bs)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal alt signature value: %w", err)
	}

	return pkix.Extension{
		Id:       oidAltSignatureValue,
		Critical: false,
		Value:    value,
	}, nil
}

// extractTBS extracts the raw TBSCertificate bytes from a DER-encoded certificate.
func extractTBS(certDER []byte) ([]byte, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(certDER, &outer); err != nil {
		return nil, fmt.Errorf("unmarshal certificate: %w", err)
	}

	// The certificate is a SEQUENCE of (TBSCertificate, SignatureAlgorithm, SignatureValue)
	// We need to extract just the first element.
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &tbs); err != nil {
		return nil, fmt.Errorf("unmarshal TBS: %w", err)
	}

	return tbs.FullBytes, nil
}

// extractTBSWithoutExtension extracts the TBS from a certificate and
// rebuilds it without the specified extension OID. This is needed for
// quantum signature verification because the quantum key signs the TBS
// before the altSignatureValue extension is added.
func extractTBSWithoutExtension(certDER []byte, excludeOID asn1.ObjectIdentifier) ([]byte, error) {
	// Parse the certificate to get its extensions
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	// Build a new template without the excluded extension
	filteredExtensions := make([]pkix.Extension, 0, len(cert.Extensions))
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(excludeOID) {
			filteredExtensions = append(filteredExtensions, ext)
		}
	}

	// Rebuild the certificate template from the parsed cert,
	// using only the filtered extensions as ExtraExtensions.
	// We create a new template that matches the original minus the excluded extension.
	rebuiltTemplate := &x509.Certificate{
		SerialNumber:          cert.SerialNumber,
		Subject:               cert.Subject,
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		KeyUsage:              cert.KeyUsage,
		BasicConstraintsValid: cert.BasicConstraintsValid,
		IsCA:                  cert.IsCA,
		MaxPathLen:            cert.MaxPathLen,
		MaxPathLenZero:        cert.MaxPathLenZero,
		SignatureAlgorithm:    cert.SignatureAlgorithm,
		DNSNames:              cert.DNSNames,
		EmailAddresses:        cert.EmailAddresses,
		IPAddresses:           cert.IPAddresses,
		URIs:                  cert.URIs,
		ExtKeyUsage:           cert.ExtKeyUsage,
	}

	// Add filtered extensions as ExtraExtensions. We need to separate the
	// "standard" extensions that x509.CreateCertificate handles automatically
	// from the non-standard ones we need to pass as ExtraExtensions.
	for _, ext := range filteredExtensions {
		if !isStandardExtension(ext.Id) {
			rebuiltTemplate.ExtraExtensions = append(rebuiltTemplate.ExtraExtensions, ext)
		}
	}

	// We need a dummy issuer cert to create the certificate. Use the same cert
	// as parent since we only need the TBS.
	// Create a temporary certificate to get the TBS using a dummy signer.
	// Instead of re-signing, we can reconstruct the TBS from the original
	// certificate's raw TBS data. The TBS in the original cert contains the
	// altSignatureValue extension. We need to remove it.
	//
	// Alternative approach: parse the TBS ASN.1 and rebuild extensions.
	return rebuildTBSWithoutExtension(certDER, excludeOID)
}

// rebuildTBSWithoutExtension parses the raw TBS ASN.1 from a certificate
// and rebuilds it with the specified extension removed.
func rebuildTBSWithoutExtension(certDER []byte, excludeOID asn1.ObjectIdentifier) ([]byte, error) {
	// Parse outer certificate SEQUENCE
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(certDER, &outer); err != nil {
		return nil, fmt.Errorf("unmarshal outer certificate: %w", err)
	}

	// Parse the TBS as a raw value
	var tbsRaw asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &tbsRaw); err != nil {
		return nil, fmt.Errorf("unmarshal TBS: %w", err)
	}

	// Parse the TBS contents to find extensions
	// TBSCertificate fields (per RFC 5280):
	// version [0] EXPLICIT, serialNumber, signature, issuer, validity,
	// subject, subjectPublicKeyInfo, extensions [3] EXPLICIT
	rest := tbsRaw.Bytes
	var fields []asn1.RawValue

	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, fmt.Errorf("unmarshal TBS field: %w", err)
		}
		fields = append(fields, field)
	}

	// Find the extensions field (tag 3, context-specific, explicit)
	// It should be the last field in the TBS
	extFieldIdx := -1
	for i, f := range fields {
		if f.Class == asn1.ClassContextSpecific && f.Tag == 3 {
			extFieldIdx = i
			break
		}
	}

	if extFieldIdx < 0 {
		// No extensions field, return original TBS
		return tbsRaw.FullBytes, nil
	}

	// Parse the extensions from the explicit wrapper
	var extensions []asn1.RawValue
	extRest := fields[extFieldIdx].Bytes

	// The explicit tag wraps a SEQUENCE OF Extension
	var extSeq asn1.RawValue
	if _, err := asn1.Unmarshal(extRest, &extSeq); err != nil {
		return nil, fmt.Errorf("unmarshal extensions SEQUENCE: %w", err)
	}

	extContents := extSeq.Bytes
	for len(extContents) > 0 {
		var ext asn1.RawValue
		var err error
		extContents, err = asn1.Unmarshal(extContents, &ext)
		if err != nil {
			return nil, fmt.Errorf("unmarshal extension: %w", err)
		}

		// Parse the extension to check its OID
		var parsedExt struct {
			OID      asn1.ObjectIdentifier
			Critical bool `asn1:"optional,default:false"`
			Value    asn1.RawValue
		}
		if _, parseErr := asn1.Unmarshal(ext.FullBytes, &parsedExt); parseErr != nil {
			// If we cannot parse, keep the extension
			extensions = append(extensions, ext)
			continue
		}

		// Skip the excluded extension
		if parsedExt.OID.Equal(excludeOID) {
			continue
		}

		extensions = append(extensions, ext)
	}

	// Rebuild the extensions SEQUENCE
	var rebuiltExtBytes []byte
	for _, ext := range extensions {
		rebuiltExtBytes = append(rebuiltExtBytes, ext.FullBytes...)
	}

	// Wrap in SEQUENCE
	rebuiltExtSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rebuiltExtBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rebuilt extensions SEQUENCE: %w", err)
	}

	// Rebuild the explicit tag [3] wrapper
	rebuiltExtField := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		IsCompound: true,
		Bytes:      rebuiltExtSeq,
	}
	rebuiltExtFieldBytes, err := asn1.Marshal(rebuiltExtField)
	if err != nil {
		return nil, fmt.Errorf("marshal extensions field: %w", err)
	}

	// Rebuild the TBS with the modified extensions
	var rebuiltTBSBytes []byte
	for i, f := range fields {
		if i == extFieldIdx {
			rebuiltTBSBytes = append(rebuiltTBSBytes, rebuiltExtFieldBytes...)
		} else {
			rebuiltTBSBytes = append(rebuiltTBSBytes, f.FullBytes...)
		}
	}

	// Wrap in SEQUENCE
	rebuiltTBS, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rebuiltTBSBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rebuilt TBS: %w", err)
	}

	return rebuiltTBS, nil
}

// isStandardExtension returns true if the OID is a standard X.509 extension
// that Go's x509.CreateCertificate handles automatically.
func isStandardExtension(oid asn1.ObjectIdentifier) bool {
	standardOIDs := []asn1.ObjectIdentifier{
		{2, 5, 29, 14}, // subjectKeyIdentifier
		{2, 5, 29, 15}, // keyUsage
		{2, 5, 29, 17}, // subjectAltName
		{2, 5, 29, 19}, // basicConstraints
		{2, 5, 29, 31}, // cRLDistributionPoints
		{2, 5, 29, 32}, // certificatePolicies
		{2, 5, 29, 35}, // authorityKeyIdentifier
		{2, 5, 29, 37}, // extKeyUsage
	}

	for _, std := range standardOIDs {
		if oid.Equal(std) {
			return true
		}
	}
	return false
}

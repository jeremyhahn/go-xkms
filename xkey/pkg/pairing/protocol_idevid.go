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

package pairing

// IDevID certificate exchange protocol method names.
// These methods handle the exchange of IDevID certificates between the
// Go side (laptop/desktop) and Android CA for mutual device identity.
//
// Protocol Flow for IDevID Certificate Issuance:
//  1. Phone requests CA bundle via local.getCABundle
//  2. Phone checks if Go side has IDevID via local.getIDevIDCertificate
//  3. If not, Go side generates CSR via local.generateIDevIDCSR
//  4. Phone submits CSR to Android CA via local.requestIDevIDIssuance
//  5. Go side stores issued certificate via local.storeIDevIDCertificate
const (
	// MethodLocalGetCABundle requests the CA bundle from the phone for
	// populating the Go side's trust store with Android CA certificates.
	MethodLocalGetCABundle = "local.getCABundle"

	// MethodLocalGetIDevIDCertificate retrieves the IDevID certificate chain
	// from the Go side (if one exists).
	MethodLocalGetIDevIDCertificate = "local.getIDevIDCertificate"

	// MethodLocalRequestIDevIDIssuance requests the Android CA to issue an
	// IDevID certificate for the Go side based on the provided CSR.
	MethodLocalRequestIDevIDIssuance = "local.requestIDevIDIssuance"

	// MethodLocalGenerateIDevIDCSR generates an IDevID CSR on the Go side
	// for submission to the Android CA.
	MethodLocalGenerateIDevIDCSR = "local.generateIDevIDCSR"

	// MethodLocalStoreIDevIDCertificate stores the issued IDevID certificate
	// and chain on the Go side after issuance by the Android CA.
	MethodLocalStoreIDevIDCertificate = "local.storeIDevIDCertificate"
)

// LocalGetCABundleParams contains parameters for local.getCABundle.
// This method may take no parameters or optional filtering.
type LocalGetCABundleParams struct {
	// IncludeRoot specifies whether to include the root CA certificate.
	IncludeRoot bool `json:"includeRoot,omitempty"`
	// Format specifies the desired format: "pem" or "der". Default is "pem".
	Format string `json:"format,omitempty"`
}

// LocalGetCABundleResult contains the result of local.getCABundle.
type LocalGetCABundleResult struct {
	// BundlePEM contains the CA bundle in PEM format (concatenated certificates).
	BundlePEM []byte `json:"bundlePem,omitempty"`
	// Certificates contains individual certificates in DER format.
	Certificates [][]byte `json:"certificates"`
	// Count is the number of certificates in the bundle.
	Count int `json:"count"`
	// RootSubject is the subject DN of the root CA certificate.
	RootSubject string `json:"rootSubject,omitempty"`
}

// LocalGetIDevIDCertificateParams contains parameters for local.getIDevIDCertificate.
type LocalGetIDevIDCertificateParams struct {
	// Nonce is an optional challenge nonce to include in the response
	// for freshness verification.
	Nonce []byte `json:"nonce,omitempty"`
}

// LocalGetIDevIDCertificateResult contains the result of local.getIDevIDCertificate.
type LocalGetIDevIDCertificateResult struct {
	// HasCertificate indicates whether an IDevID certificate exists.
	HasCertificate bool `json:"hasCertificate"`
	// CertificateChain contains the certificate chain in DER format
	// ordered as [leaf, intermediate..., root].
	CertificateChain [][]byte `json:"certificateChain,omitempty"`
	// Nonce is the echoed challenge nonce (if provided in params).
	Nonce []byte `json:"nonce,omitempty"`
	// CertificateInfo contains parsed certificate metadata.
	CertificateInfo *IDevIDCertificateInfo `json:"certificateInfo,omitempty"`
}

// LocalRequestIDevIDIssuanceParams contains parameters for local.requestIDevIDIssuance.
type LocalRequestIDevIDIssuanceParams struct {
	// CSR is the Certificate Signing Request in DER format.
	// Supports both PKCS#10 and TCG-CSR-IDEVID formats.
	CSR []byte `json:"csr"`
	// CSRFormat specifies the CSR format: "pkcs10" or "tcg-csr-idevid".
	// Default is "pkcs10".
	CSRFormat string `json:"csrFormat,omitempty"`
	// AttestationData contains optional attestation evidence to bind
	// the CSR to a hardware-backed key.
	AttestationData []byte `json:"attestationData,omitempty"`
	// ValidityDays specifies the requested certificate validity in days.
	// The CA may override this value based on policy.
	ValidityDays int `json:"validityDays,omitempty"`
}

// LocalRequestIDevIDIssuanceResult contains the result of local.requestIDevIDIssuance.
type LocalRequestIDevIDIssuanceResult struct {
	// Issued indicates whether the certificate was successfully issued.
	Issued bool `json:"issued"`
	// Certificate is the issued IDevID certificate in DER format.
	Certificate []byte `json:"certificate,omitempty"`
	// CertificateChain contains the full certificate chain in DER format
	// ordered as [leaf, intermediate..., root].
	CertificateChain [][]byte `json:"certificateChain,omitempty"`
	// CertificateInfo contains parsed certificate metadata.
	CertificateInfo *IDevIDCertificateInfo `json:"certificateInfo,omitempty"`
	// ErrorCode contains a machine-readable error code if issuance failed.
	ErrorCode string `json:"errorCode,omitempty"`
	// ErrorMessage contains a human-readable error message if issuance failed.
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// LocalGenerateIDevIDCSRParams contains parameters for local.generateIDevIDCSR.
type LocalGenerateIDevIDCSRParams struct {
	// Backend specifies the xkmsd backend to use for key generation.
	// If empty, uses the default backend.
	Backend string `json:"backend,omitempty"`
	// KeyID specifies an existing key to use. If empty, a new key is generated.
	KeyID string `json:"keyId,omitempty"`
	// Algorithm specifies the key algorithm for new key generation.
	// Supported: "ES256", "ES384", "ES512", "RS2048", "RS3072", "RS4096".
	Algorithm string `json:"algorithm,omitempty"`
	// Subject contains the requested certificate subject fields.
	Subject *IDevIDSubject `json:"subject,omitempty"`
	// CSRFormat specifies the output format: "pkcs10" or "tcg-csr-idevid".
	// Default is "pkcs10".
	CSRFormat string `json:"csrFormat,omitempty"`
}

// LocalGenerateIDevIDCSRResult contains the result of local.generateIDevIDCSR.
type LocalGenerateIDevIDCSRResult struct {
	// CSR is the generated Certificate Signing Request in DER format.
	CSR []byte `json:"csr"`
	// CSRFormat is the format of the CSR: "pkcs10" or "tcg-csr-idevid".
	CSRFormat string `json:"csrFormat"`
	// KeyID is the identifier of the key used for the CSR.
	KeyID string `json:"keyId"`
	// Backend is the xkmsd backend where the key resides.
	Backend string `json:"backend"`
	// Algorithm is the key algorithm.
	Algorithm string `json:"algorithm"`
	// PublicKey is the DER-encoded public key.
	PublicKey []byte `json:"publicKey,omitempty"`
}

// LocalStoreIDevIDCertificateParams contains parameters for local.storeIDevIDCertificate.
type LocalStoreIDevIDCertificateParams struct {
	// Certificate is the IDevID certificate in DER format.
	Certificate []byte `json:"certificate"`
	// Chain contains the certificate chain in DER format (excluding the leaf).
	// Ordered as [intermediate..., root].
	Chain [][]byte `json:"chain,omitempty"`
	// KeyID specifies which key the certificate belongs to.
	KeyID string `json:"keyId"`
	// Backend specifies the xkmsd backend where the key resides.
	Backend string `json:"backend,omitempty"`
}

// LocalStoreIDevIDCertificateResult contains the result of local.storeIDevIDCertificate.
type LocalStoreIDevIDCertificateResult struct {
	// Stored indicates whether the certificate was successfully stored.
	Stored bool `json:"stored"`
	// CertificateInfo contains parsed certificate metadata.
	CertificateInfo *IDevIDCertificateInfo `json:"certificateInfo,omitempty"`
}

// IDevIDCertificateInfo contains metadata about an IDevID certificate.
type IDevIDCertificateInfo struct {
	// SerialNumber is the certificate serial number as a hex string.
	SerialNumber string `json:"serialNumber"`
	// Issuer is the certificate issuer DN.
	Issuer string `json:"issuer"`
	// Subject is the certificate subject DN.
	Subject string `json:"subject"`
	// NotBefore is the certificate validity start time (Unix timestamp).
	NotBefore int64 `json:"notBefore"`
	// NotAfter is the certificate validity end time (Unix timestamp).
	NotAfter int64 `json:"notAfter"`
	// Algorithm is the signature algorithm used.
	Algorithm string `json:"algorithm"`
	// PublicKeyAlgorithm is the subject public key algorithm.
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm"`
	// KeySizeBits is the subject public key size in bits.
	KeySizeBits int `json:"keySizeBits"`
	// Fingerprint is the SHA-256 fingerprint of the certificate (hex-encoded).
	Fingerprint string `json:"fingerprint"`
	// IsCA indicates whether this is a CA certificate.
	IsCA bool `json:"isCa"`
	// KeyUsage describes the certificate key usage.
	KeyUsage []string `json:"keyUsage,omitempty"`
	// ExtKeyUsage describes the extended key usage.
	ExtKeyUsage []string `json:"extKeyUsage,omitempty"`
	// HardwareSerial is the device hardware serial from the certificate
	// subject (if present).
	HardwareSerial string `json:"hardwareSerial,omitempty"`
}

// IDevIDSubject contains subject fields for IDevID CSR generation.
type IDevIDSubject struct {
	// CommonName is the CN field (typically device identifier).
	CommonName string `json:"commonName,omitempty"`
	// Organization is the O field.
	Organization string `json:"organization,omitempty"`
	// OrganizationalUnit is the OU field.
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	// SerialNumber is the device serial number (serialNumber attribute).
	SerialNumber string `json:"serialNumber,omitempty"`
	// Country is the C field.
	Country string `json:"country,omitempty"`
	// Locality is the L field.
	Locality string `json:"locality,omitempty"`
	// Province is the ST field.
	Province string `json:"province,omitempty"`
}

// idevidMethodNames contains all valid IDevID-related method names for validation.
var idevidMethodNames = map[string]bool{
	MethodLocalGetCABundle:            true,
	MethodLocalGetIDevIDCertificate:   true,
	MethodLocalRequestIDevIDIssuance:  true,
	MethodLocalGenerateIDevIDCSR:      true,
	MethodLocalStoreIDevIDCertificate: true,
}

// IsIDevIDMethod returns true if the method name is a valid IDevID method.
func IsIDevIDMethod(method string) bool {
	return idevidMethodNames[method]
}

func init() {
	// Register IDevID methods in the localMethodNames map for unified validation.
	localMethodNames[MethodLocalGetCABundle] = true
	localMethodNames[MethodLocalGetIDevIDCertificate] = true
	localMethodNames[MethodLocalRequestIDevIDIssuance] = true
	localMethodNames[MethodLocalGenerateIDevIDCSR] = true
	localMethodNames[MethodLocalStoreIDevIDCertificate] = true
}

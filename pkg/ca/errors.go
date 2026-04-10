// Package ca provides error definitions for the XKMSCA certificate authority.
//
// All errors are defined as sentinel variables for consistent error checking
// using errors.Is(). Error messages follow Go conventions: lowercase without
// punctuation.
package ca

import "errors"

// Initialization errors indicate issues with CA lifecycle management.
var (
	// ErrNotInitialized indicates the CA has not been initialized.
	ErrNotInitialized = errors.New("ca: not initialized")

	// ErrAlreadyInitialized indicates the CA has already been initialized.
	ErrAlreadyInitialized = errors.New("ca: already initialized")
)

// CSR errors indicate issues with certificate signing requests.
var (
	// ErrInvalidCSR indicates the CSR is malformed or invalid.
	ErrInvalidCSR = errors.New("ca: invalid certificate signing request")

	// ErrCSRGenerationFailed indicates CSR creation failed.
	ErrCSRGenerationFailed = errors.New("ca: csr generation failed")
)

// Certificate errors indicate issues with certificate operations.
var (
	// ErrInvalidCertificate indicates the certificate is malformed or invalid.
	ErrInvalidCertificate = errors.New("ca: invalid certificate")

	// ErrCertificateNotFound indicates the requested certificate does not exist.
	ErrCertificateNotFound = errors.New("ca: certificate not found")

	// ErrCertificateExpired indicates the certificate has expired.
	ErrCertificateExpired = errors.New("ca: certificate expired")

	// ErrCertificateNotYetValid indicates the certificate is not yet valid.
	// The current time is before the certificate's NotBefore time.
	ErrCertificateNotYetValid = errors.New("ca: certificate not yet valid")

	// ErrCertificateAlreadyExists indicates a certificate with the same
	// identifier already exists.
	ErrCertificateAlreadyExists = errors.New("ca: certificate already exists")
)

// Signing errors indicate issues with cryptographic signing operations.
var (
	// ErrSigningFailed indicates the signing operation failed.
	ErrSigningFailed = errors.New("ca: signing failed")

	// ErrInvalidSignature indicates the signature verification failed.
	ErrInvalidSignature = errors.New("ca: invalid signature")
)

// Revocation errors indicate issues with certificate revocation.
var (
	// ErrCertificateRevoked indicates the certificate has been revoked.
	ErrCertificateRevoked = errors.New("ca: certificate revoked")

	// ErrCRLNotFound indicates the certificate revocation list was not found.
	ErrCRLNotFound = errors.New("ca: crl not found")

	// ErrCRLGenerationFailed indicates CRL creation failed.
	ErrCRLGenerationFailed = errors.New("ca: crl generation failed")

	// ErrAlreadyRevoked indicates the certificate is already revoked.
	ErrAlreadyRevoked = errors.New("ca: certificate already revoked")
)

// Chain errors indicate issues with certificate chain validation.
var (
	// ErrInvalidCertificateChain indicates the certificate chain is invalid.
	ErrInvalidCertificateChain = errors.New("ca: invalid certificate chain")

	// ErrRootNotFound indicates the root certificate was not found.
	ErrRootNotFound = errors.New("ca: root certificate not found")

	// ErrIntermediateNotFound indicates an intermediate certificate was not found.
	ErrIntermediateNotFound = errors.New("ca: intermediate certificate not found")
)

// Config errors indicate issues with CA configuration.
var (
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("ca: invalid configuration")

	// ErrInvalidKeyAlgorithm indicates an unsupported key algorithm was specified.
	ErrInvalidKeyAlgorithm = errors.New("ca: invalid key algorithm")

	// ErrInvalidStoreType indicates an unsupported store type was specified.
	ErrInvalidStoreType = errors.New("ca: invalid store type")

	// ErrNoKeysConfigured indicates no keys are configured for an identity.
	ErrNoKeysConfigured = errors.New("ca: no keys configured for identity")
)

// Storage errors indicate issues with key and certificate storage.
var (
	// ErrKeyStoreRequired indicates a key store must be configured.
	ErrKeyStoreRequired = errors.New("ca: key store required")

	// ErrCertStoreRequired indicates a certificate store must be configured.
	ErrCertStoreRequired = errors.New("ca: certificate store required")

	// ErrStorageError indicates a storage operation failed.
	ErrStorageError = errors.New("ca: storage operation failed")
)

// Serial number errors indicate issues with certificate serial generation.
var (
	// ErrSerialGenerationFailed indicates serial number generation failed.
	ErrSerialGenerationFailed = errors.New("ca: serial number generation failed")

	// ErrSerialCollision indicates a serial number collision was detected.
	ErrSerialCollision = errors.New("ca: serial number collision")
)

// Profile errors indicate issues with certificate profiles.
var (
	// ErrProfileNotFound indicates the requested profile does not exist.
	ErrProfileNotFound = errors.New("ca: profile not found")

	// ErrInvalidProfile indicates the profile configuration is invalid.
	ErrInvalidProfile = errors.New("ca: invalid profile")
)

// TLS errors indicate issues with TLS configuration.
var (
	// ErrTLSConfigFailed indicates TLS configuration creation failed.
	ErrTLSConfigFailed = errors.New("ca: tls configuration failed")

	// ErrInvalidTLSOptions indicates invalid TLS options were specified.
	ErrInvalidTLSOptions = errors.New("ca: invalid tls options")

	// ErrKeyNotFound indicates the private key was not found.
	ErrKeyNotFound = errors.New("ca: private key not found")

	// ErrKeyCertMismatch indicates the private key does not match the certificate.
	ErrKeyCertMismatch = errors.New("ca: private key does not match certificate")

	// ErrInvalidPEM indicates the PEM data is malformed or invalid.
	ErrInvalidPEM = errors.New("ca: invalid pem data")

	// ErrPeerVerificationFailed indicates peer certificate verification failed.
	ErrPeerVerificationFailed = errors.New("ca: peer certificate verification failed")
)

// Validation errors indicate issues with request validation.
var (
	// ErrSubjectCommonNameRequired indicates the subject common name is missing.
	ErrSubjectCommonNameRequired = errors.New("ca: subject common name required")

	// ErrInvalidValidityPeriod indicates the validity period is invalid.
	ErrInvalidValidityPeriod = errors.New("ca: invalid validity period")

	// ErrInvalidPathLength indicates the path length constraint is invalid.
	ErrInvalidPathLength = errors.New("ca: invalid path length")
)

// TCG enrollment errors indicate issues with TCG Trusted Computing operations.
var (
	// ErrTPMNotConfigured indicates SetTPM has not been called before enrollment.
	ErrTPMNotConfigured = errors.New("ca: tpm not configured for enrollment")

	// ErrTCGCSRVerificationFailed indicates the TCG-CSR-IDEVID verification failed.
	ErrTCGCSRVerificationFailed = errors.New("ca: tcg-csr-idevid verification failed")

	// ErrTCGMakeCredentialFailed indicates MakeCredentialWithExternalEK failed.
	ErrTCGMakeCredentialFailed = errors.New("ca: make credential failed")

	// ErrTCGMissingEKCert indicates the EK certificate is missing from the CSR.
	ErrTCGMissingEKCert = errors.New("ca: missing ek certificate in csr")

	// ErrTCGInvalidEKCert indicates the EK certificate could not be parsed.
	ErrTCGInvalidEKCert = errors.New("ca: invalid ek certificate")

	// ErrTCGExtensionEncoding indicates a TCG extension could not be ASN.1 encoded.
	ErrTCGExtensionEncoding = errors.New("ca: tcg extension encoding failed")

	// ErrTCGExtensionParsing indicates a TCG extension could not be ASN.1 decoded.
	ErrTCGExtensionParsing = errors.New("ca: tcg extension parsing failed")

	// ErrTCGTenantIDEmpty indicates an empty tenant ID was provided.
	ErrTCGTenantIDEmpty = errors.New("ca: tenant id must not be empty")

	// ErrTCGInvalidPublicKey indicates the public key is nil or unsupported.
	ErrTCGInvalidPublicKey = errors.New("ca: invalid public key for tcg certificate")

	// ErrTCGInvalidIssuer indicates a signer was provided without an issuer cert.
	ErrTCGInvalidIssuer = errors.New("ca: signer provided without issuer certificate")

	// ErrTCGCertIssuanceFailed indicates TCG certificate creation failed.
	ErrTCGCertIssuanceFailed = errors.New("ca: tcg certificate issuance failed")

	// ErrTCGIAKKeyExtraction indicates the IAK public key could not be extracted.
	ErrTCGIAKKeyExtraction = errors.New("ca: failed to extract iak public key")

	// ErrTCGCSRUnmarshalFailed indicates the packed CSR could not be unmarshaled.
	ErrTCGCSRUnmarshalFailed = errors.New("ca: failed to unmarshal tcg-csr-idevid")
)

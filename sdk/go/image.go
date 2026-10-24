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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/image"

// Container image signing re-exported from pkg/image so SDK consumers sign
// and verify images without importing go-xkms/pkg/image directly. An image is
// signed with a KMS crypto.Signer certified under TrustedCA's code-signing
// profile; the DSSE attestation is pushed as an OCI 1.1 referrer and into
// cosign's "sha256-<hex>.att" tag, optionally with an RFC 3161 timestamp.
// ImageVerifier.VerifyImage checks an image's attestations against a root
// store's image-signer roots.

// Image signing and verification types re-exported from pkg/image.
type (
	// ImageReference is a parsed image reference: registry, repository, tag
	// and digest.
	ImageReference = image.Reference

	// ImageSigner signs images and pushes their attestations.
	ImageSigner = image.Signer

	// ImageSignerConfig configures an ImageSigner: the KMS signer, its
	// code-signing certificate and chain, the registry and an optional
	// timestamper.
	ImageSignerConfig = image.SignerConfig

	// ImageSignOptions selects the in-toto predicate an ImageSigner signs.
	ImageSignOptions = image.SignOptions

	// ImageSignResult describes a signed image and where its attestation
	// was stored.
	ImageSignResult = image.SignResult

	// ImageCertificateIssuer certifies a signing key's CSR. TrustedCA
	// implements it.
	ImageCertificateIssuer = image.CertificateIssuer

	// ImageVerifier verifies image attestations against trusted roots.
	ImageVerifier = image.Verifier

	// ImageVerificationResult describes the attestation that verified.
	ImageVerificationResult = image.VerificationResult

	// ImageStatement is an in-toto statement naming the signed image.
	ImageStatement = image.Statement

	// ImageStatementSubject is one subject of an ImageStatement.
	ImageStatementSubject = image.Subject

	// ImageAttestation is a DSSE attestation as stored in a registry.
	ImageAttestation = image.Attestation

	// ImageRegistryClient pushes and reads image attestations.
	ImageRegistryClient = image.RegistryClient

	// ImageRegistryOptions configures an ImageRegistryClient.
	ImageRegistryOptions = image.RegistryOptions

	// ImageRegistryAuth holds registry credentials.
	ImageRegistryAuth = image.RegistryAuth

	// ImageDescriptor is an OCI content descriptor.
	ImageDescriptor = image.Descriptor

	// ImagePushResult describes where a registry stored an attestation.
	ImagePushResult = image.PushResult

	// ImageTimestamper obtains RFC 3161 timestamps over attestation
	// envelopes.
	ImageTimestamper = image.Timestamper

	// ImageTimestampInfo is a verified RFC 3161 timestamp.
	ImageTimestampInfo = image.TimestampInfo

	// RFC3161Client is an ImageTimestamper backed by an RFC 3161 TSA.
	RFC3161Client = image.RFC3161Client
)

// ImageRootStore supplies the trusted image-signer roots for a purpose.
type ImageRootStore[P ~string] = image.RootStore[P]

// ImageVerifierConfig configures an ImageVerifier: the registry, the root
// store and purpose, an optional predicate type and timestamp policy.
type ImageVerifierConfig[P ~string] = image.VerifierConfig[P]

// ImageSigningKeyResolver resolves the key that signs a repository's images
// for an ImageVerifier, such as an AttestationAppraiser's TenantSigningKeys.
type ImageSigningKeyResolver = image.SigningKeyResolver

// PredicateTypeCosign is the predicate type of cosign's default attestation,
// the one an ImageSigner signs when ImageSignOptions names none.
const PredicateTypeCosign = image.PredicateTypeCosign

// Image signing constructors and helpers re-exported from pkg/image.
var (
	// ParseImageReference parses an image reference such as
	// "registry.example.com/team/app:v1".
	ParseImageReference = image.ParseReference

	// NewImageSigner returns an ImageSigner for an ImageSignerConfig.
	NewImageSigner = image.NewSigner

	// RequestCodeSigningCertificate has a TrustedCA certify a KMS key under
	// its code-signing profile. Only the CSR leaves the KMS.
	RequestCodeSigningCertificate = image.RequestCodeSigningCertificate

	// NewImageRegistryClient returns an ImageRegistryClient.
	NewImageRegistryClient = image.NewRegistryClient

	// NewRFC3161Client returns a client of the TSA at a URL.
	NewRFC3161Client = image.NewRFC3161Client

	// VerifyRFC3161Timestamp verifies a DER TimeStampResp over data against
	// TSA roots.
	VerifyRFC3161Timestamp = image.VerifyTimestamp
)

// NewImageVerifier returns an ImageVerifier for an ImageVerifierConfig. It is
// a function rather than a variable because pkg/image's constructor is
// generic over the root store's purpose type.
func NewImageVerifier[P ~string](cfg *ImageVerifierConfig[P]) (*ImageVerifier, error) {
	return image.NewVerifier(cfg)
}

// Image signing errors re-exported from pkg/image.
var (
	ErrImageInvalidReference          = image.ErrInvalidReference
	ErrImageInvalidDigest             = image.ErrInvalidDigest
	ErrImageDigestRequired            = image.ErrDigestRequired
	ErrImageSignerRequired            = image.ErrSignerRequired
	ErrImageCertificateRequired       = image.ErrCertificateRequired
	ErrImageRegistryRequired          = image.ErrRegistryRequired
	ErrImageIssuerRequired            = image.ErrIssuerRequired
	ErrImageCommonNameRequired        = image.ErrCommonNameRequired
	ErrImageKeyMismatch               = image.ErrKeyMismatch
	ErrImageNotCodeSigning            = image.ErrNotCodeSigning
	ErrImageCertificateNotValid       = image.ErrCertificateNotValid
	ErrImageUnsupportedKey            = image.ErrUnsupportedKey
	ErrImageCSRFailed                 = image.ErrCSRFailed
	ErrImageCertificateRequestFailed  = image.ErrCertificateRequestFailed
	ErrImageSigningFailed             = image.ErrSigningFailed
	ErrImageEncodingFailed            = image.ErrEncodingFailed
	ErrImageRegistryRequest           = image.ErrRegistryRequest
	ErrImageRegistryUnavailable       = image.ErrRegistryUnavailable
	ErrImageRegistryAuth              = image.ErrRegistryAuth
	ErrImageRegistryCredentials       = image.ErrRegistryCredentials
	ErrImageManifestNotFound          = image.ErrManifestNotFound
	ErrImageInvalidManifest           = image.ErrInvalidManifest
	ErrImageDigestMismatch            = image.ErrDigestMismatch
	ErrImageResponseTooLarge          = image.ErrResponseTooLarge
	ErrImageResponseRead              = image.ErrResponseRead
	ErrImageInvalidUploadLocation     = image.ErrInvalidUploadLocation
	ErrImageRedirectRefused           = image.ErrRedirectRefused
	ErrImageInvalidRegistryOptions    = image.ErrInvalidRegistryOptions
	ErrImageSubjectRequired           = image.ErrSubjectRequired
	ErrImageRootStoreRequired         = image.ErrRootStoreRequired
	ErrImageRootPurposeRequired       = image.ErrRootPurposeRequired
	ErrImageNoTrustedRoots            = image.ErrNoTrustedRoots
	ErrImageNoAttestation             = image.ErrNoAttestation
	ErrImageNoValidAttestation        = image.ErrNoValidAttestation
	ErrImageInvalidAttestation        = image.ErrInvalidAttestation
	ErrImageInvalidEnvelope           = image.ErrInvalidEnvelope
	ErrImageInvalidStatement          = image.ErrInvalidStatement
	ErrImageSubjectMismatch           = image.ErrSubjectMismatch
	ErrImagePredicateTypeMismatch     = image.ErrPredicateTypeMismatch
	ErrImageSignatureInvalid          = image.ErrSignatureInvalid
	ErrImageUntrustedSigner           = image.ErrUntrustedSigner
	ErrImageSigningKeyMismatch        = image.ErrSigningKeyMismatch
	ErrImageTimestampURLInvalid       = image.ErrTimestampURLInvalid
	ErrImageTimestampDataRequired     = image.ErrTimestampDataRequired
	ErrImageTimestampFailed           = image.ErrTimestampFailed
	ErrImageTimestampRejected         = image.ErrTimestampRejected
	ErrImageInvalidTimestamp          = image.ErrInvalidTimestamp
	ErrImageTimestampMismatch         = image.ErrTimestampMismatch
	ErrImageTimestampSignatureInvalid = image.ErrTimestampSignatureInvalid
	ErrImageTimestampUntrusted        = image.ErrTimestampUntrusted
	ErrImageTimestampExtKeyUsage      = image.ErrTimestampExtKeyUsage
	ErrImageTimestampRootsRequired    = image.ErrTimestampRootsRequired
	ErrImageTimestampRequired         = image.ErrTimestampRequired
	ErrImageUnsupportedAlgorithm      = image.ErrUnsupportedAlgorithm
)

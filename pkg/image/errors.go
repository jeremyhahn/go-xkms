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

package image

import "errors"

// Reference errors.
var (
	// ErrInvalidReference indicates an image reference that does not parse.
	ErrInvalidReference = errors.New("image: invalid image reference")

	// ErrInvalidDigest indicates a digest that is not sha256:<64 hex> or
	// sha512:<128 hex>.
	ErrInvalidDigest = errors.New("image: invalid digest")

	// ErrDigestRequired indicates an operation that needs a digest reference
	// was given a tag reference.
	ErrDigestRequired = errors.New("image: reference has no digest")
)

// Signer errors.
var (
	// ErrSignerRequired indicates a missing KMS crypto.Signer.
	ErrSignerRequired = errors.New("image: crypto.Signer is required")

	// ErrCertificateRequired indicates a missing code-signing certificate.
	ErrCertificateRequired = errors.New("image: code-signing certificate is required")

	// ErrRegistryRequired indicates a missing registry client.
	ErrRegistryRequired = errors.New("image: registry client is required")

	// ErrIssuerRequired indicates a missing certificate issuer.
	ErrIssuerRequired = errors.New("image: certificate issuer is required")

	// ErrCommonNameRequired indicates an empty certificate common name.
	ErrCommonNameRequired = errors.New("image: common name is required")

	// ErrKeyMismatch indicates a certificate whose public key is not the
	// signer's.
	ErrKeyMismatch = errors.New("image: certificate public key does not match the signer")

	// ErrNotCodeSigning indicates a certificate without the code-signing
	// extended key usage or the digitalSignature key usage.
	ErrNotCodeSigning = errors.New("image: certificate is not a code-signing certificate")

	// ErrCertificateNotValid indicates a certificate outside its validity
	// period.
	ErrCertificateNotValid = errors.New("image: certificate is not valid at this time")

	// ErrUnsupportedKey indicates a key that is not RSA, ECDSA or Ed25519.
	ErrUnsupportedKey = errors.New("image: unsupported key type")

	// ErrCSRFailed indicates the code-signing CSR could not be created.
	ErrCSRFailed = errors.New("image: creating the certificate request failed")

	// ErrCertificateRequestFailed indicates the issuer refused the CSR.
	ErrCertificateRequestFailed = errors.New("image: certificate request failed")

	// ErrSigningFailed indicates the signer could not sign the envelope.
	ErrSigningFailed = errors.New("image: signing failed")

	// ErrEncodingFailed indicates a statement, envelope or manifest could
	// not be encoded.
	ErrEncodingFailed = errors.New("image: encoding failed")
)

// Registry errors.
var (
	// ErrRegistryRequest indicates a registry request that could not be
	// sent or that the registry answered with an unexpected status.
	ErrRegistryRequest = errors.New("image: registry request failed")

	// ErrRegistryUnavailable indicates a registry 5xx answer, retried before
	// it is returned.
	ErrRegistryUnavailable = errors.New("image: registry unavailable")

	// ErrRegistryAuth indicates a registry Bearer challenge that is
	// malformed, or whose auth realm refused to issue a token.
	ErrRegistryAuth = errors.New("image: registry token request failed")

	// ErrRegistryCredentials indicates a registry password that could not
	// be opened to sign a request.
	ErrRegistryCredentials = errors.New("image: registry credentials unavailable")

	// ErrManifestNotFound indicates the registry holds no manifest for the
	// reference.
	ErrManifestNotFound = errors.New("image: manifest not found")

	// ErrInvalidManifest indicates a manifest or referrers index that does
	// not decode.
	ErrInvalidManifest = errors.New("image: invalid manifest")

	// ErrDigestMismatch indicates content whose digest is not the one it
	// was addressed by.
	ErrDigestMismatch = errors.New("image: content digest mismatch")

	// ErrResponseTooLarge indicates a response body above the read limit.
	ErrResponseTooLarge = errors.New("image: response too large")

	// ErrResponseRead indicates a response body that could not be read or
	// closed.
	ErrResponseRead = errors.New("image: reading response failed")

	// ErrInvalidUploadLocation indicates a blob upload Location header that
	// does not parse.
	ErrInvalidUploadLocation = errors.New("image: invalid blob upload location")

	// ErrRedirectRefused indicates a registry or token-realm redirect that is
	// not followed: to a destination other than HTTPS, or past the redirect
	// limit.
	ErrRedirectRefused = errors.New("image: registry redirect refused")

	// ErrInvalidRegistryOptions indicates negative registry client timeouts,
	// retries or delays.
	ErrInvalidRegistryOptions = errors.New("image: invalid registry options")

	// ErrSubjectRequired indicates an attestation push without the image's
	// descriptor.
	ErrSubjectRequired = errors.New("image: subject descriptor is required")
)

// Verification errors.
var (
	// ErrRootStoreRequired indicates a verifier without a trust-roots store.
	ErrRootStoreRequired = errors.New("image: trust-roots store is required")

	// ErrRootPurposeRequired indicates a verifier without a root purpose.
	ErrRootPurposeRequired = errors.New("image: trust-roots purpose is required")

	// ErrNoTrustedRoots indicates the trust-roots store holds no root for
	// the verifier's purpose.
	ErrNoTrustedRoots = errors.New("image: no trusted image-signer roots")

	// ErrNoAttestation indicates the registry holds no attestation for the
	// image.
	ErrNoAttestation = errors.New("image: no attestation found")

	// ErrNoValidAttestation indicates no attestation of the image verified.
	ErrNoValidAttestation = errors.New("image: no attestation verified")

	// ErrInvalidAttestation indicates an attestation layer without a
	// parseable certificate.
	ErrInvalidAttestation = errors.New("image: invalid attestation")

	// ErrInvalidEnvelope indicates a DSSE envelope that does not decode or
	// carries no signature.
	ErrInvalidEnvelope = errors.New("image: invalid DSSE envelope")

	// ErrInvalidStatement indicates a payload that is not an in-toto
	// statement.
	ErrInvalidStatement = errors.New("image: invalid in-toto statement")

	// ErrSubjectMismatch indicates a statement whose subjects do not name
	// the image digest.
	ErrSubjectMismatch = errors.New("image: statement subject does not match the image digest")

	// ErrPredicateTypeMismatch indicates a statement of another predicate
	// type than the verifier requires.
	ErrPredicateTypeMismatch = errors.New("image: predicate type mismatch")

	// ErrSignatureInvalid indicates no envelope signature verifies under the
	// signing certificate's key.
	ErrSignatureInvalid = errors.New("image: envelope signature does not verify")

	// ErrUntrustedSigner indicates a signing certificate that does not chain
	// to a trusted image-signer root for code signing.
	ErrUntrustedSigner = errors.New("image: signing certificate is not trusted")

	// ErrSigningKeyMismatch indicates an attestation signed by a key other
	// than the one that signs the image's repository.
	ErrSigningKeyMismatch = errors.New("image: attestation is not signed by the repository's signing key")
)

// Timestamp errors.
var (
	// ErrTimestampURLInvalid indicates a TSA URL that is not http or https.
	ErrTimestampURLInvalid = errors.New("image: invalid timestamp authority URL")

	// ErrTimestampDataRequired indicates a timestamp request over no data.
	ErrTimestampDataRequired = errors.New("image: data to timestamp is required")

	// ErrTimestampFailed indicates the TSA could not be reached or answered
	// with an HTTP error.
	ErrTimestampFailed = errors.New("image: timestamp request failed")

	// ErrTimestampRejected indicates a TSA status other than granted.
	ErrTimestampRejected = errors.New("image: timestamp authority rejected the request")

	// ErrInvalidTimestamp indicates a TimeStampResp that does not decode as
	// RFC 3161 and RFC 5652.
	ErrInvalidTimestamp = errors.New("image: invalid timestamp response")

	// ErrTimestampMismatch indicates a timestamp whose imprint or nonce does
	// not match the request.
	ErrTimestampMismatch = errors.New("image: timestamp does not cover the data")

	// ErrTimestampSignatureInvalid indicates a timestamp token whose
	// signature does not verify.
	ErrTimestampSignatureInvalid = errors.New("image: timestamp signature does not verify")

	// ErrTimestampUntrusted indicates a TSA certificate that does not chain
	// to a trusted timestamping root.
	ErrTimestampUntrusted = errors.New("image: timestamp authority is not trusted")

	// ErrTimestampExtKeyUsage indicates a TSA certificate whose extended key
	// usage is not the one RFC 3161 section 2.3 requires: exactly
	// id-kp-timeStamping, in an extension marked critical.
	ErrTimestampExtKeyUsage = errors.New("image: timestamp authority certificate must carry only a critical id-kp-timeStamping extended key usage")

	// ErrTimestampRootsRequired indicates timestamp verification without
	// timestamping roots.
	ErrTimestampRootsRequired = errors.New("image: timestamp roots are required")

	// ErrTimestampRequired indicates an attestation without the timestamp
	// the verifier requires.
	ErrTimestampRequired = errors.New("image: attestation carries no timestamp")

	// ErrUnsupportedAlgorithm indicates a digest or signature algorithm
	// outside the supported set.
	ErrUnsupportedAlgorithm = errors.New("image: unsupported algorithm")
)

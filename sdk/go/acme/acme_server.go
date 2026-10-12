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

package trustedca

// This file re-exports ACME server-side types from pkg/acme/* for SDK consumers
// that embed or configure the ACME server (e.g., go-trusted-platform).

import (
	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	dns01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/dns-01"
	endorse01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/endorse-01"
	enroll01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/enroll-01"
	http01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/http-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	acmeclient "github.com/jeremyhahn/go-xkms/pkg/acme/client"
	acmecommon "github.com/jeremyhahn/go-xkms/pkg/acme/common"
	acmeserver "github.com/jeremyhahn/go-xkms/pkg/acme/server"
	acmehandler "github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	acmestorage "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
	acmeobjstore "github.com/jeremyhahn/go-xkms/pkg/acme/storage/objstore"
)

// =============================================================================
// ACME Common Types
// =============================================================================

// ACMECertificateAuthority is the minimal CA interface required by challenge verifiers.
type ACMECertificateAuthority = acmecommon.CertificateAuthority

// ACMEChallengeVerifierFunc defines the function signature for challenge verification.
type ACMEChallengeVerifierFunc = acmecommon.ChallengeVerifierFunc

// ACMEAttestingVerifier verifies an attestation challenge (enroll-01,
// endorse-01, device-attest-01) and reports the identity the device attested.
// It sits beside ACMEChallengeVerifierFunc, which is unchanged: the ACME server
// requires an ACMEAttestingVerifier for every attestation challenge type and
// refuses the challenge when only a plain verifier function is registered.
type ACMEAttestingVerifier = acmecommon.AttestingVerifier

// ACMEAttestingVerifierFunc adapts a function to an ACMEAttestingVerifier.
type ACMEAttestingVerifierFunc = acmecommon.AttestingVerifierFunc

// ACMEAttestationChallenge is what the ACME server hands an
// ACMEAttestingVerifier: the authorization and the challenge exchange to run.
type ACMEAttestationChallenge = acmecommon.AttestationChallenge

// ACMEAttestedIdentity is what an ACMEAttestingVerifier reports on success:
// the device identity it attested, and the verified evidence finalization
// binds the certificate request's key to.
type ACMEAttestedIdentity = acmecommon.AttestedIdentity

// ACMEDirectory provides the ACME server directory endpoints per RFC 8555.
type ACMEDirectory = acmecommon.Directory

// ACMEMeta provides additional ACME server metadata.
type ACMEMeta = acmecommon.Meta

// =============================================================================
// ACME Server Handler Types
// =============================================================================

// ACMERestServicer defines the interface for ACME REST service handlers.
type ACMERestServicer = acmehandler.RestServicer

// ACMERestService is the concrete ACME REST service implementation.
type ACMERestService = acmehandler.RestService

// ACMERestServiceParams contains configuration parameters for the ACME REST service.
type ACMERestServiceParams = acmehandler.Params

// ACMENonceGeneratorFunc is a function type for generating nonces.
type ACMENonceGeneratorFunc = acmehandler.NonceGeneratorFunc

// ACMECAAValidatorInterface defines the interface for CAA validation.
type ACMECAAValidatorInterface = acmehandler.CAAValidatorInterface

// ACMECAAValidator is the RFC 8659 CAA validator order finalize consults
// before signing. Construct one with NewACMECAAValidator and set it on
// ACMERestServiceParams.CAAValidator.
type ACMECAAValidator = acmeserver.CAAValidator

// ACMECAAValidatorParams contains configuration for creating a CAA validator.
type ACMECAAValidatorParams = acmeserver.CAAValidatorParams

// ACMEErrCAAValidationFailed is returned when CAA records prevent issuance.
type ACMEErrCAAValidationFailed = acmeserver.ErrCAAValidationFailed

// ACMEErrCAADNSError is returned when the CAA RRset could not be determined.
type ACMEErrCAADNSError = acmeserver.ErrCAADNSError

// ACMENewAccountRequest represents the structure of a new ACME account registration request.
type ACMENewAccountRequest = acmehandler.NewAccountRequest

// ACMEKeyChangeRequest represents the structure of an ACME key change request.
type ACMEKeyChangeRequest = acmehandler.KeyChangeRequest

// =============================================================================
// ACME Server Hook Types
// =============================================================================

// ACMEOrderFinalizeHook is a function called after successful order finalization.
type ACMEOrderFinalizeHook = acmehandler.OrderFinalizeHook

// ACMEOrderFinalizeHookContext contains contextual information for finalization hooks.
type ACMEOrderFinalizeHookContext = acmehandler.OrderFinalizeHookContext

// ACMEOrderFinalizeHookRegistry manages registered order finalization hooks.
type ACMEOrderFinalizeHookRegistry = acmehandler.OrderFinalizeHookRegistry

// ACMETCGEnrollmentData contains TPM/TCG-specific enrollment information.
type ACMETCGEnrollmentData = acmehandler.TCGEnrollmentData

// ACMEPreIssuanceHook is a function that executes before certificate signing.
type ACMEPreIssuanceHook = acmehandler.PreIssuanceHook

// ACMEPreIssuanceHookContext contains contextual information for pre-issuance hooks.
type ACMEPreIssuanceHookContext = acmehandler.PreIssuanceHookContext

// ACMEPreIssuanceHookRegistry manages registered pre-issuance hooks.
type ACMEPreIssuanceHookRegistry = acmehandler.PreIssuanceHookRegistry

// ACMEComplianceData contains a signed compliance report from the device.
type ACMEComplianceData = acmehandler.ComplianceData

// ACMEComplianceConfig defines compliance requirements for certificate issuance.
type ACMEComplianceConfig = acmehandler.ComplianceConfig

// ACMEGlobalComplianceConfig is the server-wide default compliance configuration.
type ACMEGlobalComplianceConfig = acmehandler.GlobalComplianceConfig

// ACMEOrderPreSignHook fires immediately before the CA signs the certificate and
// returns additional X.509 extensions to embed in the issued certificate.
type ACMEOrderPreSignHook = acmehandler.OrderPreSignHook

// ACMEOrderPreSignHookContext contains contextual information available to pre-sign
// extension hooks. CSR is nil when IsTCGCSR is true.
type ACMEOrderPreSignHookContext = acmehandler.OrderPreSignHookContext

// ACMEOrderPreSignHookRegistry manages registered pre-sign extension hooks.
type ACMEOrderPreSignHookRegistry = acmehandler.OrderPreSignHookRegistry

// ACMEErrPreSignHookFailed is returned when an OrderPreSignHook aborts finalization.
type ACMEErrPreSignHookFailed = acmehandler.ErrPreSignHookFailed

// ACMEErrURISANNotIA5 is returned when a pre-sign hook URI cannot be encoded
// as an IA5String SubjectAltName GeneralName.
type ACMEErrURISANNotIA5 = acmehandler.ErrURISANNotIA5

// NewACMEPermanentIdentifierURISANHook returns a pre-sign hook that embeds a
// URI SubjectAltName derived from the ACME order's permanent-identifier in
// enroll-01 (TCG-CSR-IDEVID) certificates. The caller-supplied uriFor maps a
// permanent-identifier to the URI to stamp (e.g. a SPIFFE node URI for
// attested Raft cluster enrollment) and returns "" to leave the certificate
// unchanged.
var NewACMEPermanentIdentifierURISANHook = acmehandler.NewPermanentIdentifierURISANHook

// ACMEDeviceProfile is the expected state of a device, returned by the lookup
// function of a device-profile pre-issuance hook.
type ACMEDeviceProfile = acmehandler.DeviceProfile

// ACMEDeviceProfileError is returned by a device-profile hook when the profile
// lookup fails; it unwraps to the lookup function's error.
type ACMEDeviceProfileError = acmehandler.DeviceProfileError

// NewACMEDeviceProfileHook returns a pre-issuance hook that validates a
// TCG-CSR enrollment against the profile its lookup function returns for the
// device's product serial and model. A nil profile admits the device.
var NewACMEDeviceProfileHook = acmehandler.NewDeviceProfileHook

// =============================================================================
// ACME Storage Types
// =============================================================================

// ACMEStorageFactory creates DAO instances for ACME persistence.
type ACMEStorageFactory = acmestorage.Factory

// ACMETenantAwareFactory creates tenant-scoped DAO instances.
type ACMETenantAwareFactory = acmestorage.TenantAwareFactory

// =============================================================================
// ACME Client Types
// =============================================================================

// ACMEClientConfig holds ACME client connection configuration.
type ACMEClientConfig = acmeclient.Config

// ACMEClient is the ACME protocol client.
type ACMEClient = acmeclient.Client

// ACMEClientParams contains parameters for creating an ACME client.
type ACMEClientParams = acmeclient.Params

// ACMEConfig holds the top-level ACME YAML configuration.
type ACMEConfig = acmeclient.ACMEConfig

// ACMECertificateRequest describes a certificate request for the ACME client.
type ACMECertificateRequest = acmeclient.CertificateRequest

// ACMECrossSignConfig holds configuration for cross-signing via ACME.
type ACMECrossSignConfig = acmeclient.CrossSignConfig

// ACMEEnrollmentConfig holds configuration for TPM enrollment via ACME.
type ACMEEnrollmentConfig = acmeclient.EnrollmentConfig

// ACMEEnrollmentResult is the result of a device enrollment via
// ACMEClient.EnrollDevice: the issued IAK and IDevID certificate chain.
type ACMEEnrollmentResult = acmeclient.EnrollmentResult

// ACMERenewalInfo contains renewal information from ARI.
type ACMERenewalInfo = acmeclient.RenewalInfo

// ACMETPMModule defines the TPM interface used by the ACME client for enrollment.
type ACMETPMModule = acmeclient.TPMModule

// ACMEAttestedKey is a device-attest-01 certificate key and the challenge
// response that attests it, what ACMETPMModule.CreateAttestedKey returns.
type ACMEAttestedKey = acmeclient.AttestedKey

// ACMEXKMSTPMAdapter adapts a go-xkms TPM module for use with the ACME client.
type ACMEXKMSTPMAdapter = acmeclient.XKMSTPMAdapter

// ACMEChainOption describes options for certificate chain selection.
type ACMEChainOption = acmeclient.ChainOption

// ACMEChainInfo describes a certificate chain returned by the ACME server.
type ACMEChainInfo = acmeclient.ChainInfo

// =============================================================================
// Constructor Functions
// =============================================================================

// NewACMERestService creates a new ACME REST service from the given parameters.
var NewACMERestService = acmehandler.NewRestService

// NewACMECAAValidator creates the RFC 8659 CAA validator order finalize
// consults before signing. This is the single construction path for a CAA
// validator: cmd/xkmsd's ACME composition and the pkg/acme/client TrustedCA
// composition both call it, and any SDK consumer composing its own
// ACMERestServiceParams should too rather than implementing ACMECAAValidatorInterface
// itself.
var NewACMECAAValidator = acmeserver.NewCAAValidator

// NewACMEOrderFinalizeHookRegistry creates a new order finalization hook registry.
var NewACMEOrderFinalizeHookRegistry = acmehandler.NewOrderFinalizeHookRegistry

// NewACMEPreIssuanceHookRegistry creates a new pre-issuance hook registry.
var NewACMEPreIssuanceHookRegistry = acmehandler.NewPreIssuanceHookRegistry

// NewACMEOrderPreSignHookRegistry creates a new pre-sign extension hook registry.
var NewACMEOrderPreSignHookRegistry = acmehandler.NewOrderPreSignHookRegistry

// NewACMEStorageFactoryFromKVStore creates an ACME storage factory backed by a
// go-qrdb KVStore directly. This is the datastore path: ACME persistence
// (accounts / orders / authorizations / certificates) shares the caller's
// configured qrdb datastore instead of a separate object store.
var NewACMEStorageFactoryFromKVStore = acmeobjstore.NewFactoryFromKVStore

// NewACMEClient creates a new ACME protocol client.
var NewACMEClient = acmeclient.NewClient

// NewACMEXKMSTPMAdapter creates a new adapter wrapping a go-xkms TPM module.
var NewACMEXKMSTPMAdapter = acmeclient.NewXKMSTPMAdapter

// ACMECrossSignerFromClient creates a cross-signing ACME client from an existing client.
var ACMECrossSignerFromClient = acmeclient.CrossSignerFromClient

// ACMEResolveComplianceConfig determines the effective compliance configuration.
var ACMEResolveComplianceConfig = acmehandler.ResolveComplianceConfig

// =============================================================================
// Sentinel Errors
// =============================================================================

// ACME common errors.
var (
	// ACMEErrInvalidChallengeType is returned when an invalid challenge type is provided.
	ACMEErrInvalidChallengeType = acmecommon.ErrInvalidChallengeType

	// ACMEErrAccountAlreadyExists is returned when attempting to create a duplicate account.
	ACMEErrAccountAlreadyExists = acmecommon.ErrAccountAlreadyExists
)

// ACME client errors.
var (
	// ACMEErrInvalidConfiguration is returned when the ACME client configuration is invalid.
	ACMEErrInvalidConfiguration = acmeclient.ErrInvalidConfiguration

	// ACMEErrDeviceIdentityFailed is returned by ACMETPMModule.DeviceIdentity
	// when the device's IAK certificate cannot be read.
	ACMEErrDeviceIdentityFailed = acmeclient.ErrDeviceIdentityFailed

	// ACMEErrAttestedKeyNameRequired is returned by
	// ACMETPMModule.CreateAttestedKey for an empty key name.
	ACMEErrAttestedKeyNameRequired = acmeclient.ErrAttestedKeyNameRequired

	// ACMEErrKeyBackendNotConfigured is returned by
	// ACMETPMModule.CreateAttestedKey when no TPM key store is configured.
	ACMEErrKeyBackendNotConfigured = acmeclient.ErrKeyBackendNotConfigured

	// ACMEErrAttestedKeyFailed is returned by ACMETPMModule.CreateAttestedKey
	// when the certificate key cannot be created or certified.
	ACMEErrAttestedKeyFailed = acmeclient.ErrAttestedKeyFailed
)

// ACME handler errors.
var (
	// ACMEErrAccountNotFound is returned when an account cannot be found.
	ACMEErrAccountNotFound = acmehandler.ErrAccountNotFound

	// ACMEErrAccountDeactivated is returned when a deactivated account makes a request.
	ACMEErrAccountDeactivated = acmehandler.ErrAccountDeactivated
)

// =============================================================================
// ACME Common Constants
// =============================================================================

// ACME status values per RFC 8555.
const (
	ACMEStatusValid       = acmecommon.StatusValid
	ACMEStatusPending     = acmecommon.StatusPending
	ACMEStatusProcessing  = acmecommon.StatusProcessing
	ACMEStatusInvalid     = acmecommon.StatusInvalid
	ACMEStatusDeactivated = acmecommon.StatusDeactivated
	ACMEStatusExpired     = acmecommon.StatusExpired
	ACMEStatusRevoked     = acmecommon.StatusRevoked
	ACMEStatusReady       = acmecommon.StatusReady
)

// ACME challenge type constants.
const (
	ACMEChallengeTypeEnroll01       = acmecommon.ChallengeTypeEnroll01
	ACMEChallengeTypeDNS01          = acmecommon.ChallengeTypeDNS01
	ACMEChallengeTypeHTTP01         = acmecommon.ChallengeTypeHTTP01
	ACMEChallengeTypeEndorse01      = acmecommon.ChallengeTypeEndorse01
	ACMEChallengeTypeDeviceAttest01 = acmecommon.ChallengeTypeDeviceAttest01
)

// ACME authorization type constants.
const (
	ACMEAuthzTypeDNS                 = acmecommon.AuthzTypeDNS
	ACMEAuthzTypeIP                  = acmecommon.AuthzTypeIP
	ACMEAuthzTypePermanentIdentifier = acmecommon.AuthzTypePermanentIdentifier
)

// =============================================================================
// ACME Server Rate Limiter
// =============================================================================

// ACMERateLimiter provides request rate limiting for ACME endpoints.
type ACMERateLimiter = acmeserver.RateLimiter

// NewACMERateLimiter creates a new rate limiter with the specified limits.
var NewACMERateLimiter = acmeserver.NewRateLimiter

// ACMEClientID returns the rate-limiting key for an HTTP request: the verified
// account ID when one was recorded on the request context, otherwise the
// client IP. It never trusts an unverified JWS "kid".
var ACMEClientID = acmeserver.ClientID

// =============================================================================
// ACME Challenge Verify Functions
// =============================================================================

// ACMEChallengeClient is the shared, SSRF-safe HTTP client the http-01,
// enroll-01 and device-attest-01 verifiers contact client-named targets
// through. One client is built per ACME server and shared by its verifiers.
type ACMEChallengeClient = validation.Client

// ACMEChallengeClientConfig configures an ACMEChallengeClient.
// AllowPrivateTargets (default false) is the only way to reach a reserved
// target address, for test and lab deployments.
type ACMEChallengeClientConfig = validation.Config

// NewACMEChallengeClient returns an ACMEChallengeClient.
var NewACMEChallengeClient = validation.NewClient

// ACMEVerifyHTTP01 verifies an HTTP-01 ACME challenge through an
// ACMEChallengeClient.
var ACMEVerifyHTTP01 = http01.Verify

// ACMEVerifyDNS01 verifies a DNS-01 ACME challenge.
var ACMEVerifyDNS01 = dns01.Verify

// ACMEComputeDNS01ChallengeValue computes the DNS-01 TXT record value
// (base64url SHA-256 of the key authorization) for a challenge.
var ACMEComputeDNS01ChallengeValue = dns01.ComputeChallengeValue

// ACMEVerifyEnroll01 verifies an enroll-01 ACME challenge.
var ACMEVerifyEnroll01 = enroll01.Verify

// ACMEVerifyEndorse01 is endorse01.Verify, which verifies nothing.
//
// Deprecated: it returns nil for every request. endorse-01 is authorized by the
// account's External Account Binding; register ACMEAttestingVerifiers.
var ACMEVerifyEndorse01 = endorse01.Verify //nolint:staticcheck // SA1019: re-exported unchanged for source compatibility

// ACMEVerifyEnroll01Activation verifies an enroll-01 ACME challenge and returns
// the endorsement key and activation key the credential was activated for.
var ACMEVerifyEnroll01Activation = enroll01.VerifyActivation

// ACMEEnroll01Activation is what a completed enroll-01 credential activation
// established: the endorsement key certificate and the activation key a
// TCG-CSR-IDEVID must be built around to finalize the order.
type ACMEEnroll01Activation = enroll01.Activation

// ACMEErrEnroll01ActivationUnreadable is returned when a credential activated
// but the keys it was made for cannot be read from the TCG-CSR-IDEVID.
var ACMEErrEnroll01ActivationUnreadable = enroll01.ErrActivationUnreadable

// ACMEEnroll01Format is the format tag of an enroll-01 activation record
// (ACMEDeviceAttestationEntity.Format).
const ACMEEnroll01Format = enroll01.Format

// ACMEErrEnrollActivationNotFound is returned at finalization when a
// TCG-CSR-IDEVID arrives for an order no enroll-01 credential activation was
// recorded on.
type ACMEErrEnrollActivationNotFound = acmehandler.ErrEnrollActivationNotFound

// ACMEErrEnrollActivationMismatch is returned at finalization when a
// TCG-CSR-IDEVID is built around an endorsement key or attestation key other
// than the one an enroll-01 credential was activated for.
type ACMEErrEnrollActivationMismatch = acmehandler.ErrEnrollActivationMismatch

// ACMEErrFinalizeRequestNotPermitted is returned at finalization when the
// request is not one the order's validated attestation challenge permits: an
// endorse-01 order finalizes only as an EK certificate.
type ACMEErrFinalizeRequestNotPermitted = acmehandler.ErrFinalizeRequestNotPermitted

// ACMEEnroll01TCGCSRVerifier is the TCG-CSR-IDEVID verification interface
// required by enroll-01 challenges.
type ACMEEnroll01TCGCSRVerifier = enroll01.TCGCSRVerifier

// ACMEDeviceAttest01Verifier is the AK/UEID chain-anchoring and attestation
// object verification interface required by device-attest-01 challenges. It is
// the server's trust policy over a device's evidence, passed to
// ACMEAttestingVerifiers to enable the challenge. ACMETrustAnchorVerifier
// implements it from configured trust anchors.
type ACMEDeviceAttest01Verifier = deviceattest01.AttestationVerifier

// ACMEDeviceAttestFormat names a device-attest-01 attestation format.
type ACMEDeviceAttestFormat = deviceattest01.AttestationFormat

// The device-attest-01 attestation formats that define a device identity.
const (
	// ACMEDeviceAttestFormatTPM is a WebAuthn "tpm" statement; its identity
	// is the AIK certificate's RFC 4043 permanentIdentifier.
	ACMEDeviceAttestFormatTPM = deviceattest01.FormatTPM

	// ACMEDeviceAttestFormatDICE is a TCG DICE statement (UCCS evidence); its
	// identity is the alias certificate's tcg-dice-Ueid, as lowercase hex.
	ACMEDeviceAttestFormatDICE = deviceattest01.FormatDICE
)

// ACMEDeviceIdentityFromCertificate reads the device identity an attestation
// leaf certificate of the given format carries -- the identity the server
// compares with the order's permanent-identifier, and so the value a
// device-attest-01 client must name.
var ACMEDeviceIdentityFromCertificate = deviceattest01.DeviceIdentityFromCertificate

// ACMEErrDeviceIdentityUnavailable is returned when attestation evidence
// carries no device identity ACMEDeviceIdentityFromCertificate can read.
var ACMEErrDeviceIdentityUnavailable = deviceattest01.ErrDeviceIdentityUnavailable

// ACMETrustAnchors configures an ACMETrustAnchorVerifier: the roots a "tpm"
// attestation's AIK chain and a "dice" attestation's chain must reach.
type ACMETrustAnchors = deviceattest01.TrustAnchors

// ACMEDICEPolicy is the policy a DICE alias certificate must meet beyond
// anchoring: device-signed leaf, firmware measurement, DiceTcbInfo and
// tolerated operational flags.
type ACMEDICEPolicy = deviceattest01.DICEPolicy

// ACMETrustAnchorVerifier is the production ACMEDeviceAttest01Verifier: it
// anchors a device's evidence to configured trust anchors using the TPM and
// DICE verification primitives go-xkms owns.
type ACMETrustAnchorVerifier = deviceattest01.TrustAnchorVerifier

// ACMENewTrustAnchorVerifier builds an ACMETrustAnchorVerifier. It returns
// ACMEErrNoTrustAnchors when no root is configured.
var ACMENewTrustAnchorVerifier = deviceattest01.NewTrustAnchorVerifier

// ACMEErrNoTrustAnchors is returned when device-attest-01 verification is
// asked for with no trust anchors, or none for the attestation's format.
var ACMEErrNoTrustAnchors = deviceattest01.ErrNoTrustAnchors

// ACMEErrNoAttestationVerifier is returned when an attestation is verified
// with no ACMEDeviceAttest01Verifier.
var ACMEErrNoAttestationVerifier = deviceattest01.ErrNoAttestationVerifier

// ACMEDeviceAttestRequest is the payload a device-attest-01 client POSTs to
// the challenge URL (draft-ietf-acme-device-attest): {"attObj": base64url}.
type ACMEDeviceAttestRequest = deviceattest01.AttestationRequest

// ACMEParseDeviceAttestRequest decodes a device-attest-01 challenge payload
// into its attestation object.
var ACMEParseDeviceAttestRequest = deviceattest01.ParseAttestationRequest

// ACMEEncodeDeviceAttestRequest encodes an attestation object as the
// device-attest-01 challenge payload.
var ACMEEncodeDeviceAttestRequest = deviceattest01.EncodeAttestationRequest

// ACMEErrAttestationPayloadInvalid is returned when a device-attest-01
// challenge payload is not a decodable attestation object.
var ACMEErrAttestationPayloadInvalid = deviceattest01.ErrAttestationPayloadInvalid

// ACMEDeviceAttestStatement is the attStmt of an ACMEDeviceAttestObject: the
// "tpm" format's x5c/sig/certInfo/pubArea, or the "dice" format's x5c.
type ACMEDeviceAttestStatement = deviceattest01.AttestationStatement

// ACMEDICENonce is the value a DICE device places in its eat_nonce claim to
// answer a device-attest-01 challenge for a key authorization: SHA-256 of it.
var ACMEDICENonce = deviceattest01.DICENonce

// ACMETPMExtraData is the extraData a TPM2_Certify must carry to answer a
// device-attest-01 challenge with a "tpm" statement.
var ACMETPMExtraData = deviceattest01.TPMExtraData

// ACMEDeviceAttestObject is the WebAuthn-style attestation object a
// device-attest-01 statement carries, the argument an
// ACMEDeviceAttest01Verifier receives.
type ACMEDeviceAttestObject = deviceattest01.AttestationObject

// ACMEErrAttestationIdentifierType is returned when an attestation challenge
// is asked to authorize an identifier type it cannot: attestation never
// authorizes an "ip" identifier.
type ACMEErrAttestationIdentifierType = acmehandler.ErrAttestationIdentifierType

// ACMEErrAttestingVerifierRequired is returned (to the log and audit record)
// when an attestation challenge has no ACMEAttestingVerifier registered.
type ACMEErrAttestingVerifierRequired = acmehandler.ErrAttestingVerifierRequired

// ACMEErrAttestationNoIdentity is returned when an ACMEAttestingVerifier
// reports success without an attested identity.
type ACMEErrAttestationNoIdentity = acmehandler.ErrAttestationNoIdentity

// ACMEErrIdentityMismatch is returned when the identity an attestation
// challenge established is not the identifier the order authorizes.
type ACMEErrIdentityMismatch = acmehandler.ErrIdentityMismatch

// ACMENewEndorseVerifier returns the endorse-01 ACMEAttestingVerifier: it
// reports the identity the account's External Account Binding authorized
// (ACMEAttestationChallenge.AuthorizedIdentity) and refuses without one.
// ACMEAttestingVerifiers registers it for endorse-01.
var ACMENewEndorseVerifier = acmehandler.NewEndorseVerifier

// ACMEErrEndorseEABKeyNotBound is returned when an endorse-01 External Account
// Binding names no EK: it would authorize its account for any public key.
var ACMEErrEndorseEABKeyNotBound = acmehandler.ErrEndorseEABKeyNotBound

// ACMEErrEndorseEABKeyMismatch is returned when the EK an endorse-01 order asks
// to certify is not the one the account's External Account Binding names.
var ACMEErrEndorseEABKeyMismatch = acmehandler.ErrEndorseEABKeyMismatch

// ACMEErrEndorseNoAuthorizedIdentity is returned by the endorse-01 verifier run
// without an EAB-authorized identity to attest.
var ACMEErrEndorseNoAuthorizedIdentity = acmehandler.ErrEndorseNoAuthorizedIdentity

// ACMEErrOrderAuthorizationMissing is returned when an order references an
// authorization storage does not hold. Finalization is refused rather than
// decided from the authorizations that remain.
type ACMEErrOrderAuthorizationMissing = acmehandler.ErrOrderAuthorizationMissing

// ACMEErrDeviceAttestationNotFound is returned at finalization when a
// permanent-identifier order has no validated device-attest-01 attestation to
// bind the certificate request to.
type ACMEErrDeviceAttestationNotFound = acmehandler.ErrDeviceAttestationNotFound

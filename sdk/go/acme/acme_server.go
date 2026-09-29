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

// ACMEVerifyEndorse01 verifies an endorse-01 ACME challenge.
var ACMEVerifyEndorse01 = endorse01.Verify

// ACMEEnroll01TCGCSRVerifier is the TCG-CSR-IDEVID verification interface
// required by enroll-01 challenges.
type ACMEEnroll01TCGCSRVerifier = enroll01.TCGCSRVerifier

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

package xkms

import (
	gotpm2 "github.com/google/go-tpm/tpm2"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpmdev"
)

// ---------------------------------------------------------------------------
// Interface aliases
// ---------------------------------------------------------------------------

// TrustedPlatformModule is the primary TPM 2.0 interface.
type TrustedPlatformModule = tpm2.TrustedPlatformModule

// SimulatorInterface abstracts the TPM simulator for conditional compilation.
type SimulatorInterface = tpm2.SimulatorInterface

// PlatformKeyStorer defines the interface for a TPM-backed platform key store.
type PlatformKeyStorer = tpm2.PlatformKeyStorer

// PINBackend defines the interface for backend-native PIN operations.
type PINBackend = qrdbsdk.PINBackend

// ---------------------------------------------------------------------------
// Struct and concrete type aliases
// ---------------------------------------------------------------------------

// Params holds the parameters for creating a new TPM2 instance.
type TPMParams = tpm2.Params

// TPM2 is the concrete TPM 2.0 implementation.
type TPM2 = tpm2.TPM2

// Config holds TPM configuration.
type TPMConfig = tpm2.Config

// EKConfig holds Endorsement Key configuration.
type EKConfig = tpm2.EKConfig

// SRKConfig holds Storage Root Key configuration.
type SRKConfig = tpm2.SRKConfig

// IAKConfig holds Initial Attestation Key configuration.
type IAKConfig = tpm2.IAKConfig

// IDevIDConfig holds Initial Device Identifier configuration.
type IDevIDConfig = tpm2.IDevIDConfig

// DevIDTemplateSpec names the crypto suite of a TCG Recoverable IDevID/IAK
// key creation template (Templates H-1 through H-4, section 7.3.4). Its
// Template method builds the TPMT_PUBLIC.
type DevIDTemplateSpec = tpm2.DevIDTemplateSpec

// DevIDKeyKind selects between the two TCG device identity key kinds -- the
// signing IDevID and the attestation IAK -- whose key policies differ only in
// the Policy NV Index their DelegationNV branch is bound to.
type DevIDKeyKind = tpm2.DevIDKeyKind

// LDevIDConfig holds Local Device Identifier configuration.
type LDevIDConfig = tpm2.LDevIDConfig

// LAKConfig holds Local Attestation Key configuration.
type LAKConfig = tpm2.LAKConfig

// PlatformSRKConfig holds Platform Storage Root Key configuration.
type PlatformSRKConfig = tpm2.PlatformSRKConfig

// TPMPCRSet is the sealing PCR set of TPMConfig.PlatformPCRs.
type TPMPCRSet = tpm2.PCRSet

// TPMPlatformPCRError is the typed error TPMPCRSet.Validate returns.
type TPMPlatformPCRError = tpm2.PlatformPCRError

// PlatformKeyStore provides TPM-backed key storage with integrated PIN management.
type PlatformKeyStore = tpm2.PlatformKeyStore

// ---------------------------------------------------------------------------
// TCG CSR types
// ---------------------------------------------------------------------------

// TCG_CSR_IDEVID represents the TCG-CSR-IDEVID structure per
// TCG TPM 2.0 Keys for Device Identity and Attestation, Section 13.1.
type TCG_CSR_IDEVID = tpm2.TCG_CSR_IDEVID

// TCG_IDEVID_CONTENT represents the content portion of TCG-CSR-IDEVID.
type TCG_IDEVID_CONTENT = tpm2.TCG_IDEVID_CONTENT

// UNPACKED_TCG_CSR_IDEVID is the unpacked form of TCG-CSR-IDEVID with native Go types.
type UNPACKED_TCG_CSR_IDEVID = tpm2.UNPACKED_TCG_CSR_IDEVID

// UNPACKED_TCG_IDEVID_CONTENT is the unpacked form of TCG_IDEVID_CONTENT.
type UNPACKED_TCG_IDEVID_CONTENT = tpm2.UNPACKED_TCG_IDEVID_CONTENT

// TCG_CSR_LDEVID represents the TCG-CSR-LDEVID structure.
type TCG_CSR_LDEVID = tpm2.TCG_CSR_LDEVID

// TCG_LDEVID_CONTENT represents the content portion of TCG-CSR-LDEVID.
type TCG_LDEVID_CONTENT = tpm2.TCG_LDEVID_CONTENT

// UNPACKED_TCG_CSR_LDEVID is the unpacked form of TCG-CSR-LDEVID.
type UNPACKED_TCG_CSR_LDEVID = tpm2.UNPACKED_TCG_CSR_LDEVID

// UNPACKED_TCG_LDEVID_CONTENT is the unpacked form of TCG_LDEVID_CONTENT.
type UNPACKED_TCG_LDEVID_CONTENT = tpm2.UNPACKED_TCG_LDEVID_CONTENT

// ---------------------------------------------------------------------------
// Attestation and quote types
// ---------------------------------------------------------------------------

// CertifyResult holds the output of a TPM2_Certify operation.
type CertifyResult = tpm2.CertifyResult

// AKProfile represents an Attestation Key profile.
type AKProfile = tpm2.AKProfile

// Quote represents a TPM 2.0 quote.
type Quote = tpm2.Quote

// ProvisioningState classifies a TPM's current provisioning progress: see
// TrustedPlatformModule.State.
type ProvisioningState = tpm2.ProvisioningState

// CredentialChallenge is a TPM2_MakeCredential challenge built in software
// by NewCredentialChallenge, and answered by AnswerCredentialChallenge or
// ActivateCredential.
type CredentialChallenge = tpm2.CredentialChallenge

// ActivationKey is a transient key created by
// TrustedPlatformModule.CreateActivationKey, used only to answer an EK
// credential challenge.
type ActivationKey = tpm2.ActivationKey

// NewCredentialChallenge builds a TPM2_MakeCredential challenge for an EK
// public key entirely in software; the verifier needs no TPM of its own.
var NewCredentialChallenge = tpm2.NewCredentialChallenge

// ActivationKeyName computes the TPM Name of a public area received off the
// wire (e.g. a TCG-CSR-IDEVID's AttestPub field), for use as
// NewCredentialChallenge's activationKeyName argument.
var ActivationKeyName = tpm2.ActivationKeyName

// ---------------------------------------------------------------------------
// PCR types
// ---------------------------------------------------------------------------

// PCRBank holds PCR values for a single hash algorithm bank.
type PCRBank = tpm2.PCRBank

// PCR represents a single Platform Configuration Register value.
type PCR = tpm2.PCR

// PCRBankAlgo represents a PCR bank hash algorithm name.
type PCRBankAlgo = tpm2.PCRBankAlgo

// ---------------------------------------------------------------------------
// ProdCaData types
// ---------------------------------------------------------------------------

// ProdCaData represents CA-specific attestation data included in TCG-CSR-IDEVID.
type ProdCaData = tpm2.ProdCaData

// ---------------------------------------------------------------------------
// NV index types
// ---------------------------------------------------------------------------

// NVIndexInfo describes an NV index defined on the TPM.
type NVIndexInfo = tpm2.NVIndexInfo

// ---------------------------------------------------------------------------
// Capabilities and properties types
// ---------------------------------------------------------------------------

// PropertiesFixed contains fixed TPM properties queried from the device.
type PropertiesFixed = tpm2.PropertiesFixed

// CommandInfo describes a single TPM command.
type CommandInfo = tpm2.CommandInfo

// TPMProperty represents a single TPM property.
type TPMProperty = tpm2.TPMProperty

// ---------------------------------------------------------------------------
// Event log types
// ---------------------------------------------------------------------------

// Event represents a single parsed TPM event.
type TPMEvent = tpm2.Event

// Digest represents a single hash digest in a TPM event.
type TPMDigest = tpm2.Digest

// ParseEventLogOptions configures event log parsing behavior.
type ParseEventLogOptions = tpm2.ParseEventLogOptions

// ---------------------------------------------------------------------------
// Install options
// ---------------------------------------------------------------------------

// InstallOptions controls which provisioning steps Install() performs.
type InstallOptions = tpm2.InstallOptions

// DefaultInstallOptions returns options that provision everything.
var DefaultInstallOptions = tpm2.DefaultInstallOptions

// MinimalInstallOptions returns TCG minimum provisioning (EK + SSRK only).
var MinimalInstallOptions = tpm2.MinimalInstallOptions

// ---------------------------------------------------------------------------
// Platform types
// ---------------------------------------------------------------------------

// PlatformAttributes contains device platform identification attributes.
type PlatformAttributes = tpm2.PlatformAttributes

// PlatformPassword provides just-in-time password retrieval from TPM keyed hash.
type PlatformPassword = tpm2.PlatformPassword

// ---------------------------------------------------------------------------
// Miscellaneous types
// ---------------------------------------------------------------------------

// EnrollmentStrategy represents an identity provisioning strategy.
type EnrollmentStrategy = tpm2.EnrollmentStrategy

// TCGVendorID is a TCG vendor identifier.
type TCGVendorID = tpm2.TCGVendorID

// ---------------------------------------------------------------------------
// Store interface aliases (from pkg/tpm2/store)
// ---------------------------------------------------------------------------

// TPMKeyBackend provides key storage operations for TPM keys.
type TPMKeyBackend = store.KeyBackend

// TPMStorageFactory builds key backends for TPM key persistence.
type TPMStorageFactory = store.StorageFactory

// NewTPMStorageFactory constructs a TPM key-storage factory rooted at baseDir
// (a private, file-based engine; empty baseDir uses a temp directory). For a
// key store over the shared datastore instead, use NewTPMBlobStore over its
// DAO factory.
var NewTPMStorageFactory = store.NewStorageFactory

// TPMBlobStore keeps TPM key blobs as TPMBlob entities in the tpm2 database
// of a DAO factory, one tenant per store.
type TPMBlobStore = store.BlobStore

// NewTPMBlobStore returns the system tenant's TPM key store over a DAO
// factory that serves the tpm2 database (TPMBlobDatabase).
var NewTPMBlobStore = store.NewBlobStore

// NewTPMBackendBlobStore returns the system tenant's TPM key store over an
// already-open StorageBackend that supports guarded writes.
var NewTPMBackendBlobStore = store.NewBackendBlobStore

// TPMBlobDatabase is the database TPM key blobs are kept in.
const TPMBlobDatabase = store.DatabaseName

// TPMStoreIsRSAPSS reports whether the signature algorithm is an RSA-PSS
// variant, per pkg/tpm2/store. The equivalent pkg/types helper is re-exported
// as IsRSAPSS in types.go.
var TPMStoreIsRSAPSS = store.IsRSAPSS

// NewTPMStorePassword wraps a byte slice as a types.Password using the
// pkg/tpm2/store constructor. The pkg/types equivalent is re-exported as
// NewPassword in types.go.
var NewTPMStorePassword = store.NewPassword

// TPMCertificateStorer provides certificate storage operations for TPM.
type TPMCertificateStorer = store.CertificateStorer

// TPMSignerOpts provides TPM-specific signer options.
type TPMSignerOpts = store.SignerOpts

// RSAConfig holds RSA key configuration.
type RSAConfig = store.RSAConfig

// ECCConfig holds ECC key configuration.
type ECCConfig = store.ECCConfig

// ---------------------------------------------------------------------------
// go-tpm type re-exports (from google/go-tpm/tpm2)
// ---------------------------------------------------------------------------

// TPMHandle represents a TPM handle.
type TPMHandle = gotpm2.TPMHandle

// Handle type constants from go-tpm.
const (
	TPMHTPersistent = gotpm2.TPMHTPersistent
	TPMHTTransient  = gotpm2.TPMHTTransient
)

// Hierarchy constants from go-tpm.
const (
	TPMRHOwner       = gotpm2.TPMRHOwner
	TPMRHEndorsement = gotpm2.TPMRHEndorsement
	TPMRHPlatform    = gotpm2.TPMRHPlatform
	TPMRHNull        = gotpm2.TPMRHNull
)

// RSASRKTemplate is the RSA Storage Root Key template from go-tpm.
var RSASRKTemplate = gotpm2.RSASRKTemplate

// ---------------------------------------------------------------------------
// Store constructor re-exports (from pkg/tpm2/store)
// ---------------------------------------------------------------------------

// ErrTPMStoreCertNotFound is returned when a certificate is not found in the TPM store.
var ErrTPMStoreCertNotFound = store.ErrCertNotFound

// DebugKeyAttributes logs key attributes at debug level for diagnostics.
var DebugKeyAttributes = store.DebugKeyAttributes

// ---------------------------------------------------------------------------
// Enrollment strategy constants
// ---------------------------------------------------------------------------

const (
	// EnrollmentStrategyIAK is the IAK-only enrollment strategy.
	TPMEnrollmentStrategyIAK = tpm2.EnrollmentStrategyIAK

	// TPMDevIDKeySigning is the IDevID kind: an Unrestricted signing key
	// (TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12,
	// Template H-0).
	TPMDevIDKeySigning = tpm2.DevIDKeySigning

	// TPMDevIDKeyAttestation is the IAK kind: a Restricted signing key.
	TPMDevIDKeyAttestation = tpm2.DevIDKeyAttestation

	// EnrollmentStrategyIAK_IDEVID_SINGLE_PASS is the combined IAK+IDevID enrollment.
	TPMEnrollmentStrategyIAK_IDEVID_SINGLE_PASS = tpm2.EnrollmentStrategyIAK_IDEVID_SINGLE_PASS

	// ProdCaDataVersion is the current version of the ProdCaData structure.
	ProdCaDataVersion = tpm2.ProdCaDataVersion

	// DefaultCacheTTLSeconds is the default TTL for cached TPM passwords.
	TPMDefaultCacheTTLSeconds = tpm2.DefaultCacheTTLSeconds

	// DEFAULT_PASSWORD is the default password constant.
	TPM_DEFAULT_PASSWORD = tpm2.DEFAULT_PASSWORD
)

// ---------------------------------------------------------------------------
// PCR bank constants
// ---------------------------------------------------------------------------

var (
	// PCRBankSHA1 is the SHA-1 PCR bank identifier.
	PCRBankSHA1 = tpm2.PCRBankSHA1

	// PCRBankSHA256 is the SHA-256 PCR bank identifier.
	PCRBankSHA256 = tpm2.PCRBankSHA256

	// PCRBankSHA384 is the SHA-384 PCR bank identifier.
	PCRBankSHA384 = tpm2.PCRBankSHA384

	// PCRBankSHA512 is the SHA-512 PCR bank identifier.
	PCRBankSHA512 = tpm2.PCRBankSHA512

	// DefaultTPMConfig is the default TPM configuration.
	DefaultTPMConfig = tpm2.DefaultConfig
)

// DefaultPlatformPCRs returns the sealing PCR set an unset TPMConfig
// PlatformPCRs resolves to ({7, 11}), in xkmsd and xkey alike.
var DefaultPlatformPCRs = tpm2.DefaultPlatformPCRs

// ---------------------------------------------------------------------------
// TPM public key template variables
// ---------------------------------------------------------------------------

var (
	// RSASSATemplate is the RSA-SSA signing key template.
	RSASSATemplate = tpm2.RSASSATemplate

	// RSAPSSTemplate is the RSA-PSS signing key template.
	RSAPSSTemplate = tpm2.RSAPSSTemplate

	// ECCP256Template is the ECC P-256 signing key template.
	ECCP256Template = tpm2.ECCP256Template

	// ECCP384Template is the ECC P-384 signing key template.
	ECCP384Template = tpm2.ECCP384Template

	// ECCP521Template is the ECC P-521 signing key template.
	ECCP521Template = tpm2.ECCP521Template

	// RSASSAAKTemplate is the RSA-SSA Attestation Key template.
	RSASSAAKTemplate = tpm2.RSASSAAKTemplate

	// RSAPSSAKTemplate is the RSA-PSS Attestation Key template.
	RSAPSSAKTemplate = tpm2.RSAPSSAKTemplate

	// ECCAKP256Template is the ECC P-256 Attestation Key template (TCG DevID
	// Template H-2).
	ECCAKP256Template = tpm2.ECCAKP256Template

	// ECCAKP384Template is the ECC P-384 Attestation Key template (TCG DevID
	// Template H-3).
	ECCAKP384Template = tpm2.ECCAKP384Template

	// ECCAKP521Template is the ECC P-521 Attestation Key template (TCG DevID
	// Template H-4).
	ECCAKP521Template = tpm2.ECCAKP521Template

	// RSASSAIDevIDTemplate is the RSA-SSA IDevID key template.
	RSASSAIDevIDTemplate = tpm2.RSASSAIDevIDTemplate

	// RSAPSSIDevIDTemplate is the RSA-PSS IDevID key template.
	RSAPSSIDevIDTemplate = tpm2.RSAPSSIDevIDTemplate

	// ECCIDevIDP256Template is the ECC P-256 IDevID key template (TCG DevID
	// Template H-2).
	ECCIDevIDP256Template = tpm2.ECCIDevIDP256Template

	// ECCIDevIDP384Template is the ECC P-384 IDevID key template (TCG DevID
	// Template H-3).
	ECCIDevIDP384Template = tpm2.ECCIDevIDP384Template

	// ECCIDevIDP521Template is the ECC P-521 IDevID key template (TCG DevID
	// Template H-4).
	ECCIDevIDP521Template = tpm2.ECCIDevIDP521Template

	// AES128CFBTemplate is the AES-128-CFB symmetric key template.
	AES128CFBTemplate = tpm2.AES128CFBTemplate

	// AES256CFBTemplate is the AES-256-CFB symmetric key template.
	AES256CFBTemplate = tpm2.AES256CFBTemplate

	// KeyedHashTemplate is the keyed hash (HMAC) template.
	KeyedHashTemplate = tpm2.KeyedHashTemplate
)

// ---------------------------------------------------------------------------
// Error variables
// ---------------------------------------------------------------------------

var (
	// TPM errors
	ErrTPMInvalidAKAttributes         = tpm2.ErrInvalidAKAttributes
	ErrTPMInvalidEKCertFormat         = tpm2.ErrInvalidEKCertFormat
	ErrTPMInvalidEKAttributes         = tpm2.ErrInvalidEKAttributes
	ErrTPMInvalidEKCert               = tpm2.ErrInvalidEKCert
	ErrTPMDeviceAlreadyOpen           = tpm2.ErrDeviceAlreadyOpen
	ErrTPMOpeningDevice               = tpm2.ErrOpeningDevice
	ErrTPMDeviceTransportUnsupported  = tpm2.ErrDeviceTransportUnsupported
	ErrTPMInvalidSessionType          = tpm2.ErrInvalidSessionType
	ErrTPMInvalidSRKAuth              = tpm2.ErrInvalidSRKAuth
	ErrTPMInvalidActivationCredential = tpm2.ErrInvalidActivationCredential
	ErrTPMHashAlgorithmNotSupported   = tpm2.ErrHashAlgorithmNotSupported
	ErrTPMInvalidKeyAttributes        = tpm2.ErrInvalidKeyAttributes
	ErrTPMInvalidPolicyDigest         = tpm2.ErrInvalidPolicyDigest
	ErrTPMInvalidHandle               = tpm2.ErrInvalidHandle
	ErrTPMUnexpectedRandomBytes       = tpm2.ErrUnexpectedRandomBytes
	ErrTPMInvalidRandomBytesLength    = tpm2.ErrInvalidRandomBytesLength
	ErrTPMInvalidPCRIndex             = tpm2.ErrInvalidPCRIndex
	ErrTPMInvalidNonce                = tpm2.ErrInvalidNonce
	ErrTPMNotInitialized              = tpm2.ErrNotInitialized
	ErrTPMNotConfigured               = tpm2.ErrNotConfigured
	ErrTPMEndorsementCertNotFound     = tpm2.ErrEndorsementCertNotFound
	ErrTPMInvalidPlatformSRKConfig    = tpm2.ErrInvalidPlatformSRKConfiguration
	ErrTPMPlatformPCRSetEmpty         = tpm2.ErrPlatformPCRSetEmpty
	ErrTPMPlatformPCROutOfRange       = tpm2.ErrPlatformPCROutOfRange
	ErrTPMPlatformPCRDuplicate        = tpm2.ErrPlatformPCRDuplicate
	ErrTPMPlatformPCRResettable       = tpm2.ErrPlatformPCRResettable
	ErrTPMInvalidHashFunction         = tpm2.ErrInvalidHashFunction
	ErrTPMInvalidSessionAuthorization = tpm2.ErrInvalidSessionAuthorization
	ErrTPMMissingMeasurementLog       = tpm2.ErrMissingMeasurementLog
	ErrTPMRSAPSSNotSupported          = tpm2.ErrRSAPSSNotSupported
	ErrTPMInvalidEnrollmentStrategy   = tpm2.ErrInvalidEnrollmentStrategy
	ErrTPMInvalidCryptoHashAlgID      = tpm2.ErrInvalidCryptoHashAlgID
	ErrTPMCurveNotSupported           = tpm2.ErrCurveNotSupported
	ErrTPMInvalidKeySize              = tpm2.ErrInvalidKeySize
	ErrTPMInvalidNVExtendData         = tpm2.ErrInvalidNVExtendData
	ErrTPMIAKNotProvisioned           = tpm2.ErrIAKNotProvisioned
	ErrTPMTransportNotInitialized     = tpm2.ErrTransportNotInitialized
	ErrTPMLockoutResetFailed          = tpm2.ErrLockoutResetFailed
	ErrTPMEKNotInitialized            = tpm2.ErrEKNotInitialized
	ErrTPMEKPublicRead                = tpm2.ErrEKPublicRead
	ErrTPMEKRSAParse                  = tpm2.ErrEKRSAParse
	ErrTPMEKECCParse                  = tpm2.ErrEKECCParse
	ErrTPMSRKPublicRead               = tpm2.ErrSRKPublicRead
	ErrTPMIAKNotInitialized           = tpm2.ErrIAKNotInitialized
	ErrTPMIAKPublicParse              = tpm2.ErrIAKPublicParse
	ErrTPMIDevIDNotInitialized        = tpm2.ErrIDevIDNotInitialized
	ErrTPMIDevIDPublicParse           = tpm2.ErrIDevIDPublicParse
	ErrTPMGoldenMeasurements          = tpm2.ErrGoldenMeasurements
	ErrTPMPolicyDigest                = tpm2.ErrPolicyDigest
	ErrTPMIAKConfigFailed             = tpm2.ErrIAKConfigFailed
	ErrTPMCSRFieldTooLarge            = tpm2.ErrCSRFieldTooLarge
	ErrTPMNVSecretTooLarge            = tpm2.ErrNVSecretTooLarge
	ErrTPMSealUnprotected             = tpm2.ErrSealUnprotected
	ErrTPMInvalidHierarchy            = tpm2.ErrInvalidHierarchy
	ErrTPMFactoryReset                = tpm2.ErrFactoryReset
	ErrTPMForceClear                  = tpm2.ErrForceClear
	ErrTPMClearLockoutRefused         = tpm2.ErrClearLockoutRefused
	ErrTPMClearPlatformRefused        = tpm2.ErrClearPlatformRefused
	ErrTPMProvisioningStateRead       = tpm2.ErrProvisioningStateRead
	ErrTPMCredentialChallenge         = tpm2.ErrCredentialChallenge
	ErrTPMEKPublicRequired            = tpm2.ErrEKPublicRequired
	ErrTPMActivationKeyNameRequired   = tpm2.ErrActivationKeyNameRequired
	ErrTPMActivationKeyCreate         = tpm2.ErrActivationKeyCreate
	ErrTPMActivationKeyRequired       = tpm2.ErrActivationKeyRequired
	ErrTPMCredentialChallengeRequired = tpm2.ErrCredentialChallengeRequired
	ErrTPMEKConfigNil                 = tpm2.ErrEKConfigNil
	ErrTPMIAKConfigNil                = tpm2.ErrIAKConfigNil
	ErrTPMIDevIDConfigNil             = tpm2.ErrIDevIDConfigNil
	ErrTPMDevIDPolicyUnsupported      = tpm2.ErrDevIDPolicyUnsupported
	ErrTPMDevIDPolicyDigestCompute    = tpm2.ErrDevIDPolicyDigestCompute
	ErrTPMDevIDPolicySession          = tpm2.ErrDevIDPolicySession
	ErrTPMDevIDPolicyNVIndex          = tpm2.ErrDevIDPolicyNVIndex
	ErrTPMDevIDDelegation             = tpm2.ErrDevIDDelegation
	ErrTPMDevIDCNUnresolved           = tpm2.ErrDevIDCNUnresolved
	ErrTPMDevIDTemplateNonConformant  = tpm2.ErrDevIDTemplateNonConformant
	ErrTPMDevIDProvisionEKCert        = tpm2.ErrDevIDProvisionEKCert
	ErrTPMDevIDProvisionIAK           = tpm2.ErrDevIDProvisionIAK
	ErrTPMDevIDProvisionIDevID        = tpm2.ErrDevIDProvisionIDevID
	ErrTPMDevIDProvisionLookup        = tpm2.ErrDevIDProvisionLookup
	ErrTPMTCGCSRAttestation           = tpm2.ErrTCGCSRAttestation
	ErrTPMTCGCSRPad                   = tpm2.ErrTCGCSRPad
	ErrTPMDevIDUniqueString           = tpm2.ErrDevIDUniqueString
	ErrTPMDevIDUniqueStringTooLong    = tpm2.ErrDevIDUniqueStringTooLong
	ErrTPMDevIDTemplateSuiteUnsupport = tpm2.ErrDevIDTemplateSuiteUnsupported
	ErrTPMSSRKConfigNil               = tpm2.ErrSSRKConfigNil
	ErrTPMCommandNotSupported         = tpm2.ErrCommandNotSupported
	ErrTPMInvalidSignature            = tpm2.ErrInvalidSignature
	ErrTPMInvalidProdCaData           = tpm2.ErrInvalidProdCaData
	ErrTPMProdCaDataTooLarge          = tpm2.ErrProdCaDataTooLarge
	ErrTPMIDevIDCertNotFound          = tpm2.ErrIDevIDCertNotFound
	ErrTPMIAKCertNotFound             = tpm2.ErrIAKCertNotFound
	ErrTPMCertPublicKeyMismatch       = tpm2.ErrCertPublicKeyMismatch
	ErrTPMCertStoreNotConfigured      = tpm2.ErrCertStoreNotConfigured
	ErrTPMInvalidHierarchyType        = tpm2.ErrInvalidHierarchyType
	ErrTPMInvalidPCRBankType          = tpm2.ErrInvalidPCRBankType
	ErrTPMPolicyInvalidDigest         = tpm2.ErrPolicyInvalidDigest
	ErrTPMPolicyEmptyPCRs             = tpm2.ErrPolicyEmptyPCRs
	ErrTPMPolicyAuthValueRequired     = tpm2.ErrPolicyAuthValueRequired
	ErrTPMAuthFailed                  = tpm2.ErrAuthFailed
	ErrTPMEKCertExists                = tpm2.ErrEKCertExists
	ErrTPMEKCertIndexInvalid          = tpm2.ErrEKCertIndexInvalid
	ErrTPMEKCertPlatformIndex         = tpm2.ErrEKCertPlatformIndex
	ErrTPMEKCertKeyType               = tpm2.ErrEKCertKeyType
	ErrTPMNVCertTooLarge              = tpm2.ErrNVCertTooLarge
	ErrTPMNVCertIndexMismatch         = tpm2.ErrNVCertIndexMismatch
	ErrTPMNVCertHierarchyAuth         = tpm2.ErrNVCertHierarchyAuth

	// Platform key store errors
	ErrPlatformKeyStoreNilTPM             = tpm2.ErrPlatformKeyStoreNilTPM
	ErrPlatformKeyStoreNilBackend         = tpm2.ErrPlatformKeyStoreNilBackend
	ErrPlatformKeyStoreNilConfig          = tpm2.ErrPlatformKeyStoreNilConfig
	ErrPlatformKeyStoreAlreadyInitialized = tpm2.ErrPlatformKeyStoreAlreadyInitialized
	ErrPlatformKeyStoreSetSOPIN           = tpm2.ErrPlatformKeyStoreSetSOPIN
	ErrPlatformKeyStoreSetUserPIN         = tpm2.ErrPlatformKeyStoreSetUserPIN
	ErrPlatformKeyStoreCreateSRK          = tpm2.ErrPlatformKeyStoreCreateSRK
	ErrPlatformKeyStoreSRKConfig          = tpm2.ErrPlatformKeyStoreSRKConfig
	ErrPlatformKeyStorePINManager         = tpm2.ErrPlatformKeyStorePINManager
	ErrPlatformSRKAlreadyEnrolled         = tpm2.ErrPlatformSRKAlreadyEnrolled
	ErrPlatformSRKEnrollEmptyPIN          = tpm2.ErrPlatformSRKEnrollEmptyPIN
)

// ---------------------------------------------------------------------------
// Constructor function re-exports
// ---------------------------------------------------------------------------

// NewTPM2 creates a new TPM2 instance.
var NewTPM2 = tpm2.NewTPM2

// OpenUnixSocketTransport opens a connection to a TPM via Unix domain socket.
var OpenUnixSocketTransport = tpm2.OpenUnixSocketTransport

// OpenDeviceTransport opens a raw TPM command channel to a device path or
// Unix domain socket, without the EK discovery NewTPM2 performs. Callers that
// only need a transport.TPMCloser — such as TPM2 NV-backed PIV certificate
// storage — use this instead of standing up a full TrustedPlatformModule.
var OpenDeviceTransport = tpm2.OpenDeviceTransport

// OpenSimulator opens a TPM simulator for testing.
var OpenSimulator = tpm2.OpenSimulator

// NewPlatformKeyStore creates a new PlatformKeyStore with integrated TPM PIN management.
var NewPlatformKeyStore = tpm2.NewPlatformKeyStore

// AttachPlatformKeyStore returns a TPM's PlatformKeyStore, creating and
// attaching one when it has none -- the one path xkmsd and xKey share.
var AttachPlatformKeyStore = tpm2.AttachPlatformKeyStore

// NewPlatformPassword creates a new PlatformPassword for just-in-time TPM password retrieval.
var NewPlatformPassword = tpm2.NewPlatformPassword

// NewProdCaData creates a ProdCaData structure from a Quote.
var NewProdCaData = tpm2.NewProdCaData

// ---------------------------------------------------------------------------
// Config helper function re-exports
// ---------------------------------------------------------------------------

// EKAttributesFromConfig creates EK key attributes from config.
var EKAttributesFromConfig = tpm2.EKAttributesFromConfig

// SRKAttributesFromConfig creates SRK key attributes from config.
var SRKAttributesFromConfig = tpm2.SRKAttributesFromConfig

// IAKAttributesFromConfig creates IAK key attributes from config.
var IAKAttributesFromConfig = tpm2.IAKAttributesFromConfig

// IDevIDAttributesFromConfig creates IDevID key attributes from config.
var IDevIDAttributesFromConfig = tpm2.IDevIDAttributesFromConfig

// DevIDUniqueString returns the unique-field bytes TCG "TPM 2.0 Keys for
// Device Identity and Attestation" v1.00 r12, section 7.3.1 Table 2 requires
// of an IDevID or IAK key template: 'IDEVID' or 'IAK', optionally followed by
// the device's own printable-ASCII string.
var DevIDUniqueString = tpm2.DevIDUniqueString

// DevIDKeyPolicyDigest computes the TCG IDevID/IAK Key Policy (section
// 7.3.6.6) attached as authPolicy to every IDevID and IAK this library
// creates, for a key kind and nameAlg. Pinned to the specification's
// published Tables 14-19.
var DevIDKeyPolicyDigest = tpm2.DevIDKeyPolicyDigest

// DevIDPolicyNVIndex returns the reserved Policy NV Index (section 7.3.2)
// that carries a key kind's Delegation Policy for a nameAlg.
var DevIDPolicyNVIndex = tpm2.DevIDPolicyNVIndex

// DevIDPolicyNVName returns the Name of a key kind's Policy NV Index
// (section 7.3.6.5, Table 18), the value an Owner-defined index must carry
// before anything written into it can delegate the key.
var DevIDPolicyNVName = tpm2.DevIDPolicyNVName

// TPMDevIDDelegation is a Delegation Policy (section 7.3): the digest the
// Privacy Administrator writes into the Policy NV Index and the assertions a
// delegated session runs to reach it. Built by DevIDCommandDelegation,
// DevIDSigningDelegation, DevIDAttestationDelegation or
// (*tpm2.TPM2).DevIDPlatformDelegation; consumed by
// (*tpm2.TPM2).DevIDDelegatedSession and WriteDevIDDelegationPolicy.
type TPMDevIDDelegation = tpm2.DevIDDelegation

// DevIDCommandDelegation builds a Delegation Policy admitting exactly the
// listed commands, satisfied for command.
var DevIDCommandDelegation = tpm2.DevIDCommandDelegation

// DevIDSigningDelegation is the specification's example IDevID Delegation
// Policy (section 7.3.7, Table 20): Sign and Certify.
var DevIDSigningDelegation = tpm2.DevIDSigningDelegation

// DevIDAttestationDelegation is the specification's example IAK Delegation
// Policy (section 7.3.7, Table 20): Quote, GetSessionAuditDigest, Certify
// and ActivateCredential.
var DevIDAttestationDelegation = tpm2.DevIDAttestationDelegation

// DevIDDelegationPolicyPayload returns the TPMT_HA the Policy NV Index
// stores for a Delegation Policy digest: hash algorithm ID, then digest.
var DevIDDelegationPolicyPayload = tpm2.DevIDDelegationPolicyPayload

// DevIDCommonName resolves the Common Name an IDevID or IAK is stored and
// certified under: an explicit cn, else the device's model and serial number,
// else ErrTPMDevIDCNUnresolved.
var DevIDCommonName = tpm2.DevIDCommonName

// LDevIDAttributesFromConfig creates LDevID key attributes from config.
var LDevIDAttributesFromConfig = tpm2.LDevIDAttributesFromConfig

// ---------------------------------------------------------------------------
// CSR pack/unpack function re-exports
// ---------------------------------------------------------------------------

// PackIDevIDCSR serializes a TCG_CSR_IDEVID to a big-endian binary byte array.
var PackIDevIDCSR = tpm2.PackIDevIDCSR

// PackIDevIDContent serializes TCG_IDEVID_CONTENT to a big-endian byte array.
var PackIDevIDContent = tpm2.PackIDevIDContent

// UnmarshalIDevIDCSR deserializes a TCG_CSR_IDEVID from a big-endian byte array.
var UnmarshalIDevIDCSR = tpm2.UnmarshalIDevIDCSR

// MaxIDevIDCSRSize is the largest packed TCG-CSR-IDEVID UnmarshalIDevIDCSR
// accepts.
const MaxIDevIDCSRSize = tpm2.MaxIDevIDCSRSize

// IDevIDCSRTooLargeError is returned when a packed TCG-CSR-IDEVID exceeds
// MaxIDevIDCSRSize.
type IDevIDCSRTooLargeError = tpm2.IDevIDCSRTooLargeError

// IDevIDCSRFieldSizeError is returned when a TCG-CSR-IDEVID length field
// declares more bytes than remain in the message.
type IDevIDCSRFieldSizeError = tpm2.IDevIDCSRFieldSizeError

// UnpackIDevIDContent deserializes TCG_IDEVID_CONTENT from a bytes.Reader.
var UnpackIDevIDContent = tpm2.UnpackIDevIDContent

// UnpackIDevIDCSR unpacks a TCG_CSR_IDEVID into its native Go representation.
var UnpackIDevIDCSR = tpm2.UnpackIDevIDCSR

// PackProdCaData serializes a ProdCaData structure.
var PackProdCaData = tpm2.PackProdCaData

// UnpackProdCaData deserializes a ProdCaData structure.
var UnpackProdCaData = tpm2.UnpackProdCaData

// ---------------------------------------------------------------------------
// Stateless server-side CSR verification function re-exports
// ---------------------------------------------------------------------------

// AssertDevIDKeyConformant refuses a public area carried in a TCG-CSR-IDEVID
// whose attributes or policy are not those TCG DevID v1 r12 §4 and §7.3.4.1
// require of an IDevID or IAK.
var AssertDevIDKeyConformant = tpm2.AssertDevIDKeyConformant

// VerifyTCG_CSR_IDevID_Stateless verifies a TCG-CSR-IDEVID without TPM access.
var VerifyTCG_CSR_IDevID_Stateless = tpm2.VerifyTCG_CSR_IDevID_Stateless

// VerifyTCG_CSR_IAK_Stateless verifies a TCG-CSR-IDEVID using IAK strategy without TPM access.
var VerifyTCG_CSR_IAK_Stateless = tpm2.VerifyTCG_CSR_IAK_Stateless

// VerifyTCG_CSR_IDevID is a convenience wrapper for VerifyTCG_CSR_IDevID_Stateless.
var VerifyTCG_CSR_IDevID = tpm2.VerifyTCG_CSR_IDevID

// VerifyTCG_CSR_IAK is a convenience wrapper for VerifyTCG_CSR_IAK_Stateless.
var VerifyTCG_CSR_IAK = tpm2.VerifyTCG_CSR_IAK

// ExtractPublicKeyFromTPMPublic extracts a crypto.PublicKey from TPM public area bytes.
var ExtractPublicKeyFromTPMPublic = tpm2.ExtractPublicKeyFromTPMPublic

// ---------------------------------------------------------------------------
// Certificate conversion function re-exports
// ---------------------------------------------------------------------------

// CertificateToTPMPublic converts an X.509 certificate's public key to a TPM public structure.
var CertificateToTPMPublic = tpm2.CertificateToTPMPublic

// ---------------------------------------------------------------------------
// TPM name and hash function re-exports
// ---------------------------------------------------------------------------

// CalculateName calculates the key name of the provided public area.
var CalculateName = tpm2.CalculateName

// HierarchyName returns the human-readable name of a TPM hierarchy.
var HierarchyName = tpm2.HierarchyName

// ParseHashAlg converts a crypto.Hash to a TPM hash algorithm ID.
var ParseHashAlg = tpm2.ParseHashAlg

// ParseHashAlgFromString converts a string hash name to a TPM hash algorithm ID.
var ParseHashAlgFromString = tpm2.ParseHashAlgFromString

// ParseHashSize returns the digest size for a crypto.Hash.
var ParseHashSize = tpm2.ParseHashSize

// ParseCryptoHashAlgID converts a crypto.Hash to a TPM algorithm ID.
var ParseCryptoHashAlgID = tpm2.ParseCryptoHashAlgID

// ---------------------------------------------------------------------------
// Hierarchy and enrollment parsing function re-exports
// ---------------------------------------------------------------------------

// ParseHierarchy parses a hierarchy type string to a TPM hierarchy.
var ParseHierarchy = tpm2.ParseHierarchy

// ParseIdentityProvisioningStrategy parses the identity provisioning strategy.
var ParseIdentityProvisioningStrategy = tpm2.ParseIdentityProvisioningStrategy

// ParsePCRBankAlgID parses a PCR bank string to a TPM algorithm ID.
var ParsePCRBankAlgID = tpm2.ParsePCRBankAlgID

// ParsePCRBankCryptoHash parses a PCR bank string to a crypto.Hash.
var ParsePCRBankCryptoHash = tpm2.ParsePCRBankCryptoHash

// ---------------------------------------------------------------------------
// Encoding function re-exports
// ---------------------------------------------------------------------------

// TPMEncode encodes bytes to hexadecimal form.
var TPMEncode = tpm2.Encode

// TPMDecode decodes hexadecimal form to a byte array.
var TPMDecode = tpm2.Decode

// EncodeQuote encodes a Quote to binary using gob.
var EncodeQuote = tpm2.EncodeQuote

// DecodeQuote decodes a Quote from binary using gob.
var DecodeQuote = tpm2.DecodeQuote

// EncodePCRs encodes a PCR bank slice to binary using gob.
var EncodePCRs = tpm2.EncodePCRs

// DecodePCRs decodes a PCR bank slice from binary using gob.
var DecodePCRs = tpm2.DecodePCRs

// ---------------------------------------------------------------------------
// Event log function re-exports
// ---------------------------------------------------------------------------

// ParseEventLog parses a TPM binary event log file.
var ParseEventLog = tpm2.ParseEventLog

// ParseEventLogWithOptions parses a TPM binary event log with custom options.
var ParseEventLogWithOptions = tpm2.ParseEventLogWithOptions

// DefaultParseEventLogOptions returns default event log parsing options.
var DefaultParseEventLogOptions = tpm2.DefaultParseEventLogOptions

// CalculatePCRs computes PCR values from parsed events.
var CalculatePCRs = tpm2.CalculatePCRs

// InitializePCRs returns initial (all-zero) PCR state.
var InitializePCRs = tpm2.InitializePCRs

// GetHashFunction returns the hash.Hash for a given algorithm ID string.
var GetHashFunction = tpm2.GetHashFunction

// ExtendPCR extends a PCR value with a digest.
var TPMExtendPCR = tpm2.ExtendPCR

// GetDigestSize returns the digest size for a given algorithm ID string.
var GetDigestSize = tpm2.GetDigestSize

// PrintEvents prints parsed TPM events to stdout.
var PrintEvents = tpm2.PrintEvents

// ---------------------------------------------------------------------------
// Platform discovery function re-exports
// ---------------------------------------------------------------------------

// DiscoverPlatformAttributes reads platform attributes from SMBIOS/DMI.
var DiscoverPlatformAttributes = tpm2.DiscoverPlatformAttributes

// ResolvePlatformAttributes resolves platform attributes with config-first-then-SMBIOS fallback.
var ResolvePlatformAttributes = tpm2.ResolvePlatformAttributes

// ---------------------------------------------------------------------------
// Version function re-exports
// ---------------------------------------------------------------------------

// VersionStringToInt64 converts a TPM firmware version string to int64.
var VersionStringToInt64 = tpm2.VersionStringToInt64

// Int64ToVersionComponents converts an int64 back to major and minor version components.
var Int64ToVersionComponents = tpm2.Int64ToVersionComponents

// ---------------------------------------------------------------------------
// Policy function re-exports
// ---------------------------------------------------------------------------

// PCRDigestSize returns the hash digest size for the given PCR bank.
var PCRDigestSize = tpm2.PCRDigestSize

// EncodePCRSelection encodes a TPML_PCR_SELECTION structure.
var EncodePCRSelection = tpm2.EncodePCRSelection

// ComputePolicyPCRDigest computes a TPM2 PolicyPCR digest.
var ComputePolicyPCRDigest = tpm2.ComputePolicyPCRDigest

// ---------------------------------------------------------------------------
// TPM public area marshal/unmarshal re-exports
// ---------------------------------------------------------------------------

// UnmarshalPublic deserializes a TPMTPublic structure from bytes.
var UnmarshalPublic = tpm2.UnmarshalPublic

// MarshalPublic serializes a TPMTPublic structure to bytes.
var MarshalPublic = tpm2.MarshalPublic

// OpenTPMDevice opens the TPM character device at path for reading and
// writing. It refuses a hardware TPM inside a test binary that has not opted
// in, so no test can reach the host's TPM by accident.
var OpenTPMDevice = tpmdev.Open

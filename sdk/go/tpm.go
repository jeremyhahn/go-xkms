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
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
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
type PINBackend = pin.PINBackend

// PINManager is the legacy interface for PIN management operations.
//
// Deprecated: Use PINBackend for backend implementations and pin.Service as
// the entry point.
type PINManager = pin.PINManager //nolint:staticcheck // TODO: migrate to PINBackend

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

// LDevIDConfig holds Local Device Identifier configuration.
type LDevIDConfig = tpm2.LDevIDConfig

// LAKConfig holds Local Attestation Key configuration.
type LAKConfig = tpm2.LAKConfig

// PlatformSRKConfig holds Platform Storage Root Key configuration.
type PlatformSRKConfig = tpm2.PlatformSRKConfig

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

// TPMBlobStorer provides binary blob storage for TPM operations.
type TPMBlobStorer = store.BlobStorer

// TPMCertificateStorer provides certificate storage operations for TPM.
type TPMCertificateStorer = store.CertificateStorer

// TPMSignerStorer provides crypto.Signer storage operations for TPM.
type TPMSignerStorer = store.SignerStorer

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

// NewFileBackend creates a new file-based key backend.
var NewFileBackend = store.NewFileBackend

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

	// ECCAKP256Template is the ECC P-256 Attestation Key template.
	ECCAKP256Template = tpm2.ECCAKP256Template

	// RSASSAIDevIDTemplate is the RSA-SSA IDevID key template.
	RSASSAIDevIDTemplate = tpm2.RSASSAIDevIDTemplate

	// RSAPSSIDevIDTemplate is the RSA-PSS IDevID key template.
	RSAPSSIDevIDTemplate = tpm2.RSAPSSIDevIDTemplate

	// ECCIDevIDP256Template is the ECC P-256 IDevID key template.
	ECCIDevIDP256Template = tpm2.ECCIDevIDP256Template

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
	ErrTPMInvalidHierarchy            = tpm2.ErrInvalidHierarchy
	ErrTPMFactoryReset                = tpm2.ErrFactoryReset
	ErrTPMEKConfigNil                 = tpm2.ErrEKConfigNil
	ErrTPMIAKConfigNil                = tpm2.ErrIAKConfigNil
	ErrTPMIDevIDConfigNil             = tpm2.ErrIDevIDConfigNil
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
)

// ---------------------------------------------------------------------------
// Constructor function re-exports
// ---------------------------------------------------------------------------

// NewTPM2 creates a new TPM2 instance.
var NewTPM2 = tpm2.NewTPM2

// OpenUnixSocketTransport opens a connection to a TPM via Unix domain socket.
var OpenUnixSocketTransport = tpm2.OpenUnixSocketTransport

// OpenSimulator opens a TPM simulator for testing.
var OpenSimulator = tpm2.OpenSimulator

// NewPlatformKeyStore creates a new PlatformKeyStore with integrated TPM PIN management.
var NewPlatformKeyStore = tpm2.NewPlatformKeyStore

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

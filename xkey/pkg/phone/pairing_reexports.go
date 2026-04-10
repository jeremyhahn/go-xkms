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

package phone

import (
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// ============================================================================
// Type aliases for pairing types.
// These maintain backward compatibility for consumers that reference phone.X.
// ============================================================================

// Noise session types.
type NoiseSession = pairing.NoiseSession
type NoiseSessionConfig = pairing.NoiseSessionConfig

// Handshake types.
type HandshakeConfig = pairing.HandshakeConfig

// Message routing types.
type RequestHandler = pairing.RequestHandler
type MessageRouter = pairing.MessageRouter
type BiometricPendingHandler = pairing.BiometricPendingHandler

// JSON-RPC protocol types.
type Request = pairing.Request
type Response = pairing.Response
type RPCError = pairing.RPCError

// Core protocol result/param types.
type GenerateKeyParams = pairing.GenerateKeyParams
type GenerateKeyResult = pairing.GenerateKeyResult
type SignParams = pairing.SignParams
type SignResult = pairing.SignResult
type DeleteKeyParams = pairing.DeleteKeyParams
type DeleteKeyResult = pairing.DeleteKeyResult
type LoadKeyParams = pairing.LoadKeyParams
type LoadKeyResult = pairing.LoadKeyResult
type GetInfoResult = pairing.GetInfoResult
type PingResult = pairing.PingResult
type PairingConfirmParams = pairing.PairingConfirmParams
type PairingConfirmResult = pairing.PairingConfirmResult

// Local protocol types.
type LocalGenerateKeyParams = pairing.LocalGenerateKeyParams
type LocalGenerateKeyResult = pairing.LocalGenerateKeyResult
type LocalSignParams = pairing.LocalSignParams
type LocalSignResult = pairing.LocalSignResult
type LocalDecryptParams = pairing.LocalDecryptParams
type LocalDecryptResult = pairing.LocalDecryptResult
type LocalSymmetricEncryptParams = pairing.LocalSymmetricEncryptParams
type LocalSymmetricEncryptResult = pairing.LocalSymmetricEncryptResult
type LocalSymmetricDecryptParams = pairing.LocalSymmetricDecryptParams
type LocalSymmetricDecryptResult = pairing.LocalSymmetricDecryptResult
type LocalHMACParams = pairing.LocalHMACParams
type LocalHMACResult = pairing.LocalHMACResult
type LocalECDHParams = pairing.LocalECDHParams
type LocalECDHResult = pairing.LocalECDHResult
type LocalGetPublicKeyParams = pairing.LocalGetPublicKeyParams
type LocalGetPublicKeyResult = pairing.LocalGetPublicKeyResult
type LocalListKeysParams = pairing.LocalListKeysParams
type KeyInfo = pairing.KeyInfo
type LocalListKeysResult = pairing.LocalListKeysResult
type LocalGetKeyInfoParams = pairing.LocalGetKeyInfoParams
type LocalGetKeyInfoResult = pairing.LocalGetKeyInfoResult
type LocalDeleteKeyParams = pairing.LocalDeleteKeyParams
type LocalDeleteKeyResult = pairing.LocalDeleteKeyResult
type LocalSetKeyPolicyParams = pairing.LocalSetKeyPolicyParams
type LocalSetKeyPolicyResult = pairing.LocalSetKeyPolicyResult
type LocalAttestKeyParams = pairing.LocalAttestKeyParams
type LocalAttestKeyResult = pairing.LocalAttestKeyResult
type LocalAttestDeviceParams = pairing.LocalAttestDeviceParams
type LocalAttestDeviceResult = pairing.LocalAttestDeviceResult
type Fido2CredentialInfo = pairing.Fido2CredentialInfo
type LocalListFido2CredentialsParams = pairing.LocalListFido2CredentialsParams
type LocalListFido2CredentialsResult = pairing.LocalListFido2CredentialsResult
type LocalSignFido2AssertionParams = pairing.LocalSignFido2AssertionParams
type LocalSignFido2AssertionResult = pairing.LocalSignFido2AssertionResult

// Remote protocol types.
type BackendInfo = pairing.BackendInfo
type RemoteListBackendsResult = pairing.RemoteListBackendsResult
type RemoteListKeysParams = pairing.RemoteListKeysParams
type RemoteKeyInfo = pairing.RemoteKeyInfo
type RemoteListKeysResult = pairing.RemoteListKeysResult
type RemoteGetPublicKeyParams = pairing.RemoteGetPublicKeyParams
type RemoteGetPublicKeyResult = pairing.RemoteGetPublicKeyResult
type RemoteSignParams = pairing.RemoteSignParams
type RemoteSignResult = pairing.RemoteSignResult
type RemoteVerifyParams = pairing.RemoteVerifyParams
type RemoteVerifyResult = pairing.RemoteVerifyResult
type RemoteEncryptParams = pairing.RemoteEncryptParams
type RemoteEncryptResult = pairing.RemoteEncryptResult
type RemoteDecryptParams = pairing.RemoteDecryptParams
type RemoteDecryptResult = pairing.RemoteDecryptResult
type RemoteDeriveKeyParams = pairing.RemoteDeriveKeyParams
type RemoteDeriveKeyResult = pairing.RemoteDeriveKeyResult
type RemoteGenerateKeyParams = pairing.RemoteGenerateKeyParams
type RemoteGenerateKeyResult = pairing.RemoteGenerateKeyResult
type RemoteGetKeyInfoParams = pairing.RemoteGetKeyInfoParams
type RemoteGetKeyInfoResult = pairing.RemoteGetKeyInfoResult
type RemoteDeleteKeyParams = pairing.RemoteDeleteKeyParams
type RemoteDeleteKeyResult = pairing.RemoteDeleteKeyResult
type RemoteAttestKeyParams = pairing.RemoteAttestKeyParams
type RemoteAttestKeyResult = pairing.RemoteAttestKeyResult
type RemoteAttestDeviceParams = pairing.RemoteAttestDeviceParams
type RemoteAttestDeviceResult = pairing.RemoteAttestDeviceResult
type RemoteGetTCGCSRIDevIDParams = pairing.RemoteGetTCGCSRIDevIDParams
type RemoteGetTCGCSRIDevIDResult = pairing.RemoteGetTCGCSRIDevIDResult

// Sharing protocol types.
type LocalSharePublicKeyParams = pairing.LocalSharePublicKeyParams
type LocalSharePublicKeyResult = pairing.LocalSharePublicKeyResult
type RemoteSharePublicKeyParams = pairing.RemoteSharePublicKeyParams
type RemoteSharePublicKeyResult = pairing.RemoteSharePublicKeyResult
type LocalShareSymmetricParams = pairing.LocalShareSymmetricParams
type LocalShareSymmetricResult = pairing.LocalShareSymmetricResult
type RemoteShareSymmetricParams = pairing.RemoteShareSymmetricParams
type RemoteShareSymmetricResult = pairing.RemoteShareSymmetricResult
type LocalImportSharedKeyParams = pairing.LocalImportSharedKeyParams
type LocalImportSharedKeyResult = pairing.LocalImportSharedKeyResult
type RemoteImportSharedKeyParams = pairing.RemoteImportSharedKeyParams
type RemoteImportSharedKeyResult = pairing.RemoteImportSharedKeyResult

// Backup protocol types.
type LocalCreateBackupParams = pairing.LocalCreateBackupParams
type LocalCreateBackupResult = pairing.LocalCreateBackupResult
type LocalRestoreBackupParams = pairing.LocalRestoreBackupParams
type LocalRestoreBackupResult = pairing.LocalRestoreBackupResult
type RemoteCreateBackupParams = pairing.RemoteCreateBackupParams
type RemoteCreateBackupResult = pairing.RemoteCreateBackupResult
type RemoteRestoreBackupParams = pairing.RemoteRestoreBackupParams
type RemoteRestoreBackupResult = pairing.RemoteRestoreBackupResult
type RemoteListBackupsParams = pairing.RemoteListBackupsParams
type RemoteListBackupsResult = pairing.RemoteListBackupsResult
type BackupInfo = pairing.BackupInfo

// OATH protocol types.
type OATHCredentialInfo = pairing.OATHCredentialInfo
type LocalOATHAddParams = pairing.LocalOATHAddParams
type LocalOATHAddResult = pairing.LocalOATHAddResult
type LocalOATHListParams = pairing.LocalOATHListParams
type LocalOATHListResult = pairing.LocalOATHListResult
type LocalOATHGenerateParams = pairing.LocalOATHGenerateParams
type LocalOATHGenerateResult = pairing.LocalOATHGenerateResult
type LocalOATHRemoveParams = pairing.LocalOATHRemoveParams
type LocalOATHRemoveResult = pairing.LocalOATHRemoveResult
type RemoteOATHAddParams = pairing.RemoteOATHAddParams
type RemoteOATHAddResult = pairing.RemoteOATHAddResult
type RemoteOATHGenerateParams = pairing.RemoteOATHGenerateParams
type RemoteOATHGenerateResult = pairing.RemoteOATHGenerateResult

// PIV protocol types.
type PIVSlotInfo = pairing.PIVSlotInfo
type LocalPIVGenerateKeyParams = pairing.LocalPIVGenerateKeyParams
type LocalPIVGenerateKeyResult = pairing.LocalPIVGenerateKeyResult
type LocalPIVImportCertParams = pairing.LocalPIVImportCertParams
type LocalPIVImportCertResult = pairing.LocalPIVImportCertResult
type LocalPIVListSlotsParams = pairing.LocalPIVListSlotsParams
type LocalPIVListSlotsResult = pairing.LocalPIVListSlotsResult
type LocalPIVSignParams = pairing.LocalPIVSignParams
type LocalPIVSignResult = pairing.LocalPIVSignResult
type LocalPIVGetCertParams = pairing.LocalPIVGetCertParams
type LocalPIVGetCertResult = pairing.LocalPIVGetCertResult
type RemotePIVListSlotsParams = pairing.RemotePIVListSlotsParams
type RemotePIVListSlotsResult = pairing.RemotePIVListSlotsResult
type RemotePIVSignParams = pairing.RemotePIVSignParams
type RemotePIVSignResult = pairing.RemotePIVSignResult
type RemotePIVGetCertParams = pairing.RemotePIVGetCertParams
type RemotePIVGetCertResult = pairing.RemotePIVGetCertResult

// Sync protocol types.
type SyncCertificate = pairing.SyncCertificate
type SyncOATHCredential = pairing.SyncOATHCredential
type SyncPassword = pairing.SyncPassword
type LocalSyncTrustStoreParams = pairing.LocalSyncTrustStoreParams
type LocalSyncTrustStoreResult = pairing.LocalSyncTrustStoreResult
type LocalSyncOATHParams = pairing.LocalSyncOATHParams
type LocalSyncOATHResult = pairing.LocalSyncOATHResult
type LocalSyncPasswordsParams = pairing.LocalSyncPasswordsParams
type LocalSyncPasswordsResult = pairing.LocalSyncPasswordsResult
type LocalSyncStatusParams = pairing.LocalSyncStatusParams
type LocalSyncStatusResult = pairing.LocalSyncStatusResult
type RemoteSyncTrustStoreParams = pairing.RemoteSyncTrustStoreParams
type RemoteSyncTrustStoreResult = pairing.RemoteSyncTrustStoreResult
type RemoteSyncOATHParams = pairing.RemoteSyncOATHParams
type RemoteSyncOATHResult = pairing.RemoteSyncOATHResult
type RemoteSyncPasswordsParams = pairing.RemoteSyncPasswordsParams
type RemoteSyncPasswordsResult = pairing.RemoteSyncPasswordsResult
type RemoteSyncAllParams = pairing.RemoteSyncAllParams
type RemoteSyncAllResult = pairing.RemoteSyncAllResult

// IDevID protocol types.
type LocalGetCABundleParams = pairing.LocalGetCABundleParams
type LocalGetCABundleResult = pairing.LocalGetCABundleResult
type LocalGetIDevIDCertificateParams = pairing.LocalGetIDevIDCertificateParams
type LocalGetIDevIDCertificateResult = pairing.LocalGetIDevIDCertificateResult
type LocalRequestIDevIDIssuanceParams = pairing.LocalRequestIDevIDIssuanceParams
type LocalRequestIDevIDIssuanceResult = pairing.LocalRequestIDevIDIssuanceResult
type LocalGenerateIDevIDCSRParams = pairing.LocalGenerateIDevIDCSRParams
type LocalGenerateIDevIDCSRResult = pairing.LocalGenerateIDevIDCSRResult
type LocalStoreIDevIDCertificateParams = pairing.LocalStoreIDevIDCertificateParams
type LocalStoreIDevIDCertificateResult = pairing.LocalStoreIDevIDCertificateResult
type IDevIDCertificateInfo = pairing.IDevIDCertificateInfo
type IDevIDSubject = pairing.IDevIDSubject

// Attestation protocol types.
type LocalGetTCGCSRIDevIDResult = pairing.LocalGetTCGCSRIDevIDResult
type LocalActivateCredentialParams = pairing.LocalActivateCredentialParams
type LocalActivateCredentialResult = pairing.LocalActivateCredentialResult
type LocalGetAttestationQuoteParams = pairing.LocalGetAttestationQuoteParams
type LocalGetAttestationQuoteResult = pairing.LocalGetAttestationQuoteResult
type LocalGetIAKPublicKeyResult = pairing.LocalGetIAKPublicKeyResult
type LocalStoreEnrollmentCertsParams = pairing.LocalStoreEnrollmentCertsParams
type LocalStoreEnrollmentCertsResult = pairing.LocalStoreEnrollmentCertsResult

// Attestation types.
type AttestationMode = pairing.AttestationMode
type LaptopAttestor = pairing.LaptopAttestor
type LaptopAttestorConfig = pairing.LaptopAttestorConfig

// Fragmentation types.
type Fragmenter = pairing.Fragmenter
type Reassembler = pairing.Reassembler
type Fragment = pairing.Fragment

// Bridge types.
type Bridge = pairing.Bridge
type BridgeConfig = pairing.BridgeConfig

// Sharing policy types.
type SharingPolicy = pairing.SharingPolicy
type SharingPolicyStore = pairing.SharingPolicyStore
type FileSharingPolicyStore = pairing.FileSharingPolicyStore

// PairedDevice types from pairing package.
type PairedDevice = pairing.PairedDevice
type DeviceType = pairing.DeviceType
type AttestationPolicy = pairing.AttestationPolicy

// TCP pairing server types from the pairing package are NOT re-exported here.
// The phone package defines its own TCPPairingServer and TCPPairingConfig in
// tcp_server.go, which use PeripheralRequestHandler ([]byte in, []byte out)
// instead of the pairing package's RequestHandler (*Request in, *Response out).

// ============================================================================
// Function re-exports for backward compatibility.
// ============================================================================

// NewNoiseSession creates a new Noise protocol session.
var NewNoiseSession = pairing.NewNoiseSession

// GenerateStaticKey generates a new Noise static key pair.
var GenerateStaticKey = pairing.GenerateStaticKey

// LoadStaticKey loads a Noise static key from a private key.
var LoadStaticKey = pairing.LoadStaticKey

// EncodeStaticKey encodes a Noise static key.
var EncodeStaticKey = pairing.EncodeStaticKey

// DecodeStaticKey decodes a Noise static key.
var DecodeStaticKey = pairing.DecodeStaticKey

// PerformHandshake performs the Noise XX handshake.
var PerformHandshake = pairing.PerformHandshake

// NewMessageRouter creates a new bidirectional message router.
var NewMessageRouter = pairing.NewMessageRouter

// NewMessageRouterWithNotifier creates a message router with biometric notifications.
var NewMessageRouterWithNotifier = pairing.NewMessageRouterWithNotifier

// NewRequest creates a new JSON-RPC request.
var NewRequest = pairing.NewRequest

// EncodeRequest encodes a JSON-RPC request.
var EncodeRequest = pairing.EncodeRequest

// DecodeRequest decodes a JSON-RPC request.
var DecodeRequest = pairing.DecodeRequest

// DecodeResponse decodes a JSON-RPC response.
var DecodeResponse = pairing.DecodeResponse

// EncodeResponse encodes a JSON-RPC response.
var EncodeResponse = pairing.EncodeResponse

// EncodeErrorResponse encodes a JSON-RPC error response.
var EncodeErrorResponse = pairing.EncodeErrorResponse

// MapRPCError maps a JSON-RPC error to a package error.
var MapRPCError = pairing.MapRPCError

// NewBridge creates a new Bridge.
var NewBridge = pairing.NewBridge

// DefaultBridgeConfig returns the default bridge configuration.
var DefaultBridgeConfig = pairing.DefaultBridgeConfig

// NewFragmenter creates a new message fragmenter.
var NewFragmenter = pairing.NewFragmenter

// NewReassembler creates a new message reassembler.
var NewReassembler = pairing.NewReassembler

// DecodeFragment decodes a fragment from bytes.
var DecodeFragment = pairing.DecodeFragment

// NewFileSharingPolicyStore creates a new file-backed sharing policy store.
var NewFileSharingPolicyStore = pairing.NewFileSharingPolicyStore

// NewLaptopAttestor creates a new laptop attestor.
var NewLaptopAttestor = pairing.NewLaptopAttestor

// ParseAttestationMode parses an attestation mode string.
var ParseAttestationMode = pairing.ParseAttestationMode

// IsAttestationMethod checks if a method name is an attestation method.
var IsAttestationMethod = pairing.IsAttestationMethod

// IsBackupLocalMethod checks if a method is a local backup method.
var IsBackupLocalMethod = pairing.IsBackupLocalMethod

// IsBackupRemoteMethod checks if a method is a remote backup method.
var IsBackupRemoteMethod = pairing.IsBackupRemoteMethod

// IsSharingLocalMethod checks if a method is a local sharing method.
var IsSharingLocalMethod = pairing.IsSharingLocalMethod

// IsSharingRemoteMethod checks if a method is a remote sharing method.
var IsSharingRemoteMethod = pairing.IsSharingRemoteMethod

// IsOATHLocalMethod checks if a method is a local OATH method.
var IsOATHLocalMethod = pairing.IsOATHLocalMethod

// IsOATHRemoteMethod checks if a method is a remote OATH method.
var IsOATHRemoteMethod = pairing.IsOATHRemoteMethod

// IsPIVLocalMethod checks if a method is a local PIV method.
var IsPIVLocalMethod = pairing.IsPIVLocalMethod

// IsPIVRemoteMethod checks if a method is a remote PIV method.
var IsPIVRemoteMethod = pairing.IsPIVRemoteMethod

// IsIDevIDMethod checks if a method is an IDevID method.
var IsIDevIDMethod = pairing.IsIDevIDMethod

// DecodeResult is a generic function that cannot be re-exported as a var.
// It wraps pairing.DecodeResult for backward compatibility.
func DecodeResult[T any](resp *pairing.Response) (*T, error) {
	return pairing.DecodeResult[T](resp)
}

// ============================================================================
// Constant re-exports for backward compatibility.
// ============================================================================

// Noise protocol constants.
const NoiseKeySize = pairing.NoiseKeySize

const MinMTU = pairing.MinMTU

// JSON-RPC version.
const JSONRPCVersion = pairing.JSONRPCVersion

// Method name re-exports.
const (
	MethodGenerateKey    = pairing.MethodGenerateKey
	MethodSign           = pairing.MethodSign
	MethodDeleteKey      = pairing.MethodDeleteKey
	MethodLoadKey        = pairing.MethodLoadKey
	MethodGetInfo        = pairing.MethodGetInfo
	MethodPing           = pairing.MethodPing
	MethodPairingConfirm = pairing.MethodPairingConfirm
)

// Local method name re-exports.
const (
	MethodLocalGenerateKey          = pairing.MethodLocalGenerateKey
	MethodLocalSign                 = pairing.MethodLocalSign
	MethodLocalDecrypt              = pairing.MethodLocalDecrypt
	MethodLocalSymmetricEncrypt     = pairing.MethodLocalSymmetricEncrypt
	MethodLocalSymmetricDecrypt     = pairing.MethodLocalSymmetricDecrypt
	MethodLocalHMAC                 = pairing.MethodLocalHMAC
	MethodLocalECDH                 = pairing.MethodLocalECDH
	MethodLocalGetPublicKey         = pairing.MethodLocalGetPublicKey
	MethodLocalListKeys             = pairing.MethodLocalListKeys
	MethodLocalGetKeyInfo           = pairing.MethodLocalGetKeyInfo
	MethodLocalDeleteKey            = pairing.MethodLocalDeleteKey
	MethodLocalSetKeyPolicy         = pairing.MethodLocalSetKeyPolicy
	MethodLocalAttestKey            = pairing.MethodLocalAttestKey
	MethodLocalAttestDevice         = pairing.MethodLocalAttestDevice
	MethodLocalListFido2Credentials = pairing.MethodLocalListFido2Credentials
	MethodLocalSignFido2Assertion   = pairing.MethodLocalSignFido2Assertion
)

// Remote method name re-exports.
const (
	MethodRemoteListBackends    = pairing.MethodRemoteListBackends
	MethodRemoteListKeys        = pairing.MethodRemoteListKeys
	MethodRemoteGetPublicKey    = pairing.MethodRemoteGetPublicKey
	MethodRemoteSign            = pairing.MethodRemoteSign
	MethodRemoteVerify          = pairing.MethodRemoteVerify
	MethodRemoteEncrypt         = pairing.MethodRemoteEncrypt
	MethodRemoteDecrypt         = pairing.MethodRemoteDecrypt
	MethodRemoteDeriveKey       = pairing.MethodRemoteDeriveKey
	MethodRemoteGenerateKey     = pairing.MethodRemoteGenerateKey
	MethodRemoteGetKeyInfo      = pairing.MethodRemoteGetKeyInfo
	MethodRemoteDeleteKey       = pairing.MethodRemoteDeleteKey
	MethodRemoteAttestKey       = pairing.MethodRemoteAttestKey
	MethodRemoteAttestDevice    = pairing.MethodRemoteAttestDevice
	MethodRemoteGetTCGCSRIDevID = pairing.MethodRemoteGetTCGCSRIDevID
)

// Sharing method name re-exports.
const (
	MethodLocalSharePublicKey   = pairing.MethodLocalSharePublicKey
	MethodLocalShareSymmetric   = pairing.MethodLocalShareSymmetric
	MethodLocalImportSharedKey  = pairing.MethodLocalImportSharedKey
	MethodRemoteSharePublicKey  = pairing.MethodRemoteSharePublicKey
	MethodRemoteShareSymmetric  = pairing.MethodRemoteShareSymmetric
	MethodRemoteImportSharedKey = pairing.MethodRemoteImportSharedKey
)

// Backup method name re-exports.
const (
	MethodLocalCreateBackup   = pairing.MethodLocalCreateBackup
	MethodLocalRestoreBackup  = pairing.MethodLocalRestoreBackup
	MethodRemoteCreateBackup  = pairing.MethodRemoteCreateBackup
	MethodRemoteRestoreBackup = pairing.MethodRemoteRestoreBackup
	MethodRemoteListBackups   = pairing.MethodRemoteListBackups
)

// OATH method name re-exports.
const (
	MethodLocalOATHAdd       = pairing.MethodLocalOATHAdd
	MethodLocalOATHList      = pairing.MethodLocalOATHList
	MethodLocalOATHGenerate  = pairing.MethodLocalOATHGenerate
	MethodLocalOATHRemove    = pairing.MethodLocalOATHRemove
	MethodRemoteOATHAdd      = pairing.MethodRemoteOATHAdd
	MethodRemoteOATHGenerate = pairing.MethodRemoteOATHGenerate
)

// PIV method name re-exports.
const (
	MethodLocalPIVGenerateKey = pairing.MethodLocalPIVGenerateKey
	MethodLocalPIVImportCert  = pairing.MethodLocalPIVImportCert
	MethodLocalPIVListSlots   = pairing.MethodLocalPIVListSlots
	MethodLocalPIVSign        = pairing.MethodLocalPIVSign
	MethodLocalPIVGetCert     = pairing.MethodLocalPIVGetCert
	MethodRemotePIVListSlots  = pairing.MethodRemotePIVListSlots
	MethodRemotePIVSign       = pairing.MethodRemotePIVSign
	MethodRemotePIVGetCert    = pairing.MethodRemotePIVGetCert
)

// IDevID method name re-exports.
const (
	MethodLocalGetCABundle            = pairing.MethodLocalGetCABundle
	MethodLocalGetIDevIDCertificate   = pairing.MethodLocalGetIDevIDCertificate
	MethodLocalRequestIDevIDIssuance  = pairing.MethodLocalRequestIDevIDIssuance
	MethodLocalGenerateIDevIDCSR      = pairing.MethodLocalGenerateIDevIDCSR
	MethodLocalStoreIDevIDCertificate = pairing.MethodLocalStoreIDevIDCertificate
)

// Sync method name re-exports.
const (
	MethodLocalSyncTrustStore  = pairing.MethodLocalSyncTrustStore
	MethodLocalSyncOATH        = pairing.MethodLocalSyncOATH
	MethodLocalSyncPasswords   = pairing.MethodLocalSyncPasswords
	MethodLocalSyncStatus      = pairing.MethodLocalSyncStatus
	MethodRemoteSyncTrustStore = pairing.MethodRemoteSyncTrustStore
	MethodRemoteSyncOATH       = pairing.MethodRemoteSyncOATH
	MethodRemoteSyncPasswords  = pairing.MethodRemoteSyncPasswords
	MethodRemoteSyncAll        = pairing.MethodRemoteSyncAll
)

// Attestation protocol method name re-exports.
const (
	MethodLocalGetTCGCSRIDevID      = pairing.MethodLocalGetTCGCSRIDevID
	MethodLocalActivateCredential   = pairing.MethodLocalActivateCredential
	MethodLocalGetAttestationQuote  = pairing.MethodLocalGetAttestationQuote
	MethodLocalGetIAKPublicKey      = pairing.MethodLocalGetIAKPublicKey
	MethodLocalStoreEnrollmentCerts = pairing.MethodLocalStoreEnrollmentCerts
)

// Error code re-exports.
const (
	ErrorCodeParseError     = pairing.ErrorCodeParseError
	ErrorCodeInvalidRequest = pairing.ErrorCodeInvalidRequest
	ErrorCodeMethodNotFound = pairing.ErrorCodeMethodNotFound
	ErrorCodeInvalidParams  = pairing.ErrorCodeInvalidParams
	ErrorCodeInternalError  = pairing.ErrorCodeInternalError

	ErrorCodeKeyNotFound        = pairing.ErrorCodeKeyNotFound
	ErrorCodeUserCancelled      = pairing.ErrorCodeUserCancelled
	ErrorCodeBiometricFailed    = pairing.ErrorCodeBiometricFailed
	ErrorCodeKeyExists          = pairing.ErrorCodeKeyExists
	ErrorCodeUnsupportedAlg     = pairing.ErrorCodeUnsupportedAlg
	ErrorCodeInvalidCredID      = pairing.ErrorCodeInvalidCredID
	ErrorCodeStorageFull        = pairing.ErrorCodeStorageFull
	ErrorCodeOperationTimeout   = pairing.ErrorCodeOperationTimeout
	ErrorCodeBackendDenied      = pairing.ErrorCodeBackendDenied
	ErrorCodeAttestFailed       = pairing.ErrorCodeAttestFailed
	ErrorCodeAttestUnsupported  = pairing.ErrorCodeAttestUnsupported
	ErrorCodeOperationDenied    = pairing.ErrorCodeOperationDenied
	ErrorCodeInvalidPublicKey   = pairing.ErrorCodeInvalidPublicKey
	ErrorCodeDecryptFailed      = pairing.ErrorCodeDecryptFailed
	ErrorCodeHMACFailed         = pairing.ErrorCodeHMACFailed
	ErrorCodeECDHFailed         = pairing.ErrorCodeECDHFailed
	ErrorCodeInvalidFormat      = pairing.ErrorCodeInvalidFormat
	ErrorCodePairingRejected    = pairing.ErrorCodePairingRejected
	ErrorCodeShareDenied        = pairing.ErrorCodeShareDenied
	ErrorCodeShareNotExportable = pairing.ErrorCodeShareNotExportable

	ErrorCodeBackupFailed   = pairing.ErrorCodeBackupFailed
	ErrorCodeBackupRestore  = pairing.ErrorCodeBackupRestore
	ErrorCodeBackupNotFound = pairing.ErrorCodeBackupNotFound

	ErrorCodeOATHNotFound = pairing.ErrorCodeOATHNotFound
	ErrorCodeOATHGenerate = pairing.ErrorCodeOATHGenerate
	ErrorCodeOATHStore    = pairing.ErrorCodeOATHStore

	ErrorCodePIVSlotNotFound = pairing.ErrorCodePIVSlotNotFound
	ErrorCodePIVSlotOccupied = pairing.ErrorCodePIVSlotOccupied
	ErrorCodePIVSignFailed   = pairing.ErrorCodePIVSignFailed
	ErrorCodePIVInvalidSlot  = pairing.ErrorCodePIVInvalidSlot

	ErrorCodeSyncFailed          = pairing.ErrorCodeSyncFailed
	ErrorCodeSyncConflict        = pairing.ErrorCodeSyncConflict
	ErrorCodeSyncRemoteUnavail   = pairing.ErrorCodeSyncRemoteUnavail
	ErrorCodeSyncNoData          = pairing.ErrorCodeSyncNoData
	ErrorCodeSyncVersionMismatch = pairing.ErrorCodeSyncVersionMismatch
)

// Fragmentation constant re-exports.
const (
	FragmentHeaderSize = pairing.FragmentHeaderSize
	FlagFirstFragment  = pairing.FlagFirstFragment
	FlagLastFragment   = pairing.FlagLastFragment
	FlagSingleFragment = pairing.FlagSingleFragment
)

// Attestation mode constant re-exports.
const (
	AttestationModeSoftware = pairing.AttestationModeSoftware
	AttestationModeTPM2     = pairing.AttestationModeTPM2
)

// Bridge timeout re-export.
const DefaultBridgeRequestTimeout = pairing.DefaultBridgeRequestTimeout

// PIV slot constant re-exports.
const (
	PIVSlotAuthentication   = pairing.PIVSlotAuthentication
	PIVSlotDigitalSignature = pairing.PIVSlotDigitalSignature
	PIVSlotKeyManagement    = pairing.PIVSlotKeyManagement
	PIVSlotCardAuth         = pairing.PIVSlotCardAuth
)

// COSE algorithm constant re-exports.
const (
	COSEAlgES256 = pairing.COSEAlgES256
	COSEAlgES384 = pairing.COSEAlgES384
	COSEAlgES512 = pairing.COSEAlgES512
)

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

// Package pairingproto is the SDK re-export of the device pairing wire
// protocol (pkg/pairingproto): the JSON-RPC envelope, the method names and
// their parameter and result types, the handshake, fragmentation and live
// attestation primitives, and the protocol errors. Client binaries import
// this package instead of pkg/* so they depend only on the SDK.
package pairingproto

import (
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

const (
	JSONRPCVersion = pairingproto.JSONRPCVersion
	MinMTU         = pairingproto.MinMTU

	AttestationFormatAndroidKey = pairingproto.AttestationFormatAndroidKey

	SecurityLevelSoftware  = pairingproto.SecurityLevelSoftware
	SecurityLevelStrongBox = pairingproto.SecurityLevelStrongBox
	SecurityLevelTEE       = pairingproto.SecurityLevelTEE

	COSEAlgES256 = pairingproto.COSEAlgES256
	COSEAlgES384 = pairingproto.COSEAlgES384
	COSEAlgES512 = pairingproto.COSEAlgES512
)

// Handshake identity exchange.
const (
	IdentityAckKnown     = pairingproto.IdentityAckKnown
	IdentityAckKnownSize = pairingproto.IdentityAckKnownSize
	IdentityAckUnknown   = pairingproto.IdentityAckUnknown
	IdentityMsgSize      = pairingproto.IdentityMsgSize
	IdentityMsgVersion   = pairingproto.IdentityMsgVersion
)

// Live attestation challenge.
const (
	AttestChannelBindingDomain = pairingproto.AttestChannelBindingDomain
	AttestFingerprintSize      = pairingproto.AttestFingerprintSize
	AttestGenesisChallenge     = pairingproto.AttestGenesisChallenge
	AttestNonceSize            = pairingproto.AttestNonceSize
	AttestProtocolV2           = pairingproto.AttestProtocolV2
	AttestPurposePair          = pairingproto.AttestPurposePair
	AttestPurposeReattest      = pairingproto.AttestPurposeReattest
	AttestSignatureES256       = pairingproto.AttestSignatureES256
	AttestTranscriptDomain     = pairingproto.AttestTranscriptDomain
)

// Method names.
const (
	MethodDeleteKey                       = pairingproto.MethodDeleteKey
	MethodGenerateKey                     = pairingproto.MethodGenerateKey
	MethodGetInfo                         = pairingproto.MethodGetInfo
	MethodLoadKey                         = pairingproto.MethodLoadKey
	MethodPairingConfirm                  = pairingproto.MethodPairingConfirm
	MethodPing                            = pairingproto.MethodPing
	MethodSign                            = pairingproto.MethodSign
	MethodLocalActivateCredential         = pairingproto.MethodLocalActivateCredential
	MethodLocalAttestKey                  = pairingproto.MethodLocalAttestKey
	MethodLocalCreateBackup               = pairingproto.MethodLocalCreateBackup
	MethodLocalImportSharedKey            = pairingproto.MethodLocalImportSharedKey
	MethodLocalOATHAdd                    = pairingproto.MethodLocalOATHAdd
	MethodLocalOATHList                   = pairingproto.MethodLocalOATHList
	MethodLocalPIVGenerateKey             = pairingproto.MethodLocalPIVGenerateKey
	MethodLocalPIVGetCert                 = pairingproto.MethodLocalPIVGetCert
	MethodLocalPIVImportCert              = pairingproto.MethodLocalPIVImportCert
	MethodLocalPIVListSlots               = pairingproto.MethodLocalPIVListSlots
	MethodLocalRestoreBackup              = pairingproto.MethodLocalRestoreBackup
	MethodLocalSharePublicKey             = pairingproto.MethodLocalSharePublicKey
	MethodLocalShareSymmetric             = pairingproto.MethodLocalShareSymmetric
	MethodLocalSyncOATH                   = pairingproto.MethodLocalSyncOATH
	MethodLocalSyncPasswords              = pairingproto.MethodLocalSyncPasswords
	MethodLocalSyncStatus                 = pairingproto.MethodLocalSyncStatus
	MethodLocalSyncTrustStore             = pairingproto.MethodLocalSyncTrustStore
	MethodLocalAttestDevice               = pairingproto.MethodLocalAttestDevice
	MethodLocalBiometricPending           = pairingproto.MethodLocalBiometricPending
	MethodLocalGetAttestationQuote        = pairingproto.MethodLocalGetAttestationQuote
	MethodLocalGetDeviceEnrollmentRequest = pairingproto.MethodLocalGetDeviceEnrollmentRequest
	MethodLocalGetIAKPublicKey            = pairingproto.MethodLocalGetIAKPublicKey
	MethodLocalGetTCGCSRIDevID            = pairingproto.MethodLocalGetTCGCSRIDevID
	MethodLocalListFido2Credentials       = pairingproto.MethodLocalListFido2Credentials
	MethodLocalSignFido2Assertion         = pairingproto.MethodLocalSignFido2Assertion
	MethodLocalStoreDeviceCredential      = pairingproto.MethodLocalStoreDeviceCredential
	MethodRemoteActivateCredential        = pairingproto.MethodRemoteActivateCredential
	MethodRemoteAttestDevice              = pairingproto.MethodRemoteAttestDevice
	MethodRemoteAttestKey                 = pairingproto.MethodRemoteAttestKey
	MethodRemoteCreateBackup              = pairingproto.MethodRemoteCreateBackup
	MethodRemoteDecrypt                   = pairingproto.MethodRemoteDecrypt
	MethodRemoteDeleteKey                 = pairingproto.MethodRemoteDeleteKey
	MethodRemoteDeriveKey                 = pairingproto.MethodRemoteDeriveKey
	MethodRemoteEncrypt                   = pairingproto.MethodRemoteEncrypt
	MethodRemoteGenerateKey               = pairingproto.MethodRemoteGenerateKey
	MethodRemoteGetAttestationQuote       = pairingproto.MethodRemoteGetAttestationQuote
	MethodRemoteGetKeyInfo                = pairingproto.MethodRemoteGetKeyInfo
	MethodRemoteGetPublicKey              = pairingproto.MethodRemoteGetPublicKey
	MethodRemoteGetTCGCSRIDevID           = pairingproto.MethodRemoteGetTCGCSRIDevID
	MethodRemoteImportSharedKey           = pairingproto.MethodRemoteImportSharedKey
	MethodRemoteListBackends              = pairingproto.MethodRemoteListBackends
	MethodRemoteListBackups               = pairingproto.MethodRemoteListBackups
	MethodRemoteListKeys                  = pairingproto.MethodRemoteListKeys
	MethodRemoteOATHAdd                   = pairingproto.MethodRemoteOATHAdd
	MethodRemoteOATHGenerate              = pairingproto.MethodRemoteOATHGenerate
	MethodRemotePIVGetCert                = pairingproto.MethodRemotePIVGetCert
	MethodRemotePIVListSlots              = pairingproto.MethodRemotePIVListSlots
	MethodRemotePIVSign                   = pairingproto.MethodRemotePIVSign
	MethodRemoteRestoreBackup             = pairingproto.MethodRemoteRestoreBackup
	MethodRemoteSharePublicKey            = pairingproto.MethodRemoteSharePublicKey
	MethodRemoteShareSymmetric            = pairingproto.MethodRemoteShareSymmetric
	MethodRemoteSign                      = pairingproto.MethodRemoteSign
	MethodRemoteStoreEnrollmentCerts      = pairingproto.MethodRemoteStoreEnrollmentCerts
	MethodRemoteSyncAll                   = pairingproto.MethodRemoteSyncAll
	MethodRemoteSyncOATH                  = pairingproto.MethodRemoteSyncOATH
	MethodRemoteSyncPasswords             = pairingproto.MethodRemoteSyncPasswords
	MethodRemoteSyncStatus                = pairingproto.MethodRemoteSyncStatus
	MethodRemoteSyncTrustStore            = pairingproto.MethodRemoteSyncTrustStore
	MethodRemoteVerify                    = pairingproto.MethodRemoteVerify
)

// JSON-RPC error codes.
const (
	ErrorCodeAttestFailed         = pairingproto.ErrorCodeAttestFailed
	ErrorCodeAttestUnsupported    = pairingproto.ErrorCodeAttestUnsupported
	ErrorCodeBackendDenied        = pairingproto.ErrorCodeBackendDenied
	ErrorCodeBackupFailed         = pairingproto.ErrorCodeBackupFailed
	ErrorCodeBackupNotFound       = pairingproto.ErrorCodeBackupNotFound
	ErrorCodeBackupRestore        = pairingproto.ErrorCodeBackupRestore
	ErrorCodeFeatureUnavailable   = pairingproto.ErrorCodeFeatureUnavailable
	ErrorCodeInternalError        = pairingproto.ErrorCodeInternalError
	ErrorCodeInvalidFormat        = pairingproto.ErrorCodeInvalidFormat
	ErrorCodeInvalidParams        = pairingproto.ErrorCodeInvalidParams
	ErrorCodeInvalidPublicKey     = pairingproto.ErrorCodeInvalidPublicKey
	ErrorCodeInvalidRequest       = pairingproto.ErrorCodeInvalidRequest
	ErrorCodeKeyExists            = pairingproto.ErrorCodeKeyExists
	ErrorCodeKeyNotFound          = pairingproto.ErrorCodeKeyNotFound
	ErrorCodeMethodNotFound       = pairingproto.ErrorCodeMethodNotFound
	ErrorCodeOATHGenerate         = pairingproto.ErrorCodeOATHGenerate
	ErrorCodeOATHNotFound         = pairingproto.ErrorCodeOATHNotFound
	ErrorCodeOATHStore            = pairingproto.ErrorCodeOATHStore
	ErrorCodeParseError           = pairingproto.ErrorCodeParseError
	ErrorCodePIVInvalidSlot       = pairingproto.ErrorCodePIVInvalidSlot
	ErrorCodePIVSignFailed        = pairingproto.ErrorCodePIVSignFailed
	ErrorCodePIVSlotNotFound      = pairingproto.ErrorCodePIVSlotNotFound
	ErrorCodePIVSlotOccupied      = pairingproto.ErrorCodePIVSlotOccupied
	ErrorCodeShareDenied          = pairingproto.ErrorCodeShareDenied
	ErrorCodeShareNotExportable   = pairingproto.ErrorCodeShareNotExportable
	ErrorCodeSyncApprovalRequired = pairingproto.ErrorCodeSyncApprovalRequired
	ErrorCodeSyncConflict         = pairingproto.ErrorCodeSyncConflict
	ErrorCodeSyncFailed           = pairingproto.ErrorCodeSyncFailed
	ErrorCodeSyncNoData           = pairingproto.ErrorCodeSyncNoData
	ErrorCodeSyncNotApproved      = pairingproto.ErrorCodeSyncNotApproved
	ErrorCodeMessageTooLarge      = pairingproto.ErrorCodeMessageTooLarge
	ErrorCodeSyncRemoteUnavail    = pairingproto.ErrorCodeSyncRemoteUnavail
	ErrorCodeSyncVersionMismatch  = pairingproto.ErrorCodeSyncVersionMismatch
	ErrorCodeUnsupportedAlg       = pairingproto.ErrorCodeUnsupportedAlg
)

// Envelope, transport, framing and error types.
type (
	DetailError          = pairingproto.DetailError
	Fragmenter           = pairingproto.Fragmenter
	HandshakeConfig      = pairingproto.HandshakeConfig
	LiveAttestFunc       = pairingproto.LiveAttestFunc
	RPCError             = pairingproto.RPCError
	RPCExchange          = pairingproto.RPCExchange
	Reassembler          = pairingproto.Reassembler
	Request              = pairingproto.Request
	Response             = pairingproto.Response
	SentinelCauseError   = pairingproto.SentinelCauseError
	MessageTooLargeError = pairingproto.MessageTooLargeError
	Transport            = pairingproto.Transport
)

// Method parameter and result types.
type (
	BackendInfo                           = pairingproto.BackendInfo
	DeleteKeyParams                       = pairingproto.DeleteKeyParams
	DeleteKeyResult                       = pairingproto.DeleteKeyResult
	Fido2CredentialInfo                   = pairingproto.Fido2CredentialInfo
	GenerateKeyParams                     = pairingproto.GenerateKeyParams
	GenerateKeyResult                     = pairingproto.GenerateKeyResult
	GetInfoResult                         = pairingproto.GetInfoResult
	LoadKeyParams                         = pairingproto.LoadKeyParams
	LoadKeyResult                         = pairingproto.LoadKeyResult
	OATHCredentialInfo                    = pairingproto.OATHCredentialInfo
	PIVSlotInfo                           = pairingproto.PIVSlotInfo
	PairingConfirmParams                  = pairingproto.PairingConfirmParams
	PairingConfirmResult                  = pairingproto.PairingConfirmResult
	PingResult                            = pairingproto.PingResult
	SignParams                            = pairingproto.SignParams
	SignResult                            = pairingproto.SignResult
	SyncCertificate                       = pairingproto.SyncCertificate
	SyncOATHCredential                    = pairingproto.SyncOATHCredential
	SyncPassword                          = pairingproto.SyncPassword
	LocalAttestKeyParams                  = pairingproto.LocalAttestKeyParams
	LocalAttestKeyResult                  = pairingproto.LocalAttestKeyResult
	LocalCreateBackupParams               = pairingproto.LocalCreateBackupParams
	LocalCreateBackupResult               = pairingproto.LocalCreateBackupResult
	LocalGetDeviceEnrollmentRequestParams = pairingproto.LocalGetDeviceEnrollmentRequestParams
	LocalImportSharedKeyParams            = pairingproto.LocalImportSharedKeyParams
	LocalImportSharedKeyResult            = pairingproto.LocalImportSharedKeyResult
	LocalOATHAddParams                    = pairingproto.LocalOATHAddParams
	LocalOATHAddResult                    = pairingproto.LocalOATHAddResult
	LocalOATHListParams                   = pairingproto.LocalOATHListParams
	LocalOATHListResult                   = pairingproto.LocalOATHListResult
	LocalPIVGenerateKeyParams             = pairingproto.LocalPIVGenerateKeyParams
	LocalPIVGenerateKeyResult             = pairingproto.LocalPIVGenerateKeyResult
	LocalPIVGetCertParams                 = pairingproto.LocalPIVGetCertParams
	LocalPIVGetCertResult                 = pairingproto.LocalPIVGetCertResult
	LocalPIVImportCertParams              = pairingproto.LocalPIVImportCertParams
	LocalPIVImportCertResult              = pairingproto.LocalPIVImportCertResult
	LocalPIVListSlotsParams               = pairingproto.LocalPIVListSlotsParams
	LocalPIVListSlotsResult               = pairingproto.LocalPIVListSlotsResult
	LocalRestoreBackupParams              = pairingproto.LocalRestoreBackupParams
	LocalRestoreBackupResult              = pairingproto.LocalRestoreBackupResult
	LocalSharePublicKeyParams             = pairingproto.LocalSharePublicKeyParams
	LocalSharePublicKeyResult             = pairingproto.LocalSharePublicKeyResult
	LocalShareSymmetricParams             = pairingproto.LocalShareSymmetricParams
	LocalShareSymmetricResult             = pairingproto.LocalShareSymmetricResult
	LocalStoreDeviceCredentialParams      = pairingproto.LocalStoreDeviceCredentialParams
	LocalSyncOATHParams                   = pairingproto.LocalSyncOATHParams
	LocalSyncOATHResult                   = pairingproto.LocalSyncOATHResult
	LocalSyncPasswordsParams              = pairingproto.LocalSyncPasswordsParams
	LocalSyncPasswordsResult              = pairingproto.LocalSyncPasswordsResult
	LocalSyncStatusParams                 = pairingproto.LocalSyncStatusParams
	LocalSyncStatusResult                 = pairingproto.LocalSyncStatusResult
	LocalSyncTrustStoreParams             = pairingproto.LocalSyncTrustStoreParams
	LocalSyncTrustStoreResult             = pairingproto.LocalSyncTrustStoreResult
	LocalAttestDeviceParams               = pairingproto.LocalAttestDeviceParams
	LocalAttestDeviceResult               = pairingproto.LocalAttestDeviceResult
	LocalBiometricPendingParams           = pairingproto.LocalBiometricPendingParams
	LocalGetCapabilitiesResult            = pairingproto.LocalGetCapabilitiesResult
	LocalGetDeviceEnrollmentRequestResult = pairingproto.LocalGetDeviceEnrollmentRequestResult
	LocalListFido2CredentialsParams       = pairingproto.LocalListFido2CredentialsParams
	LocalListFido2CredentialsResult       = pairingproto.LocalListFido2CredentialsResult
	LocalSignFido2AssertionParams         = pairingproto.LocalSignFido2AssertionParams
	LocalSignFido2AssertionResult         = pairingproto.LocalSignFido2AssertionResult
	LocalStoreDeviceCredentialResult      = pairingproto.LocalStoreDeviceCredentialResult
	RemoteActivateCredentialParams        = pairingproto.RemoteActivateCredentialParams
	RemoteActivateCredentialResult        = pairingproto.RemoteActivateCredentialResult
	RemoteAttestDeviceParams              = pairingproto.RemoteAttestDeviceParams
	RemoteAttestDeviceResult              = pairingproto.RemoteAttestDeviceResult
	RemoteAttestKeyParams                 = pairingproto.RemoteAttestKeyParams
	RemoteAttestKeyResult                 = pairingproto.RemoteAttestKeyResult
	RemoteCreateBackupParams              = pairingproto.RemoteCreateBackupParams
	RemoteCreateBackupResult              = pairingproto.RemoteCreateBackupResult
	RemoteDecryptParams                   = pairingproto.RemoteDecryptParams
	RemoteDecryptResult                   = pairingproto.RemoteDecryptResult
	RemoteDeleteKeyParams                 = pairingproto.RemoteDeleteKeyParams
	RemoteDeleteKeyResult                 = pairingproto.RemoteDeleteKeyResult
	RemoteDeriveKeyParams                 = pairingproto.RemoteDeriveKeyParams
	RemoteDeriveKeyResult                 = pairingproto.RemoteDeriveKeyResult
	RemoteEncryptParams                   = pairingproto.RemoteEncryptParams
	RemoteEncryptResult                   = pairingproto.RemoteEncryptResult
	RemoteGenerateKeyParams               = pairingproto.RemoteGenerateKeyParams
	RemoteGenerateKeyResult               = pairingproto.RemoteGenerateKeyResult
	RemoteGetAttestationQuoteParams       = pairingproto.RemoteGetAttestationQuoteParams
	RemoteGetAttestationQuoteResult       = pairingproto.RemoteGetAttestationQuoteResult
	RemoteGetKeyInfoParams                = pairingproto.RemoteGetKeyInfoParams
	RemoteGetKeyInfoResult                = pairingproto.RemoteGetKeyInfoResult
	RemoteGetPublicKeyParams              = pairingproto.RemoteGetPublicKeyParams
	RemoteGetPublicKeyResult              = pairingproto.RemoteGetPublicKeyResult
	RemoteGetTCGCSRIDevIDParams           = pairingproto.RemoteGetTCGCSRIDevIDParams
	RemoteGetTCGCSRIDevIDResult           = pairingproto.RemoteGetTCGCSRIDevIDResult
	RemoteImportSharedKeyParams           = pairingproto.RemoteImportSharedKeyParams
	RemoteImportSharedKeyResult           = pairingproto.RemoteImportSharedKeyResult
	RemoteKeyInfo                         = pairingproto.RemoteKeyInfo
	RemoteListBackendsResult              = pairingproto.RemoteListBackendsResult
	RemoteListKeysParams                  = pairingproto.RemoteListKeysParams
	RemoteListKeysResult                  = pairingproto.RemoteListKeysResult
	RemoteOATHAddParams                   = pairingproto.RemoteOATHAddParams
	RemoteOATHAddResult                   = pairingproto.RemoteOATHAddResult
	RemoteOATHGenerateParams              = pairingproto.RemoteOATHGenerateParams
	RemoteOATHGenerateResult              = pairingproto.RemoteOATHGenerateResult
	RemotePIVGetCertParams                = pairingproto.RemotePIVGetCertParams
	RemotePIVGetCertResult                = pairingproto.RemotePIVGetCertResult
	RemotePIVListSlotsParams              = pairingproto.RemotePIVListSlotsParams
	RemotePIVListSlotsResult              = pairingproto.RemotePIVListSlotsResult
	RemotePIVSignParams                   = pairingproto.RemotePIVSignParams
	RemotePIVSignResult                   = pairingproto.RemotePIVSignResult
	RemoteRestoreBackupParams             = pairingproto.RemoteRestoreBackupParams
	RemoteRestoreBackupResult             = pairingproto.RemoteRestoreBackupResult
	RemoteRestoreBackupItem               = pairingproto.RemoteRestoreBackupItem
	RemoteSharePublicKeyParams            = pairingproto.RemoteSharePublicKeyParams
	RemoteSharePublicKeyResult            = pairingproto.RemoteSharePublicKeyResult
	RemoteShareSymmetricParams            = pairingproto.RemoteShareSymmetricParams
	RemoteShareSymmetricResult            = pairingproto.RemoteShareSymmetricResult
	RemoteSignParams                      = pairingproto.RemoteSignParams
	RemoteSignResult                      = pairingproto.RemoteSignResult
	RemoteStoreEnrollmentCertsParams      = pairingproto.RemoteStoreEnrollmentCertsParams
	RemoteStoreEnrollmentCertsResult      = pairingproto.RemoteStoreEnrollmentCertsResult
	RemoteSyncAllParams                   = pairingproto.RemoteSyncAllParams
	RemoteSyncAllResult                   = pairingproto.RemoteSyncAllResult
	RemoteSyncOATHParams                  = pairingproto.RemoteSyncOATHParams
	RemoteSyncOATHResult                  = pairingproto.RemoteSyncOATHResult
	RemoteSyncPasswordsParams             = pairingproto.RemoteSyncPasswordsParams
	RemoteSyncPasswordsResult             = pairingproto.RemoteSyncPasswordsResult
	RemoteSyncStatusResult                = pairingproto.RemoteSyncStatusResult
	RemoteSyncTrustStoreParams            = pairingproto.RemoteSyncTrustStoreParams
	RemoteSyncTrustStoreResult            = pairingproto.RemoteSyncTrustStoreResult
	RemoteVerifyParams                    = pairingproto.RemoteVerifyParams
	RemoteVerifyResult                    = pairingproto.RemoteVerifyResult
)

// Envelope codec, framing, handshake and live attestation functions.
var (
	DecodeFragment      = pairingproto.DecodeFragment
	DecodeRequest       = pairingproto.DecodeRequest
	DecodeResponse      = pairingproto.DecodeResponse
	EncodeErrorResponse = pairingproto.EncodeErrorResponse
	EncodeRequest       = pairingproto.EncodeRequest
	EncodeResponse      = pairingproto.EncodeResponse
	MapRPCError         = pairingproto.MapRPCError
	NewFragmenter       = pairingproto.NewFragmenter
	NewReassembler      = pairingproto.NewReassembler
	NewRequest          = pairingproto.NewRequest
	PerformHandshake    = pairingproto.PerformHandshake

	AttestChannelBinding           = pairingproto.AttestChannelBinding
	AttestedKeyFingerprint         = pairingproto.AttestedKeyFingerprint
	BuildAttestTranscript          = pairingproto.BuildAttestTranscript
	VerifyAttestChallengeSignature = pairingproto.VerifyAttestChallengeSignature
	VerifyGenesisChallenge         = pairingproto.VerifyGenesisChallenge
)

// DecodeResult decodes the result of a successful response into a T. A
// generic function cannot be re-exported by value, so this forwards to
// pkg/pairingproto.DecodeResult.
func DecodeResult[T any](resp *Response) (*T, error) {
	return pairingproto.DecodeResult[T](resp)
}

// Protocol errors.
var (
	ErrAttestProtocolDowngrade  = pairingproto.ErrAttestProtocolDowngrade
	ErrAttestationFailed        = pairingproto.ErrAttestationFailed
	ErrAttestationNotSupported  = pairingproto.ErrAttestationNotSupported
	ErrBackendClosed            = pairingproto.ErrBackendClosed
	ErrBackendDenied            = pairingproto.ErrBackendDenied
	ErrBackupFailed             = pairingproto.ErrBackupFailed
	ErrBackupNotConfigured      = pairingproto.ErrBackupNotConfigured
	ErrBackupNotFound           = pairingproto.ErrBackupNotFound
	ErrBackupPasswordRequired   = pairingproto.ErrBackupPasswordRequired
	ErrBackupRestoreFailed      = pairingproto.ErrBackupRestoreFailed
	ErrBiometricFailed          = pairingproto.ErrBiometricFailed
	ErrBridgeBackendDenied      = pairingproto.ErrBridgeBackendDenied
	ErrBridgeInvalidParams      = pairingproto.ErrBridgeInvalidParams
	ErrBridgeNotConnected       = pairingproto.ErrBridgeNotConnected
	ErrConnectionFailed         = pairingproto.ErrConnectionFailed
	ErrDecryptFailed            = pairingproto.ErrDecryptFailed
	ErrDeviceNotFound           = pairingproto.ErrDeviceNotFound
	ErrDuplicateRequestID       = pairingproto.ErrDuplicateRequestID
	ErrECDHFailed               = pairingproto.ErrECDHFailed
	ErrEKCertificateMissing     = pairingproto.ErrEKCertificateMissing
	ErrExportNotSupported       = pairingproto.ErrExportNotSupported
	ErrFragmentationError       = pairingproto.ErrFragmentationError
	ErrHMACFailed               = pairingproto.ErrHMACFailed
	ErrImportNotSupported       = pairingproto.ErrImportNotSupported
	ErrInvalidCertificate       = pairingproto.ErrInvalidCertificate
	ErrInvalidClientDataHash    = pairingproto.ErrInvalidClientDataHash
	ErrInvalidCredentialID      = pairingproto.ErrInvalidCredentialID
	ErrInvalidFormat            = pairingproto.ErrInvalidFormat
	ErrInvalidFragment          = pairingproto.ErrInvalidFragment
	ErrInvalidKeyHandle         = pairingproto.ErrInvalidKeyHandle
	ErrInvalidPublicKey         = pairingproto.ErrInvalidPublicKey
	ErrInvalidResponse          = pairingproto.ErrInvalidResponse
	ErrInvalidRpID              = pairingproto.ErrInvalidRpID
	ErrKeyExists                = pairingproto.ErrKeyExists
	ErrKeyNotFound              = pairingproto.ErrKeyNotFound
	ErrMTUTooSmall              = pairingproto.ErrMTUTooSmall
	ErrMaxRetriesExceeded       = pairingproto.ErrMaxRetriesExceeded
	ErrNotConnected             = pairingproto.ErrNotConnected
	ErrOATHCredentialNotFound   = pairingproto.ErrOATHCredentialNotFound
	ErrOATHGenerateFailed       = pairingproto.ErrOATHGenerateFailed
	ErrOATHNotConfigured        = pairingproto.ErrOATHNotConfigured
	ErrOATHStoreFailed          = pairingproto.ErrOATHStoreFailed
	ErrOperationDenied          = pairingproto.ErrOperationDenied
	ErrPCRBankUnavailable       = pairingproto.ErrPCRBankUnavailable
	ErrPIVInvalidSlot           = pairingproto.ErrPIVInvalidSlot
	ErrPIVNotConfigured         = pairingproto.ErrPIVNotConfigured
	ErrPIVSignFailed            = pairingproto.ErrPIVSignFailed
	ErrPIVSlotNotFound          = pairingproto.ErrPIVSlotNotFound
	ErrPIVSlotOccupied          = pairingproto.ErrPIVSlotOccupied
	ErrPairingFailed            = pairingproto.ErrPairingFailed
	ErrPairingRejected          = pairingproto.ErrPairingRejected
	ErrProtocolError            = pairingproto.ErrProtocolError
	ErrMessageTooLarge          = pairingproto.ErrMessageTooLarge
	ErrSequenceNumber           = pairingproto.ErrSequenceNumber
	ErrSessionExpired           = pairingproto.ErrSessionExpired
	ErrShareDenied              = pairingproto.ErrShareDenied
	ErrShareInvalidKeyType      = pairingproto.ErrShareInvalidKeyType
	ErrShareNotExportable       = pairingproto.ErrShareNotExportable
	ErrSharePolicyNotFound      = pairingproto.ErrSharePolicyNotFound
	ErrStorageFull              = pairingproto.ErrStorageFull
	ErrSyncApprovalRequired     = pairingproto.ErrSyncApprovalRequired
	ErrSyncConflict             = pairingproto.ErrSyncConflict
	ErrSyncFailed               = pairingproto.ErrSyncFailed
	ErrSyncNoData               = pairingproto.ErrSyncNoData
	ErrSyncNotApproved          = pairingproto.ErrSyncNotApproved
	ErrSyncNotConfigured        = pairingproto.ErrSyncNotConfigured
	ErrSyncRemoteUnavailable    = pairingproto.ErrSyncRemoteUnavailable
	ErrSyncVersionMismatch      = pairingproto.ErrSyncVersionMismatch
	ErrTPM2DirectAccessRequired = pairingproto.ErrTPM2DirectAccessRequired
	ErrTPMKeyNotProvisioned     = pairingproto.ErrTPMKeyNotProvisioned
	ErrTPMNotConfigured         = pairingproto.ErrTPMNotConfigured
	ErrTPMOperationFailed       = pairingproto.ErrTPMOperationFailed
	ErrTPMUnavailable           = pairingproto.ErrTPMUnavailable
	ErrTimeout                  = pairingproto.ErrTimeout
	ErrUnsupportedAlgorithm     = pairingproto.ErrUnsupportedAlgorithm
	ErrUntrustedDevice          = pairingproto.ErrUntrustedDevice
	ErrUserCancelled            = pairingproto.ErrUserCancelled
)

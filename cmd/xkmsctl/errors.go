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

package main

import (
	"errors"
	"fmt"
)

// Sentinel errors for xkmsctl operations.
var (
	// ErrUnsupportedAuthMethod is returned when an unknown authentication method is specified.
	ErrUnsupportedAuthMethod = errors.New("unsupported authentication method")

	// ErrNoCertificateSource is returned when mTLS enrollment is requested but neither
	// --pkcs11-module nor --cert-file is provided.
	ErrNoCertificateSource = errors.New("mTLS enrollment requires --pkcs11-module or --cert-file")

	// ErrCertFileRead is returned when the certificate file cannot be read.
	ErrCertFileRead = errors.New("failed to read certificate file")

	// ErrCertFileParse is returned when the certificate file cannot be parsed as PEM/X.509.
	ErrCertFileParse = errors.New("failed to parse certificate file")

	// ErrDNSQuery is returned when a DNS query fails to execute.
	ErrDNSQuery = errors.New("DNS query failed")

	// ErrDNSNoRecords is returned when no TLSA records are found for the queried name.
	ErrDNSNoRecords = errors.New("no TLSA records found")

	// ErrDNSResponseCode is returned when the DNS server responds with a non-success RCODE.
	ErrDNSResponseCode = errors.New("DNS server returned error response")

	// ErrTLSAVerificationFailed is returned when TLSA record verification fails
	// against the provided certificate.
	ErrTLSAVerificationFailed = errors.New("TLSA verification failed: no matching records")

	// ErrTLSAInvalidSelector is returned when an unsupported TLSA selector value is encountered.
	ErrTLSAInvalidSelector = errors.New("unsupported TLSA selector")

	// ErrTLSAInvalidMatchingType is returned when an unsupported TLSA matching type is encountered.
	ErrTLSAInvalidMatchingType = errors.New("unsupported TLSA matching type")

	// Canonical barrier errors are defined as typed errors (with structured
	// fields) in barrier.go: PINsNotAllowedError, BarrierStrategyError,
	// BarrierSecretRequiredError, BarrierSecretNotAllowedError, PINPairError,
	// BarrierShamirParamsError, BarrierShamirOnInitError, BarrierShareInputError,
	// BarrierSharesFileError, BarrierSharesFileEmptyError,
	// XKMSRekeyShamirParamsRequiredError, BarrierRecoverySharesRequiredError,
	// BarrierSealConfirmationError. Sentinel-style flag-validation errors
	// for barrier verbs have been retired in favour of those typed forms.

	// Custodian group errors

	// ErrCustodianNameRequired is returned when --name is not provided for custodian create.
	ErrCustodianNameRequired = errors.New("--name is required")

	// ErrCustodianInvalidThreshold is returned when --threshold or --total are not positive.
	ErrCustodianInvalidThreshold = errors.New("--threshold and --total must be positive integers")

	// ErrCustodianThresholdExceedsTotal is returned when threshold exceeds total shares.
	ErrCustodianThresholdExceedsTotal = errors.New("--threshold must not exceed --total")

	// ErrCustodianIDRequired is returned when --id is not provided for a command
	// that requires a custodian group ID.
	ErrCustodianIDRequired = errors.New("--id is required")

	// ErrCustodianGroupIDRequired is returned when --group-id is not provided.
	ErrCustodianGroupIDRequired = errors.New("--group-id is required")

	// ErrCustodianUserIDRequired is returned when --user-id is not provided.
	ErrCustodianUserIDRequired = errors.New("--user-id is required")

	// Tenant errors

	// ErrTenantIDRequired is returned when --id is not provided for a tenant command.
	ErrTenantIDRequired = errors.New("--id is required for tenant operations")

	// ErrTenantNameRequired is returned when --name is not provided for tenant create.
	ErrTenantNameRequired = errors.New("--name is required for tenant creation")

	// Bootstrap auto errors

	// ErrAllBootstrapMethodsFailed is returned when all configured bootstrap
	// methods have been attempted and none succeeded.
	ErrAllBootstrapMethodsFailed = errors.New("all bootstrap methods failed")

	// ErrNoBootstrapMethodConfigured is returned when no bootstrap methods
	// are configured (none of --dane-hostname, --noise-key, or --spki-pin provided).
	ErrNoBootstrapMethodConfigured = errors.New("no bootstrap method configured")

	// ErrBootstrapBundleWrite is returned when the CA bundle cannot be written
	// to the specified output file.
	ErrBootstrapBundleWrite = errors.New("failed to write CA bundle to output file")

	// ErrBootstrapServerURLRequired is returned when --server-url is not provided
	// for auto bootstrap.
	ErrBootstrapServerURLRequired = errors.New("--server-url is required for auto bootstrap")

	// Init ceremony errors

	// ErrServerRequired is returned when --server is not specified for init commands.
	ErrServerRequired = errors.New("--server is required for init commands")

	// ErrUsernameRequired is returned when --username is not specified.
	ErrUsernameRequired = errors.New("--username is required")

	// ErrKeyFileRequired is returned when --key is not specified for claim-cert.
	ErrKeyFileRequired = errors.New("--key is required for claim-cert (CSR private key)")

	// ErrSPKIPinRequired is returned when --spki-pin is not specified for SPKI-pinned operations.
	ErrSPKIPinRequired = errors.New("--spki-pin is required for initial cert claim")

	// ErrNonceSignFailed is returned when nonce signing fails.
	ErrNonceSignFailed = errors.New("failed to sign nonce challenge")

	// ErrHTTPRequestFailed is returned when an HTTP request to the server fails.
	ErrHTTPRequestFailed = errors.New("HTTP request to server failed")

	// ErrServerResponseError is returned when the server returns a non-2xx status.
	ErrServerResponseError = errors.New("server returned error")

	// ErrPrivateKeyRead is returned when the private key file cannot be read.
	ErrPrivateKeyRead = errors.New("failed to read private key file")

	// ErrPrivateKeyParse is returned when the private key cannot be parsed.
	ErrPrivateKeyParse = errors.New("failed to parse private key")

	// ErrUnsupportedKeyType is returned when the private key type is not supported for signing.
	ErrUnsupportedKeyType = errors.New("unsupported private key type for nonce signing")

	// Credential errors

	// ErrCredentialNameRequired is returned when --name is not specified for credential submit.
	ErrCredentialNameRequired = errors.New("--name is required for credential submit")

	// ErrCredentialValueRequired is returned when --value is not specified for credential submit.
	ErrCredentialValueRequired = errors.New("--value is required for credential submit")

	// ErrCSRFileRequired is returned when --csr is not specified for sign-csr.
	ErrCSRFileRequired = errors.New("--csr is required for sign-csr")

	// ErrSOPinRequired is returned when --so-pin is not specified.
	ErrSOPinRequired = errors.New("--so-pin is required for this operation")

	// ErrRoleRequired is returned when --role is not specified for sign-csr.
	ErrRoleRequired = errors.New("--role is required for sign-csr")

	// ErrJSONParseFailed is returned when a JSON response cannot be parsed.
	ErrJSONParseFailed = errors.New("failed to parse JSON response")

	// ErrJSONMarshalFailed is returned when a request cannot be marshalled to JSON.
	ErrJSONMarshalFailed = errors.New("failed to marshal JSON request")

	// ErrNonceDecode is returned when a nonce cannot be decoded.
	ErrNonceDecode = errors.New("failed to decode nonce")

	// ErrBase64Decode is returned when base64 decoding fails.
	ErrBase64Decode = errors.New("failed to decode base64 data")

	// ErrCertFileWrite is returned when a certificate file cannot be written.
	ErrCertFileWrite = errors.New("failed to write certificate file")

	// ErrShareFileWrite is returned when a share file cannot be written.
	ErrShareFileWrite = errors.New("failed to write share file")

	// ErrKeyGenFailed is returned when key generation fails.
	ErrKeyGenFailed = errors.New("failed to generate key pair")

	// ErrPubKeyMarshalFailed is returned when public key marshalling fails.
	ErrPubKeyMarshalFailed = errors.New("failed to marshal public key")

	// ErrInvalidCA is returned when the CA certificate is invalid.
	ErrInvalidCA = errors.New("invalid CA certificate")

	// FIDO2 virtual device errors

	// ErrVirtualStorageInit is returned when the file-based storage backend
	// for a virtual FIDO2 device cannot be initialized.
	ErrVirtualStorageInit = errors.New("fido2: failed to initialize virtual device storage")

	// ErrVirtualCredentialStorageInit is returned when the credential storage
	// adapter for a virtual FIDO2 device cannot be created.
	ErrVirtualCredentialStorageInit = errors.New("fido2: failed to create virtual credential storage")
)

// Sentinel errors introduced by the typed-errors migration. Each classifies
// a CLI failure mode; wrap sites pair them with an underlying cause via
// WrappedError / WrappedDetailError.
var (
	// ErrAddCustodianMemberFailed is the sentinel error "failed to add custodian member".
	ErrAddCustodianMemberFailed = errors.New("failed to add custodian member")

	// ErrAggregateSignaturesFailed is the sentinel error "failed to aggregate signatures".
	ErrAggregateSignaturesFailed = errors.New("failed to aggregate signatures")

	// ErrAuthenticationFailed is the sentinel error "authentication failed".
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrBeginAuthenticationFailed is the sentinel error "failed to begin authentication".
	ErrBeginAuthenticationFailed = errors.New("failed to begin authentication")

	// ErrBeginRegistrationFailed is the sentinel error "failed to begin registration".
	ErrBeginRegistrationFailed = errors.New("failed to begin registration")

	// ErrBindCertFailed is the sentinel error "failed to bind cert".
	ErrBindCertFailed = errors.New("failed to bind cert")

	// ErrBootstrapDirectBundleRequired is the sentinel error "bootstrap direct: --bundle is required".
	ErrBootstrapDirectBundleRequired = errors.New("bootstrap direct: --bundle is required")

	// ErrBootstrapDirectBundleStat is the sentinel error "bootstrap direct: cannot stat bundle".
	ErrBootstrapDirectBundleStat = errors.New("bootstrap direct: cannot stat bundle")

	// ErrCACertFileRequired is the sentinel error "CA certificate file (--ca-cert) is required".
	ErrCACertFileRequired = errors.New("CA certificate file (--ca-cert) is required")

	// ErrCAKeyFileRequired is the sentinel error "CA private key file (--ca-key) is required".
	ErrCAKeyFileRequired = errors.New("CA private key file (--ca-key) is required")

	// ErrCertFileRequired is the sentinel error "--cert-file is required".
	ErrCertFileRequired = errors.New("--cert-file is required")

	// ErrCertFileRequiredVerification is the sentinel error "--cert-file is required for verification".
	ErrCertFileRequiredVerification = errors.New("--cert-file is required for verification")

	// ErrCheckAdminStatusFailed is the sentinel error "failed to check admin status".
	ErrCheckAdminStatusFailed = errors.New("failed to check admin status")

	// ErrCheckCertificateExistenceFailed is the sentinel error "failed to check certificate existence".
	ErrCheckCertificateExistenceFailed = errors.New("failed to check certificate existence")

	// ErrCheckRevocationStatusFailed is the sentinel error "failed to check revocation status".
	ErrCheckRevocationStatusFailed = errors.New("failed to check revocation status")

	// ErrCheckSealingSupportFailed is the sentinel error "failed to check sealing support".
	ErrCheckSealingSupportFailed = errors.New("failed to check sealing support")

	// ErrCheckUserStatusFailed is the sentinel error "failed to check user status".
	ErrCheckUserStatusFailed = errors.New("failed to check user status")

	// ErrCiphertextInputRequired is the sentinel error "ciphertext must be provided as argument, via --ciphertext, or via --ciphertext-file".
	ErrCiphertextInputRequired = errors.New("ciphertext must be provided as argument, via --ciphertext, or via --ciphertext-file")

	// ErrCommonNameRequired is the sentinel error "common name (--cn) is required".
	ErrCommonNameRequired = errors.New("common name (--cn) is required")

	// ErrConnectFailed is the sentinel error "failed to connect".
	ErrConnectFailed = errors.New("failed to connect")

	// ErrCopyKeyFailed is the sentinel error "failed to copy key".
	ErrCopyKeyFailed = errors.New("failed to copy key")

	// ErrCreateAdminFailed is the sentinel error "failed to create admin".
	ErrCreateAdminFailed = errors.New("failed to create admin")

	// ErrCreateBackendFailed is the sentinel error "failed to create backend".
	ErrCreateBackendFailed = errors.New("failed to create backend")

	// ErrCreateCertStorageFailed is the sentinel error "failed to create cert storage".
	ErrCreateCertStorageFailed = errors.New("failed to create cert storage")

	// ErrCreateCertificateFailed is the sentinel error "failed to create certificate".
	ErrCreateCertificateFailed = errors.New("failed to create certificate")

	// ErrCreateClientFailed is the sentinel error "failed to create client".
	ErrCreateClientFailed = errors.New("failed to create client")

	// ErrCreateClientFromURLFailed is the sentinel error "failed to create client from URL".
	ErrCreateClientFromURLFailed = errors.New("failed to create client from URL")

	// ErrCreateCustodianGroupFailed is the sentinel error "failed to create custodian group".
	ErrCreateCustodianGroupFailed = errors.New("failed to create custodian group")

	// ErrCreateDestinationBackendFailed is the sentinel error "failed to create destination backend".
	ErrCreateDestinationBackendFailed = errors.New("failed to create destination backend")

	// ErrCreateExportDirectoryFailed is the sentinel error "failed to create export directory".
	ErrCreateExportDirectoryFailed = errors.New("failed to create export directory")

	// ErrCreateFIDO2HandlerFailed is the sentinel error "failed to create FIDO2 handler".
	ErrCreateFIDO2HandlerFailed = errors.New("failed to create FIDO2 handler")

	// ErrCreateFROSTBackendFailed is the sentinel error "failed to create FROST backend".
	ErrCreateFROSTBackendFailed = errors.New("failed to create FROST backend")

	// ErrCreateMigrationPlanFailed is the sentinel error "failed to create migration plan".
	ErrCreateMigrationPlanFailed = errors.New("failed to create migration plan")

	// ErrCreateMigratorFailed is the sentinel error "failed to create migrator".
	ErrCreateMigratorFailed = errors.New("failed to create migrator")

	// ErrCreateOutputDirectoryFailed is the sentinel error "failed to create output directory".
	ErrCreateOutputDirectoryFailed = errors.New("failed to create output directory")

	// ErrCreatePKCS11TLSConfigFailed is the sentinel error "failed to create PKCS#11 TLS config".
	ErrCreatePKCS11TLSConfigFailed = errors.New("failed to create PKCS#11 TLS config")

	// ErrCreatePublicDirectoryFailed is the sentinel error "failed to create public directory".
	ErrCreatePublicDirectoryFailed = errors.New("failed to create public directory")

	// ErrCreatePublicStorageFailed is the sentinel error "failed to create public storage".
	ErrCreatePublicStorageFailed = errors.New("failed to create public storage")

	// ErrCreateSecretDirectoryFailed is the sentinel error "failed to create secret directory".
	ErrCreateSecretDirectoryFailed = errors.New("failed to create secret directory")

	// ErrCreateSecretStorageFailed is the sentinel error "failed to create secret storage".
	ErrCreateSecretStorageFailed = errors.New("failed to create secret storage")

	// ErrCreateSoftwareBackendFailed is the sentinel error "failed to create software backend".
	ErrCreateSoftwareBackendFailed = errors.New("failed to create software backend")

	// ErrCreateSourceBackendFailed is the sentinel error "failed to create source backend".
	ErrCreateSourceBackendFailed = errors.New("failed to create source backend")

	// ErrCreateStorageBackendFailed is the sentinel error "failed to create storage backend".
	ErrCreateStorageBackendFailed = errors.New("failed to create storage backend")

	// ErrCreateTenantFailed is the sentinel error "failed to create tenant".
	ErrCreateTenantFailed = errors.New("failed to create tenant")

	// ErrCreateUserFailed is the sentinel error "failed to create user".
	ErrCreateUserFailed = errors.New("failed to create user")

	// ErrCreateVirtualDeviceFailed is the sentinel error "failed to create virtual device".
	ErrCreateVirtualDeviceFailed = errors.New("failed to create virtual device")

	// ErrCredentialIDRequired is the sentinel error "credential-id is required".
	ErrCredentialIDRequired = errors.New("credential-id is required")

	// ErrDataInputRequired is the sentinel error "data must be provided as argument or via --data-file".
	ErrDataInputRequired = errors.New("data must be provided as argument or via --data-file")

	// ErrDealerModeExportDirRequired is the sentinel error "dealer mode requires --export-dir to specify where to save packages".
	ErrDealerModeExportDirRequired = errors.New("dealer mode requires --export-dir to specify where to save packages")

	// ErrDecodeBase64OrHex is the sentinel error "could not decode as base64 or hex".
	ErrDecodeBase64OrHex = errors.New("could not decode as base64 or hex")

	// ErrDecodeCACertificatePEMFailed is the sentinel error "failed to decode CA certificate PEM".
	ErrDecodeCACertificatePEMFailed = errors.New("failed to decode CA certificate PEM")

	// ErrDecodeCAPrivateKeyPEMFailed is the sentinel error "failed to decode CA private key PEM".
	ErrDecodeCAPrivateKeyPEMFailed = errors.New("failed to decode CA private key PEM")

	// ErrDecodeCertificatePEMFailed is the sentinel error "failed to decode certificate PEM".
	ErrDecodeCertificatePEMFailed = errors.New("failed to decode certificate PEM")

	// ErrDecodeCiphertextFailed is the sentinel error "failed to decode ciphertext".
	ErrDecodeCiphertextFailed = errors.New("failed to decode ciphertext")

	// ErrDecodeGroupPublicKeyFailed is the sentinel error "failed to decode group public key".
	ErrDecodeGroupPublicKeyFailed = errors.New("failed to decode group public key")

	// ErrDecodeKeyFailed is the sentinel error "failed to decode key".
	ErrDecodeKeyFailed = errors.New("failed to decode key")

	// ErrDecodePEMBlockFailed is the sentinel error "failed to decode PEM block".
	ErrDecodePEMBlockFailed = errors.New("failed to decode PEM block")

	// ErrDecodeSecretShareFailed is the sentinel error "failed to decode secret share".
	ErrDecodeSecretShareFailed = errors.New("failed to decode secret share")

	// ErrDecodeShareFailed is the sentinel error "failed to decode share".
	ErrDecodeShareFailed = errors.New("failed to decode share")

	// ErrDecodeSignatureFailed is the sentinel error "failed to decode signature".
	ErrDecodeSignatureFailed = errors.New("failed to decode signature")

	// ErrDecodeTagFailed is the sentinel error "failed to decode tag".
	ErrDecodeTagFailed = errors.New("failed to decode tag")

	// ErrDecodeUserHandleFailed is the sentinel error "failed to decode user handle".
	ErrDecodeUserHandleFailed = errors.New("failed to decode user handle")

	// ErrDecryptDataFailed is the sentinel error "failed to decrypt data".
	ErrDecryptDataFailed = errors.New("failed to decrypt data")

	// ErrDeleteAdminFailed is the sentinel error "failed to delete admin".
	ErrDeleteAdminFailed = errors.New("failed to delete admin")

	// ErrDeleteCertificateFailed is the sentinel error "failed to delete certificate".
	ErrDeleteCertificateFailed = errors.New("failed to delete certificate")

	// ErrDeleteCustodianGroupFailed is the sentinel error "failed to delete custodian group".
	ErrDeleteCustodianGroupFailed = errors.New("failed to delete custodian group")

	// ErrDeleteKeyFailed is the sentinel error "failed to delete key".
	ErrDeleteKeyFailed = errors.New("failed to delete key")

	// ErrDeletePIVCertificateFailed is the sentinel error "failed to delete PIV certificate".
	ErrDeletePIVCertificateFailed = errors.New("failed to delete PIV certificate")

	// ErrDeleteTenantFailed is the sentinel error "failed to delete tenant".
	ErrDeleteTenantFailed = errors.New("failed to delete tenant")

	// ErrDeleteUserFailed is the sentinel error "failed to delete user".
	ErrDeleteUserFailed = errors.New("failed to delete user")

	// ErrDeserializeImportParametersFailed is the sentinel error "failed to deserialize import parameters".
	ErrDeserializeImportParametersFailed = errors.New("failed to deserialize import parameters")

	// ErrDeserializeWrappedKeyFailed is the sentinel error "failed to deserialize wrapped key".
	ErrDeserializeWrappedKeyFailed = errors.New("failed to deserialize wrapped key")

	// ErrDeserializeWrappedKeyMaterialFailed is the sentinel error "failed to deserialize wrapped key material".
	ErrDeserializeWrappedKeyMaterialFailed = errors.New("failed to deserialize wrapped key material")

	// ErrDeviceNotFound is the sentinel error "device not found".
	ErrDeviceNotFound = errors.New("device not found")

	// ErrDisableAdminFailed is the sentinel error "failed to disable admin".
	ErrDisableAdminFailed = errors.New("failed to disable admin")

	// ErrDisableUserFailed is the sentinel error "failed to disable user".
	ErrDisableUserFailed = errors.New("failed to disable user")

	// ErrDisconnectFailed is the sentinel error "failed to disconnect".
	ErrDisconnectFailed = errors.New("failed to disconnect")

	// ErrDistributeSharesFailed is the sentinel error "failed to distribute shares".
	ErrDistributeSharesFailed = errors.New("failed to distribute shares")

	// ErrEnableAdminFailed is the sentinel error "failed to enable admin".
	ErrEnableAdminFailed = errors.New("failed to enable admin")

	// ErrEnableEncryptionFailed is the sentinel error "failed to enable encryption".
	ErrEnableEncryptionFailed = errors.New("failed to enable encryption")

	// ErrEnableUserFailed is the sentinel error "failed to enable user".
	ErrEnableUserFailed = errors.New("failed to enable user")

	// ErrEncryptDataFailed is the sentinel error "failed to encrypt data".
	ErrEncryptDataFailed = errors.New("failed to encrypt data")

	// ErrEnrollDeviceFailed is the sentinel error "failed to enroll device".
	ErrEnrollDeviceFailed = errors.New("failed to enroll device")

	// ErrExportKeyFailed is the sentinel error "failed to export key".
	ErrExportKeyFailed = errors.New("failed to export key")

	// ErrExportPIVCertificateFailed is the sentinel error "failed to export PIV certificate".
	ErrExportPIVCertificateFailed = errors.New("failed to export PIV certificate")

	// ErrFROSTVerifyFailed is the sentinel error "signature verification FAILED".
	ErrFROSTVerifyFailed = errors.New("signature verification FAILED")

	// ErrFileSecretBackendUnsupported is the sentinel error "not implemented for file secret backend".
	ErrFileSecretBackendUnsupported = errors.New("not implemented for file secret backend")

	// ErrFinishAuthenticationFailed is the sentinel error "failed to finish authentication".
	ErrFinishAuthenticationFailed = errors.New("failed to finish authentication")

	// ErrFinishRegistrationFailed is the sentinel error "failed to finish registration".
	ErrFinishRegistrationFailed = errors.New("failed to finish registration")

	// ErrFromToFlagsRequired is the sentinel error "both --from and --to flags are required".
	ErrFromToFlagsRequired = errors.New("both --from and --to flags are required")

	// ErrGenerateCAFailed is the sentinel error "failed to generate CA".
	ErrGenerateCAFailed = errors.New("failed to generate CA")

	// ErrGenerateCRLFailed is the sentinel error "failed to generate CRL".
	ErrGenerateCRLFailed = errors.New("failed to generate CRL")

	// ErrGenerateFROSTKeyFailed is the sentinel error "failed to generate FROST key".
	ErrGenerateFROSTKeyFailed = errors.New("failed to generate FROST key")

	// ErrGenerateFROSTPackagesFailed is the sentinel error "failed to generate FROST packages".
	ErrGenerateFROSTPackagesFailed = errors.New("failed to generate FROST packages")

	// ErrGenerateKeyFailed is the sentinel error "failed to generate key".
	ErrGenerateKeyFailed = errors.New("failed to generate key")

	// ErrGenerateNoncesFailed is the sentinel error "failed to generate nonces".
	ErrGenerateNoncesFailed = errors.New("failed to generate nonces")

	// ErrGeneratePIVCSRFailed is the sentinel error "failed to generate PIV CSR".
	ErrGeneratePIVCSRFailed = errors.New("failed to generate PIV CSR")

	// ErrGeneratePIVKeyFailed is the sentinel error "failed to generate PIV key".
	ErrGeneratePIVKeyFailed = errors.New("failed to generate PIV key")

	// ErrGenerateRecoveryKeysFailed is the sentinel error "failed to generate recovery keys".
	ErrGenerateRecoveryKeysFailed = errors.New("failed to generate recovery keys")

	// ErrGenerateSerialNumberFailed is the sentinel error "failed to generate serial number".
	ErrGenerateSerialNumberFailed = errors.New("failed to generate serial number")

	// ErrGenerateSignatureShareFailed is the sentinel error "failed to generate signature share".
	ErrGenerateSignatureShareFailed = errors.New("failed to generate signature share")

	// ErrGetAdminFailed is the sentinel error "failed to get admin".
	ErrGetAdminFailed = errors.New("failed to get admin")

	// ErrGetBackendInfoFailed is the sentinel error "failed to get backend info".
	ErrGetBackendInfoFailed = errors.New("failed to get backend info")

	// ErrGetBarrierStatusFailed is the sentinel error "failed to get barrier status".
	ErrGetBarrierStatusFailed = errors.New("failed to get barrier status")

	// ErrGetCABundleFailed is the sentinel error "failed to get CA bundle".
	ErrGetCABundleFailed = errors.New("failed to get CA bundle")

	// ErrGetCACertificateFailed is the sentinel error "failed to get CA certificate".
	ErrGetCACertificateFailed = errors.New("failed to get CA certificate")

	// ErrGetCertificateChainFailed is the sentinel error "failed to get certificate chain".
	ErrGetCertificateChainFailed = errors.New("failed to get certificate chain")

	// ErrGetCertificateFailed is the sentinel error "failed to get certificate".
	ErrGetCertificateFailed = errors.New("failed to get certificate")

	// ErrGetClusterStatusFailed is the sentinel error "failed to get cluster status".
	ErrGetClusterStatusFailed = errors.New("failed to get cluster status")

	// ErrGetCustodianGroupFailed is the sentinel error "failed to get custodian group".
	ErrGetCustodianGroupFailed = errors.New("failed to get custodian group")

	// ErrGetImportParametersFailed is the sentinel error "failed to get import parameters".
	ErrGetImportParametersFailed = errors.New("failed to get import parameters")

	// ErrGetKeyFailed is the sentinel error "failed to get key".
	ErrGetKeyFailed = errors.New("failed to get key")

	// ErrGetPIVCertificateFailed is the sentinel error "failed to get PIV certificate".
	ErrGetPIVCertificateFailed = errors.New("failed to get PIV certificate")

	// ErrGetSecretFailed is the sentinel error "failed to get secret".
	ErrGetSecretFailed = errors.New("failed to get secret")

	// ErrGetTenantFailed is the sentinel error "failed to get tenant".
	ErrGetTenantFailed = errors.New("failed to get tenant")

	// ErrGetUserFailed is the sentinel error "failed to get user".
	ErrGetUserFailed = errors.New("failed to get user")

	// ErrHostnameRequired is the sentinel error "--hostname is required".
	ErrHostnameRequired = errors.New("--hostname is required")

	// ErrImportKeyFailed is the sentinel error "failed to import key".
	ErrImportKeyFailed = errors.New("failed to import key")

	// ErrImportPIVCertificateFailed is the sentinel error "failed to import PIV certificate".
	ErrImportPIVCertificateFailed = errors.New("failed to import PIV certificate")

	// ErrInitSOPINRequired is the sentinel error "xkmsctl init: --so-pin is required (or set XKMS_SO_PIN)".
	ErrInitSOPINRequired = errors.New("xkmsctl init: --so-pin is required (or set XKMS_SO_PIN)")

	// ErrInitSharesRequireShamir is the sentinel error "xkmsctl init: --shares / --threshold only valid when --barrier-strategy=shamir".
	ErrInitSharesRequireShamir = errors.New("xkmsctl init: --shares / --threshold only valid when --barrier-strategy=shamir")

	// ErrInitSharesRequired is the sentinel error "xkmsctl init: --shares >= 2 required when --barrier-strategy=shamir".
	ErrInitSharesRequired = errors.New("xkmsctl init: --shares >= 2 required when --barrier-strategy=shamir")

	// ErrInitThresholdRequired is the sentinel error "xkmsctl init: --threshold (2 <= threshold <= shares) required when --barrier-strategy=shamir".
	ErrInitThresholdRequired = errors.New("xkmsctl init: --threshold (2 <= threshold <= shares) required when --barrier-strategy=shamir")

	// ErrInitUserPINRequired is the sentinel error "xkmsctl init: --user-pin is required (or set XKMS_USER_PIN)".
	ErrInitUserPINRequired = errors.New("xkmsctl init: --user-pin is required (or set XKMS_USER_PIN)")

	// ErrInitializeBarrierFailed is the sentinel error "failed to initialize barrier".
	ErrInitializeBarrierFailed = errors.New("failed to initialize barrier")

	// ErrInitializeShamirBarrierFailed is the sentinel error "failed to initialize Shamir barrier".
	ErrInitializeShamirBarrierFailed = errors.New("failed to initialize Shamir barrier")

	// ErrInitializeTenantBarrierFailed is the sentinel error "failed to initialize tenant barrier".
	ErrInitializeTenantBarrierFailed = errors.New("failed to initialize tenant barrier")

	// ErrInitializeTokenFailed is the sentinel error "failed to initialize token".
	ErrInitializeTokenFailed = errors.New("failed to initialize token")

	// ErrInvalidAESKeySize is the sentinel error "invalid AES key size".
	ErrInvalidAESKeySize = errors.New("invalid AES key size")

	// ErrInvalidAlgorithm is the sentinel error "invalid algorithm".
	ErrInvalidAlgorithm = errors.New("invalid algorithm")

	// ErrInvalidBase64Ciphertext is the sentinel error "invalid base64 ciphertext".
	ErrInvalidBase64Ciphertext = errors.New("invalid base64 ciphertext")

	// ErrInvalidBase64Nonce is the sentinel error "invalid base64 nonce".
	ErrInvalidBase64Nonce = errors.New("invalid base64 nonce")

	// ErrInvalidBase64Tag is the sentinel error "invalid base64 tag".
	ErrInvalidBase64Tag = errors.New("invalid base64 tag")

	// ErrInvalidCredentialID is the sentinel error "invalid credential-id".
	ErrInvalidCredentialID = errors.New("invalid credential-id")

	// ErrInvalidCurve is the sentinel error "invalid curve".
	ErrInvalidCurve = errors.New("invalid curve")

	// ErrInvalidIPAddress is the sentinel error "invalid IP address".
	ErrInvalidIPAddress = errors.New("invalid IP address")

	// ErrInvalidKeyAlgorithm is the sentinel error "invalid key algorithm".
	ErrInvalidKeyAlgorithm = errors.New("invalid key algorithm")

	// ErrInvalidKeyParameters is the sentinel error "invalid key parameters".
	ErrInvalidKeyParameters = errors.New("invalid key parameters")

	// ErrInvalidKeyType is the sentinel error "invalid key type".
	ErrInvalidKeyType = errors.New("invalid key type")

	// ErrInvalidMessageHex is the sentinel error "invalid message hex".
	ErrInvalidMessageHex = errors.New("invalid message hex")

	// ErrInvalidRole is the sentinel error "invalid role".
	ErrInvalidRole = errors.New("invalid role")

	// ErrInvalidSalt is the sentinel error "invalid salt".
	ErrInvalidSalt = errors.New("invalid salt")

	// ErrInvalidSignatureHex is the sentinel error "invalid signature hex".
	ErrInvalidSignatureHex = errors.New("invalid signature hex")

	// ErrIssueAKCertificateFailed is the sentinel error "failed to issue AK certificate".
	ErrIssueAKCertificateFailed = errors.New("failed to issue AK certificate")

	// ErrIssueCertificateFailed is the sentinel error "failed to issue certificate".
	ErrIssueCertificateFailed = errors.New("failed to issue certificate")

	// ErrIssueEKCertificateFailed is the sentinel error "failed to issue EK certificate".
	ErrIssueEKCertificateFailed = errors.New("failed to issue EK certificate")

	// ErrKeyIDFromToFlagsRequired is the sentinel error "--key-id, --from, and --to flags are required".
	ErrKeyIDFromToFlagsRequired = errors.New("--key-id, --from, and --to flags are required")

	// ErrKeyInputRequired is the sentinel error "either --key-file or --key-hex is required".
	ErrKeyInputRequired = errors.New("either --key-file or --key-hex is required")

	// ErrLabelRequired is the sentinel error "--label is required".
	ErrLabelRequired = errors.New("--label is required")

	// ErrListAdminsFailed is the sentinel error "failed to list admins".
	ErrListAdminsFailed = errors.New("failed to list admins")

	// ErrListBackendsFailed is the sentinel error "failed to list backends".
	ErrListBackendsFailed = errors.New("failed to list backends")

	// ErrListCertificatesFailed is the sentinel error "failed to list certificates".
	ErrListCertificatesFailed = errors.New("failed to list certificates")

	// ErrListClusterMembersFailed is the sentinel error "failed to list cluster members".
	ErrListClusterMembersFailed = errors.New("failed to list cluster members")

	// ErrListCredentialsFailed is the sentinel error "failed to list credentials".
	ErrListCredentialsFailed = errors.New("failed to list credentials")

	// ErrListCustodianGroupsFailed is the sentinel error "failed to list custodian groups".
	ErrListCustodianGroupsFailed = errors.New("failed to list custodian groups")

	// ErrListDevicesFailed is the sentinel error "failed to list devices".
	ErrListDevicesFailed = errors.New("failed to list devices")

	// ErrListFIDO2DevicesFailed is the sentinel error "failed to list FIDO2 devices".
	ErrListFIDO2DevicesFailed = errors.New("failed to list FIDO2 devices")

	// ErrListKeysFailed is the sentinel error "failed to list keys".
	ErrListKeysFailed = errors.New("failed to list keys")

	// ErrListPIVSlotsFailed is the sentinel error "failed to list PIV slots".
	ErrListPIVSlotsFailed = errors.New("failed to list PIV slots")

	// ErrListTenantsFailed is the sentinel error "failed to list tenants".
	ErrListTenantsFailed = errors.New("failed to list tenants")

	// ErrListUsersFailed is the sentinel error "failed to list users".
	ErrListUsersFailed = errors.New("failed to list users")

	// ErrLoadPKCS11CertificateFailed is the sentinel error "failed to load PKCS#11 certificate".
	ErrLoadPKCS11CertificateFailed = errors.New("failed to load PKCS#11 certificate")

	// ErrMarshalCommitmentFailed is the sentinel error "failed to marshal commitment".
	ErrMarshalCommitmentFailed = errors.New("failed to marshal commitment")

	// ErrMarshalNoncesFailed is the sentinel error "failed to marshal nonces".
	ErrMarshalNoncesFailed = errors.New("failed to marshal nonces")

	// ErrMarshalPackageFailed is the sentinel error "failed to marshal package".
	ErrMarshalPackageFailed = errors.New("failed to marshal package")

	// ErrMarshalPrivateKeyFailed is the sentinel error "failed to marshal private key".
	ErrMarshalPrivateKeyFailed = errors.New("failed to marshal private key")

	// ErrMarshalShareFailed is the sentinel error "failed to marshal share".
	ErrMarshalShareFailed = errors.New("failed to marshal share")

	// ErrMessageInputRequired is the sentinel error "one of --message, --message-file, or --message-hex is required".
	ErrMessageInputRequired = errors.New("one of --message, --message-file, or --message-hex is required")

	// ErrMigrationFailed is the sentinel error "migration failed".
	ErrMigrationFailed = errors.New("migration failed")

	// ErrModuleIDRequired is the sentinel error "--module-id is required".
	ErrModuleIDRequired = errors.New("--module-id is required")

	// ErrModuleOrModuleIDRequired is the sentinel error "--module or --module-id is required".
	ErrModuleOrModuleIDRequired = errors.New("--module or --module-id is required")

	// ErrModuleRequired is the sentinel error "--module is required".
	ErrModuleRequired = errors.New("--module is required")

	// ErrNoFIDO2DevicesFound is the sentinel error "no FIDO2 devices found".
	ErrNoFIDO2DevicesFound = errors.New("no FIDO2 devices found")

	// ErrNoPEMData is the sentinel error "no PEM data found in file".
	ErrNoPEMData = errors.New("no PEM data found in file")

	// ErrNoPKCS11ModulesFound is the sentinel error "no PKCS#11 modules found; specify --module or --module-id".
	ErrNoPKCS11ModulesFound = errors.New("no PKCS#11 modules found; specify --module or --module-id")

	// ErrPINRequired is the sentinel error "--pin is required".
	ErrPINRequired = errors.New("--pin is required")

	// ErrParseAuthenticationOptionsFailed is the sentinel error "failed to parse authentication options".
	ErrParseAuthenticationOptionsFailed = errors.New("failed to parse authentication options")

	// ErrParseCACertificateFailed is the sentinel error "failed to parse CA certificate".
	ErrParseCACertificateFailed = errors.New("failed to parse CA certificate")

	// ErrParseCAPrivateKeyFailed is the sentinel error "failed to parse CA private key".
	ErrParseCAPrivateKeyFailed = errors.New("failed to parse CA private key")

	// ErrParseCertificateFailed is the sentinel error "failed to parse certificate".
	ErrParseCertificateFailed = errors.New("failed to parse certificate")

	// ErrParseCommitmentFileFailed is the sentinel error "failed to parse commitment file".
	ErrParseCommitmentFileFailed = errors.New("failed to parse commitment file")

	// ErrParseNonceFileFailed is the sentinel error "failed to parse nonce file".
	ErrParseNonceFileFailed = errors.New("failed to parse nonce file")

	// ErrParsePackageFileFailed is the sentinel error "failed to parse package file".
	ErrParsePackageFileFailed = errors.New("failed to parse package file")

	// ErrParseRegistrationOptionsFailed is the sentinel error "failed to parse registration options".
	ErrParseRegistrationOptionsFailed = errors.New("failed to parse registration options")

	// ErrRSAKeySizeTooSmall is the sentinel error "RSA key size must be at least 2048 bits".
	ErrRSAKeySizeTooSmall = errors.New("RSA key size must be at least 2048 bits")

	// ErrReadCACertificateFailed is the sentinel error "failed to read CA certificate".
	ErrReadCACertificateFailed = errors.New("failed to read CA certificate")

	// ErrReadCAPrivateKeyFailed is the sentinel error "failed to read CA private key".
	ErrReadCAPrivateKeyFailed = errors.New("failed to read CA private key")

	// ErrReadCSRFileFailed is the sentinel error "failed to read CSR file".
	ErrReadCSRFileFailed = errors.New("failed to read CSR file")

	// ErrReadCiphertextFileFailed is the sentinel error "failed to read ciphertext file".
	ErrReadCiphertextFileFailed = errors.New("failed to read ciphertext file")

	// ErrReadCommitmentFileFailed is the sentinel error "failed to read commitment file".
	ErrReadCommitmentFileFailed = errors.New("failed to read commitment file")

	// ErrReadDataFileFailed is the sentinel error "failed to read data file".
	ErrReadDataFileFailed = errors.New("failed to read data file")

	// ErrReadEKPublicKeyFileFailed is the sentinel error "failed to read EK public key file".
	ErrReadEKPublicKeyFileFailed = errors.New("failed to read EK public key file")

	// ErrReadKeyFileFailed is the sentinel error "failed to read key file".
	ErrReadKeyFileFailed = errors.New("failed to read key file")

	// ErrReadKeyMaterialFileFailed is the sentinel error "failed to read key material file".
	ErrReadKeyMaterialFileFailed = errors.New("failed to read key material file")

	// ErrReadMessageFileFailed is the sentinel error "failed to read message file".
	ErrReadMessageFileFailed = errors.New("failed to read message file")

	// ErrReadNonceFileFailed is the sentinel error "failed to read nonce file".
	ErrReadNonceFileFailed = errors.New("failed to read nonce file")

	// ErrReadPackageFileFailed is the sentinel error "failed to read package file".
	ErrReadPackageFileFailed = errors.New("failed to read package file")

	// ErrReadPackedCSRFileFailed is the sentinel error "failed to read packed CSR file".
	ErrReadPackedCSRFileFailed = errors.New("failed to read packed CSR file")

	// ErrReadParametersFileFailed is the sentinel error "failed to read parameters file".
	ErrReadParametersFileFailed = errors.New("failed to read parameters file")

	// ErrReadPublicKeyFileFailed is the sentinel error "failed to read public key file".
	ErrReadPublicKeyFileFailed = errors.New("failed to read public key file")

	// ErrReadSignatureFileFailed is the sentinel error "failed to read signature file".
	ErrReadSignatureFileFailed = errors.New("failed to read signature file")

	// ErrReadTCGCSRFileFailed is the sentinel error "failed to read TCG CSR file".
	ErrReadTCGCSRFileFailed = errors.New("failed to read TCG CSR file")

	// ErrReadWrappedKeyFileFailed is the sentinel error "failed to read wrapped key file".
	ErrReadWrappedKeyFileFailed = errors.New("failed to read wrapped key file")

	// ErrRecoverBarrierFailed is the sentinel error "failed to recover barrier".
	ErrRecoverBarrierFailed = errors.New("failed to recover barrier")

	// ErrRegisterCredentialFailed is the sentinel error "failed to register credential".
	ErrRegisterCredentialFailed = errors.New("failed to register credential")

	// ErrRegisterModuleFailed is the sentinel error "failed to register module".
	ErrRegisterModuleFailed = errors.New("failed to register module")

	// ErrRegisterVirtualDeviceFailed is the sentinel error "failed to register virtual device".
	ErrRegisterVirtualDeviceFailed = errors.New("failed to register virtual device")

	// ErrRekeyBarrierFailed is the sentinel error "failed to rekey barrier".
	ErrRekeyBarrierFailed = errors.New("failed to rekey barrier")

	// ErrRemoveCustodianMemberFailed is the sentinel error "failed to remove custodian member".
	ErrRemoveCustodianMemberFailed = errors.New("failed to remove custodian member")

	// ErrRevokeCertificateFailed is the sentinel error "failed to revoke certificate".
	ErrRevokeCertificateFailed = errors.New("failed to revoke certificate")

	// ErrRotateKeyFailed is the sentinel error "failed to rotate key".
	ErrRotateKeyFailed = errors.New("failed to rotate key")

	// ErrSOPINRequired is the sentinel error "--so-pin is required".
	ErrSOPINRequired = errors.New("--so-pin is required")

	// ErrSaltRequired is the sentinel error "salt is required".
	ErrSaltRequired = errors.New("salt is required")

	// ErrSaveCertificateChainFailed is the sentinel error "failed to save certificate chain".
	ErrSaveCertificateChainFailed = errors.New("failed to save certificate chain")

	// ErrSaveCertificateFailed is the sentinel error "failed to save certificate".
	ErrSaveCertificateFailed = errors.New("failed to save certificate")

	// ErrSealBarrierFailed is the sentinel error "failed to seal barrier".
	ErrSealBarrierFailed = errors.New("failed to seal barrier")

	// ErrSealDataFailed is the sentinel error "failed to seal data".
	ErrSealDataFailed = errors.New("failed to seal data")

	// ErrSerializeImportParametersFailed is the sentinel error "failed to serialize import parameters".
	ErrSerializeImportParametersFailed = errors.New("failed to serialize import parameters")

	// ErrSerializeWrappedKeyFailed is the sentinel error "failed to serialize wrapped key".
	ErrSerializeWrappedKeyFailed = errors.New("failed to serialize wrapped key")

	// ErrSetSOPINFailed is the sentinel error "failed to set SO PIN".
	ErrSetSOPINFailed = errors.New("failed to set SO PIN")

	// ErrSetUserPINFailed is the sentinel error "failed to set user PIN".
	ErrSetUserPINFailed = errors.New("failed to set user PIN")

	// ErrSignCSRFailed is the sentinel error "failed to sign CSR".
	ErrSignCSRFailed = errors.New("failed to sign CSR")

	// ErrSignDataFailed is the sentinel error "failed to sign data".
	ErrSignDataFailed = errors.New("failed to sign data")

	// ErrSignTCGCSRFailed is the sentinel error "failed to sign TCG CSR".
	ErrSignTCGCSRFailed = errors.New("failed to sign TCG CSR")

	// ErrSignatureInputRequired is the sentinel error "either --signature or --signature-hex is required".
	ErrSignatureInputRequired = errors.New("either --signature or --signature-hex is required")

	// ErrSignatureInvalid is the sentinel error "signature is invalid".
	ErrSignatureInvalid = errors.New("signature is invalid")

	// ErrSignatureVerificationFailed is the sentinel error "signature verification failed".
	ErrSignatureVerificationFailed = errors.New("signature verification failed")

	// ErrStoreKeyPackageFailed is the sentinel error "failed to store key package".
	ErrStoreKeyPackageFailed = errors.New("failed to store key package")

	// ErrStorePIVCertificateFailed is the sentinel error "failed to store PIV certificate".
	ErrStorePIVCertificateFailed = errors.New("failed to store PIV certificate")

	// ErrStoreSecretFailed is the sentinel error "failed to store secret".
	ErrStoreSecretFailed = errors.New("failed to store secret")

	// ErrUnknownOutputFormat is the sentinel error "unknown output format".
	ErrUnknownOutputFormat = errors.New("unknown output format")

	// ErrUnsealBarrierFailed is the sentinel error "failed to unseal barrier".
	ErrUnsealBarrierFailed = errors.New("failed to unseal barrier")

	// ErrUnsealBarrierSharesFailed is the sentinel error "failed to unseal barrier with shares".
	ErrUnsealBarrierSharesFailed = errors.New("failed to unseal barrier with shares")

	// ErrUnsealDataFailed is the sentinel error "failed to unseal data".
	ErrUnsealDataFailed = errors.New("failed to unseal data")

	// ErrUnsealTenantBarrierFailed is the sentinel error "failed to unseal tenant barrier".
	ErrUnsealTenantBarrierFailed = errors.New("failed to unseal tenant barrier")

	// ErrUnsupportedProtocol is the sentinel error "unsupported protocol".
	ErrUnsupportedProtocol = errors.New("unsupported protocol")

	// ErrUnwrapKeyMaterialFailed is the sentinel error "failed to unwrap key material".
	ErrUnwrapKeyMaterialFailed = errors.New("failed to unwrap key material")

	// ErrUpdateTenantEntitlementsFailed is the sentinel error "failed to update tenant entitlements".
	ErrUpdateTenantEntitlementsFailed = errors.New("failed to update tenant entitlements")

	// ErrUpdateTenantQuotasFailed is the sentinel error "failed to update tenant quotas".
	ErrUpdateTenantQuotasFailed = errors.New("failed to update tenant quotas")

	// ErrUserPINRequired is the sentinel error "--user-pin is required".
	ErrUserPINRequired = errors.New("--user-pin is required")

	// ErrValidationFailed is the sentinel error "validation failed".
	ErrValidationFailed = errors.New("validation failed")

	// ErrVerifySOPINFailed is the sentinel error "failed to verify SO PIN".
	ErrVerifySOPINFailed = errors.New("failed to verify SO PIN")

	// ErrVerifySignatureFailed is the sentinel error "failed to verify signature".
	ErrVerifySignatureFailed = errors.New("failed to verify signature")

	// ErrWaitForDeviceFailed is the sentinel error "failed while waiting for device".
	ErrWaitForDeviceFailed = errors.New("failed while waiting for device")

	// ErrWrapKeyMaterialFailed is the sentinel error "failed to wrap key material".
	ErrWrapKeyMaterialFailed = errors.New("failed to wrap key material")

	// ErrWrappingKeyUnexpectedType is the sentinel error "wrapping public key has unexpected type".
	ErrWrappingKeyUnexpectedType = errors.New("wrapping public key has unexpected type")

	// ErrWriteAKCertificateFailed is the sentinel error "failed to write AK certificate".
	ErrWriteAKCertificateFailed = errors.New("failed to write AK certificate")

	// ErrWriteCRLFailed is the sentinel error "failed to write CRL".
	ErrWriteCRLFailed = errors.New("failed to write CRL")

	// ErrWriteCertificateFailed is the sentinel error "failed to write certificate".
	ErrWriteCertificateFailed = errors.New("failed to write certificate")

	// ErrWriteCommitmentFileFailed is the sentinel error "failed to write commitment file".
	ErrWriteCommitmentFileFailed = errors.New("failed to write commitment file")

	// ErrWriteCredentialBlobFailed is the sentinel error "failed to write credential blob".
	ErrWriteCredentialBlobFailed = errors.New("failed to write credential blob")

	// ErrWriteEKCertificateFailed is the sentinel error "failed to write EK certificate".
	ErrWriteEKCertificateFailed = errors.New("failed to write EK certificate")

	// ErrWriteEncryptedSecretFailed is the sentinel error "failed to write encrypted secret".
	ErrWriteEncryptedSecretFailed = errors.New("failed to write encrypted secret")

	// ErrWriteIAKCertificateFailed is the sentinel error "failed to write IAK certificate".
	ErrWriteIAKCertificateFailed = errors.New("failed to write IAK certificate")

	// ErrWriteIDevIDCertificateFailed is the sentinel error "failed to write IDevID certificate".
	ErrWriteIDevIDCertificateFailed = errors.New("failed to write IDevID certificate")

	// ErrWriteKeyFileFailed is the sentinel error "failed to write key file".
	ErrWriteKeyFileFailed = errors.New("failed to write key file")

	// ErrWriteKeyMaterialFileFailed is the sentinel error "failed to write key material file".
	ErrWriteKeyMaterialFileFailed = errors.New("failed to write key material file")

	// ErrWriteNonceFileFailed is the sentinel error "failed to write nonce file".
	ErrWriteNonceFileFailed = errors.New("failed to write nonce file")

	// ErrWritePackageFileFailed is the sentinel error "failed to write package file".
	ErrWritePackageFileFailed = errors.New("failed to write package file")

	// ErrWriteParametersFileFailed is the sentinel error "failed to write parameters file".
	ErrWriteParametersFileFailed = errors.New("failed to write parameters file")

	// ErrWritePrivateKeyFailed is the sentinel error "failed to write private key".
	ErrWritePrivateKeyFailed = errors.New("failed to write private key")

	// ErrWriteSignatureFileFailed is the sentinel error "failed to write signature file".
	ErrWriteSignatureFileFailed = errors.New("failed to write signature file")

	// ErrWriteWrappedKeyFileFailed is the sentinel error "failed to write wrapped key file".
	ErrWriteWrappedKeyFileFailed = errors.New("failed to write wrapped key file")
)

// WrappedError pairs a sentinel error with an underlying cause, rendering
// as "<sentinel>: <cause>". Both errors are exposed to errors.Is/errors.As
// via Go 1.20+ multi-error unwrapping.
type WrappedError struct {
	// Sentinel is the classifying sentinel error.
	Sentinel error
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *WrappedError) Error() string {
	return e.Sentinel.Error() + ": " + e.Err.Error()
}

// Unwrap returns both the sentinel and the underlying cause.
func (e *WrappedError) Unwrap() []error {
	return []error{e.Sentinel, e.Err}
}

// WrappedDetailError pairs a sentinel error with a contextual detail string
// and an optional underlying cause, rendering as "<sentinel>: <detail>" or
// "<sentinel>: <detail>: <cause>".
type WrappedDetailError struct {
	// Sentinel is the classifying sentinel error.
	Sentinel error
	// Detail is the contextual detail (for example a file path or value).
	Detail string
	// Err is the optional underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *WrappedDetailError) Error() string {
	msg := e.Sentinel.Error() + ": " + e.Detail
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the sentinel and, when present, the underlying cause.
func (e *WrappedDetailError) Unwrap() []error {
	if e.Err != nil {
		return []error{e.Sentinel, e.Err}
	}
	return []error{e.Sentinel}
}

// ConfigLoadError is returned when the xkmsctl configuration file cannot be loaded.
type ConfigLoadError struct {
	// Path is the configuration file path.
	Path string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *ConfigLoadError) Error() string {
	return "xkmsctl: load config " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ConfigLoadError) Unwrap() error { return e.Err }

// InitEnvValueError is returned when an init environment variable holds an
// invalid value for the corresponding flag.
type InitEnvValueError struct {
	// Flag is the flag name whose environment value is invalid.
	Flag string
	// Err is the underlying parse error.
	Err error
}

// Error returns a human-readable description.
func (e *InitEnvValueError) Error() string {
	return "xkmsctl init: invalid env value for " + e.Flag + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *InitEnvValueError) Unwrap() error { return e.Err }

// InitBarrierStrategyError is returned when --barrier-strategy holds an
// unrecognized value.
type InitBarrierStrategyError struct {
	// Strategy is the rejected strategy value.
	Strategy string
}

// Error returns a human-readable description.
func (e *InitBarrierStrategyError) Error() string {
	return fmt.Sprintf("xkmsctl init: invalid --barrier-strategy %q", e.Strategy)
}

// BundlePathIsDirError is returned when the direct-bootstrap bundle path
// refers to a directory instead of a file.
type BundlePathIsDirError struct {
	// Path is the offending bundle path.
	Path string
}

// Error returns a human-readable description.
func (e *BundlePathIsDirError) Error() string {
	return "bootstrap direct: " + e.Path + " is a directory"
}

// PEMBlockDecodeError is returned when no PEM block can be decoded from a file.
type PEMBlockDecodeError struct {
	// Path is the file that contained no decodable PEM block.
	Path string
}

// Error returns a human-readable description.
func (e *PEMBlockDecodeError) Error() string {
	return "failed to decode PEM block from " + e.Path
}

// CertPEMDecodeError is returned when a certificate at a given position in a
// bundle cannot be decoded from PEM.
type CertPEMDecodeError struct {
	// Index is the 1-based certificate position.
	Index int
}

// Error returns a human-readable description.
func (e *CertPEMDecodeError) Error() string {
	return fmt.Sprintf("failed to decode certificate %d PEM", e.Index)
}

// CertFileReadError is returned when a certificate file cannot be read.
type CertFileReadError struct {
	// Path is the certificate file path.
	Path string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *CertFileReadError) Error() string {
	return "failed to read certificate file " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *CertFileReadError) Unwrap() error { return e.Err }

// CertFileParseError is returned when a certificate file cannot be parsed.
type CertFileParseError struct {
	// Path is the certificate file path.
	Path string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *CertFileParseError) Error() string {
	return "failed to parse certificate from " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *CertFileParseError) Unwrap() error { return e.Err }

// CertIndexParseError is returned when a certificate at a given position in
// a bundle cannot be parsed.
type CertIndexParseError struct {
	// Index is the 1-based certificate position.
	Index int
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *CertIndexParseError) Error() string {
	return fmt.Sprintf("failed to parse certificate %d: %v", e.Index, e.Err)
}

// Unwrap returns the underlying cause.
func (e *CertIndexParseError) Unwrap() error { return e.Err }

// CommitmentFileReadError is returned when a FROST commitment file cannot be read.
type CommitmentFileReadError struct {
	// Path is the commitment file path.
	Path string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *CommitmentFileReadError) Error() string {
	return "failed to read commitment file " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *CommitmentFileReadError) Unwrap() error { return e.Err }

// CommitmentFileParseError is returned when a FROST commitment file cannot be parsed.
type CommitmentFileParseError struct {
	// Path is the commitment file path.
	Path string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *CommitmentFileParseError) Error() string {
	return "failed to parse commitment file " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *CommitmentFileParseError) Unwrap() error { return e.Err }

// ShareFileReadError is returned when a FROST signature-share file cannot be read.
type ShareFileReadError struct {
	// Path is the share file path.
	Path string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *ShareFileReadError) Error() string {
	return "failed to read share file " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ShareFileReadError) Unwrap() error { return e.Err }

// ShareFileParseError is returned when a FROST signature-share file cannot be parsed.
type ShareFileParseError struct {
	// Path is the share file path.
	Path string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *ShareFileParseError) Error() string {
	return "failed to parse share file " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ShareFileParseError) Unwrap() error { return e.Err }

// ShareDecodeError is returned when a FROST signature share cannot be decoded.
type ShareDecodeError struct {
	// Path is the share file path.
	Path string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *ShareDecodeError) Error() string {
	return "failed to decode share from " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying cause.
func (e *ShareDecodeError) Unwrap() error { return e.Err }

// VerificationShareDecodeError is returned when a FROST verification share
// cannot be hex-decoded.
type VerificationShareDecodeError struct {
	// ID is the participant ID owning the share.
	ID uint32
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *VerificationShareDecodeError) Error() string {
	return fmt.Sprintf("failed to decode verification share %d: %v", e.ID, e.Err)
}

// Unwrap returns the underlying cause.
func (e *VerificationShareDecodeError) Unwrap() error { return e.Err }

// ParticipantCountError is returned when the number of FROST participants
// does not match the configured total.
type ParticipantCountError struct {
	// Count is the number of participants supplied.
	Count int
	// Total is the configured total.
	Total int
}

// Error returns a human-readable description.
func (e *ParticipantCountError) Error() string {
	return fmt.Sprintf("number of participants (%d) must match total (%d)", e.Count, e.Total)
}

// ParticipantIDRangeError is returned when --participant-id is out of range.
type ParticipantIDRangeError struct {
	// Total is the configured total number of participants.
	Total int
}

// Error returns a human-readable description.
func (e *ParticipantIDRangeError) Error() string {
	return fmt.Sprintf("participant-id must be between 1 and %d", e.Total)
}

// ParticipantPackageNotFoundError is returned when no generated FROST key
// package matches the requested participant.
type ParticipantPackageNotFoundError struct {
	// ID is the participant ID.
	ID uint32
}

// Error returns a human-readable description.
func (e *ParticipantPackageNotFoundError) Error() string {
	return fmt.Sprintf("package for participant %d not found", e.ID)
}

// MigrationResultError carries a per-key failure message reported in a
// migration result.
type MigrationResultError struct {
	// Message is the failure message reported by the migrator.
	Message string
}

// Error returns the reported failure message.
func (e *MigrationResultError) Error() string { return e.Message }

// UserHandleTypeError is returned when a WebAuthn user handle has an
// unexpected dynamic type.
type UserHandleTypeError struct {
	// Handle is the value with the unexpected type.
	Handle any
}

// Error returns a human-readable description.
func (e *UserHandleTypeError) Error() string {
	return fmt.Sprintf("unexpected user handle type %T", e.Handle)
}

// UserNoCredentialsError is returned when a user has no registered credentials.
type UserNoCredentialsError struct {
	// Username is the user without credentials.
	Username string
}

// Error returns a human-readable description.
func (e *UserNoCredentialsError) Error() string {
	return "user " + e.Username + " has no credentials"
}

// TenantBarrierStatusError is returned when the barrier status of a tenant
// cannot be retrieved.
type TenantBarrierStatusError struct {
	// TenantID is the tenant whose barrier status was requested.
	TenantID string
	// Err is the underlying cause.
	Err error
}

// Error returns a human-readable description.
func (e *TenantBarrierStatusError) Error() string {
	return fmt.Sprintf("failed to get barrier status for tenant %q: %v", e.TenantID, e.Err)
}

// Unwrap returns the underlying cause.
func (e *TenantBarrierStatusError) Unwrap() error { return e.Err }

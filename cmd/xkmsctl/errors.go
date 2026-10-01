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

	// ErrImportKeyTypeRequired is returned when `key import` is invoked without
	// --key-type. The server cannot infer the algorithm from wrapped material —
	// it is opaque ciphertext — so an import that omits it previously stored a
	// key with no algorithm that no later operation could resolve. Requiring it
	// here turns that silent corruption into an error before anything is sent.
	ErrImportKeyTypeRequired = errors.New("--key-type is required (rsa, ecdsa, ed25519, or aes)")

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

	// ErrExternalOfficerMaterial reports that external-officer enrolment was
	// given both or neither of --cert / --pubkey. Exactly one is required:
	// they are different trust sources (external CA chain vs admin-asserted),
	// so accepting both would leave the trust decision ambiguous.
	ErrExternalOfficerMaterial = errors.New("exactly one of --cert or --pubkey is required")

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

	// ErrShareMissingInResponse is returned when the server answers a share
	// claim with a body that carries no share document.
	ErrShareMissingInResponse = errors.New("server response contained no share")

	// ErrShareGroupIDRequired is returned when a share command needs --group-id.
	ErrShareGroupIDRequired = errors.New("--group-id is required")

	// ErrShareDataRequired is returned when share submission has no share data.
	ErrShareDataRequired = errors.New("share data is required (use --data or --file)")

	// ErrShareDataSourceConflict is returned when both --data and --file are set.
	ErrShareDataSourceConflict = errors.New("only one of --data or --file may be provided")

	// ErrSubmitShareFailed wraps a share submission failure.
	ErrSubmitShareFailed = errors.New("failed to submit share")

	// ErrListSharesFailed wraps a share listing failure.
	ErrListSharesFailed = errors.New("failed to list shares")

	// ErrShareCollectionStatusFailed wraps a collection-status failure.
	ErrShareCollectionStatusFailed = errors.New("failed to get share collection status")

	// ErrReadShareFileFailed wraps a share file read failure.
	ErrReadShareFileFailed = errors.New("failed to read share file")

	// ErrShareServerURLRequired is returned when a per-share command needs
	// --server-url to address the share.
	ErrShareServerURLRequired = errors.New("--server-url is required")

	// ErrListAlgorithmsFailed wraps an algorithm-discovery failure.
	ErrListAlgorithmsFailed = errors.New("failed to list algorithms")

	// ErrGetShareFailed wraps a single-share retrieval failure.
	ErrGetShareFailed = errors.New("failed to get share")

	// ErrDeleteShareFailed wraps a single-share deletion failure.
	ErrDeleteShareFailed = errors.New("failed to delete share")

	// ErrKeyGenFailed is returned when key generation fails.
	ErrKeyGenFailed = errors.New("failed to generate key pair")

	// ErrInvalidCA is returned when the CA certificate is invalid.
	ErrInvalidCA = errors.New("invalid CA certificate")

	// ErrUnsupportedPrivateKeyType is returned when a generated or loaded
	// private key does not implement crypto.Signer, so it cannot be used to
	// issue a certificate.
	ErrUnsupportedPrivateKeyType = errors.New("unsupported private key type")

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

	// ErrAuditFromInvalid is returned when "audit query" is invoked with a
	// --from value that does not parse as RFC3339.
	ErrAuditFromInvalid = errors.New("--from is not a valid RFC3339 timestamp")

	// ErrAuditToInvalid is returned when "audit query" is invoked with a
	// --to value that does not parse as RFC3339.
	ErrAuditToInvalid = errors.New("--to is not a valid RFC3339 timestamp")

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
	// ErrEmailRequired is returned when a FIDO2 registration supplies no email.
	// WebAuthn enrollment resolves by the canonical email login key, so a user
	// registered without one cannot be enrolled by anybody.
	ErrEmailRequired = errors.New("--email is required: it is the canonical login key WebAuthn resolves through")
	// ErrLoginKeyNotEmail is returned when the login key given to a WebAuthn
	// ceremony is not an email address. The server resolves the account by
	// its canonical email login key, so a username would run the ceremony
	// against nothing, or against a second principal keyed by that string.
	ErrLoginKeyNotEmail = errors.New("the login key must be an email address: the server resolves the account by its canonical email login key")

	// ErrCreateCertificateFailed is the sentinel error "failed to create certificate".
	ErrCreateCertificateFailed = errors.New("failed to create certificate")

	// ErrCreateClientFailed is the sentinel error "failed to create client".
	ErrCreateClientFailed = errors.New("failed to create client")

	// ErrCreateClientFromURLFailed is the sentinel error "failed to create client from URL".
	ErrCreateClientFromURLFailed = errors.New("failed to create client from URL")

	// ErrCreateCustodianGroupFailed is the sentinel error "failed to create custodian group".
	ErrCreateCustodianGroupFailed = errors.New("failed to create custodian group")

	// ErrCreateExportDirectoryFailed is the sentinel error "failed to create export directory".
	ErrCreateExportDirectoryFailed = errors.New("failed to create export directory")

	// ErrCreateFIDO2HandlerFailed is the sentinel error "failed to create FIDO2 handler".
	ErrCreateFIDO2HandlerFailed = errors.New("failed to create FIDO2 handler")

	// ErrCreateFROSTBackendFailed is the sentinel error "failed to create FROST backend".
	ErrCreateFROSTBackendFailed = errors.New("failed to create FROST backend")

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

	// ErrDecodeCredentialIDFailed is the sentinel error "failed to decode
	// credential ID" - returned when the credential ID cannot be recovered
	// from the authenticator's attestation JSON.
	ErrDecodeCredentialIDFailed = errors.New("failed to decode credential ID")

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

	// ErrFinishAuthenticationFailed is the sentinel error "failed to finish authentication".
	ErrFinishAuthenticationFailed = errors.New("failed to finish authentication")

	// ErrFinishRegistrationFailed is the sentinel error "failed to finish registration".
	ErrFinishRegistrationFailed = errors.New("failed to finish registration")

	// ErrSoftwareBackendNotSealer is the sentinel error returned when the SDK
	// PKCS#8 backend used to hold the FROST wrapping key unexpectedly does
	// not implement client.SealingKeyProvider. Every production PKCS#8
	// backend does; reaching this indicates an SDK defect, not an operator
	// config mistake.
	ErrSoftwareBackendNotSealer = errors.New("software backend does not implement SealingKeyProvider")

	// ErrProvisionFrostSealKeyFailed is the sentinel error "failed to
	// provision FROST secret wrapping key", returned when the
	// passphrase-encrypted Ed25519 wrapping key (used to seal/unseal FROST
	// secret shares) could not be generated or retrieved for a reason other
	// than a rejected passphrase.
	ErrProvisionFrostSealKeyFailed = errors.New("failed to provision FROST secret wrapping key")

	// ErrFrostPassphraseRequired is returned by every xkmsctl FROST verb
	// that seals or unseals a secret share when no passphrase source was
	// supplied. xkmsctl has no local hardware backend to hold the wrapping
	// key, so the passphrase is the only thing protecting it at rest.
	ErrFrostPassphraseRequired = errors.New("FROST secret shares are protected by a passphrase: supply it with --passphrase-stdin, --passphrase-file or XKMS_FROST_PASSPHRASE")

	// ErrFrostPassphraseEmpty is returned when a FROST passphrase source was
	// supplied but held an empty passphrase.
	ErrFrostPassphraseEmpty = errors.New("FROST passphrase is empty")

	// ErrReadFrostPassphraseFailed is the sentinel error "failed to read
	// FROST passphrase", returned when the stdin or file passphrase source
	// could not be read.
	ErrReadFrostPassphraseFailed = errors.New("failed to read FROST passphrase")

	// ErrFrostPassphraseRejected is returned when a key in the local FROST
	// store -- the share wrapping key or the package recipient key --
	// cannot be decrypted with the supplied passphrase: either the
	// passphrase is wrong, or the key was not written under a passphrase
	// (a key store created before go-xkms#1324) or is corrupt.
	ErrFrostPassphraseRejected = errors.New("FROST passphrase rejected: the local FROST key store could not be decrypted with it")

	// ErrFrostWrapBackendUnsupported is returned when --backend names a
	// backend that the local xkmsctl FROST store cannot hold its wrapping
	// key in. The store supports only the passphrase-encrypted software
	// key; it refuses rather than silently ignoring the requested backend.
	ErrFrostWrapBackendUnsupported = errors.New("xkmsctl frost stores its share wrapping key only in the passphrase-encrypted software backend; unsupported --backend")

	// ErrRestrictFrostDirectoryFailed is the sentinel error "failed to
	// restrict FROST directory to owner-only access".
	ErrRestrictFrostDirectoryFailed = errors.New("failed to restrict FROST directory to owner-only access")

	// ErrFrostRecipientSpecInvalid is returned when a keygen --recipient
	// value is not of the form <participant-id>=<public-key-file>, or names
	// a participant ID outside 1..--total.
	ErrFrostRecipientSpecInvalid = errors.New("invalid --recipient: expected <participant-id>=<public-key-file> with an ID from 1 to --total")

	// ErrFrostRecipientDuplicate is returned when keygen is given more than
	// one --recipient for the same participant ID.
	ErrFrostRecipientDuplicate = errors.New("duplicate --recipient for participant")

	// ErrFrostRecipientReused is returned when keygen is given the same
	// recipient public key for two participants. One holder would receive
	// two shares, which lowers the number of people needed to sign.
	ErrFrostRecipientReused = errors.New("the same recipient public key is given for two participants")

	// ErrFrostRecipientKeyInvalid is returned when a --recipient file does
	// not hold a PEM-encoded ECDSA P-256 public key.
	ErrFrostRecipientKeyInvalid = errors.New("recipient public key must be a PEM-encoded ECDSA P-256 public key")

	// ErrFrostRecipientParticipantMode is returned when --recipient is given
	// to keygen in participant mode, which exports nothing. The flag is
	// refused rather than silently ignored.
	ErrFrostRecipientParticipantMode = errors.New("--recipient applies only to dealer mode (--export-dir)")

	// ErrFrostRecipientKeyMissing is returned by frost import when the key
	// directory holds no recipient key. The participant creates one with
	// `xkmsctl frost recipient` and gives its public key to the dealer
	// before the dealer runs keygen.
	ErrFrostRecipientKeyMissing = errors.New("no FROST recipient key in this --key-dir: run `xkmsctl frost recipient` and send its public key to the dealer")

	// ErrProvisionFrostRecipientKeyFailed is the sentinel error "failed to
	// provision FROST recipient key", returned when the passphrase-encrypted
	// P-256 recipient key could not be generated or read for a reason other
	// than a rejected passphrase.
	ErrProvisionFrostRecipientKeyFailed = errors.New("failed to provision FROST recipient key")

	// ErrWriteRecipientKeyFailed is the sentinel error "failed to write
	// recipient public key".
	ErrWriteRecipientKeyFailed = errors.New("failed to write recipient public key")

	// ErrEncryptPackageFailed is the sentinel error "failed to encrypt key
	// package", returned when dealer keygen cannot encrypt a participant's
	// package to that participant's recipient key.
	ErrEncryptPackageFailed = errors.New("failed to encrypt key package")

	// ErrFrostPackageNotEncrypted is returned by frost import for a package
	// file that carries no encrypted package: a plaintext export written by
	// an earlier build, or not a dealer export at all.
	ErrFrostPackageNotEncrypted = errors.New("key package is not encrypted to a recipient key: ask the dealer to re-export it with --recipient")

	// ErrFrostPackageRecipientMismatch is returned by frost import when the
	// package was encrypted to a recipient key other than the one in this
	// --key-dir: it belongs to another participant.
	ErrFrostPackageRecipientMismatch = errors.New("key package is encrypted to a different recipient key")

	// ErrFrostPackageDecryptFailed is returned by frost import when the
	// package names this key directory's recipient key but does not decrypt
	// under it: the file was modified or corrupted.
	ErrFrostPackageDecryptFailed = errors.New("key package failed to decrypt")

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

	// ErrGetBootstrapListenerKeysFailed is the sentinel error "failed to get bootstrap listener keys".
	ErrGetBootstrapListenerKeysFailed = errors.New("failed to get bootstrap listener keys")

	// ErrGetCABundleFailed is the sentinel error "failed to get CA bundle".
	ErrGetCABundleFailed = errors.New("failed to get CA bundle")

	// ErrGetCACertificateFailed is the sentinel error "failed to get CA certificate".
	ErrGetCACertificateFailed = errors.New("failed to get CA certificate")

	// ErrGetCertificateChainFailed is the sentinel error "failed to get certificate chain".
	ErrGetCertificateChainFailed = errors.New("failed to get certificate chain")

	// ErrGetCertificateFailed is the sentinel error "failed to get certificate".
	ErrGetCertificateFailed = errors.New("failed to get certificate")

	// ErrGetCustodianGroupFailed is the sentinel error "failed to get custodian group".
	ErrGetCustodianGroupFailed = errors.New("failed to get custodian group")

	// ErrGetImportParametersFailed is the sentinel error "failed to get import parameters".
	ErrGetImportParametersFailed = errors.New("failed to get import parameters")

	// ErrGetKeyFailed is the sentinel error "failed to get key".
	ErrGetKeyFailed = errors.New("failed to get key")

	// ErrGetPIVCertificateFailed is the sentinel error "failed to get PIV certificate".
	ErrGetPIVCertificateFailed = errors.New("failed to get PIV certificate")

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

	// ErrKeyInputRequired is the sentinel error "either --key-file or --key-hex is required".
	ErrKeyInputRequired = errors.New("either --key-file or --key-hex is required")

	// ErrOutputFileRequired is the sentinel error "--output is required: the
	// private key is written to a file, never printed".
	ErrOutputFileRequired = errors.New("--output is required: the private key is written to a file, never printed")

	// ErrEncodeKeyFailed is the sentinel error "failed to encode key".
	ErrEncodeKeyFailed = errors.New("failed to encode key")

	// ErrLabelRequired is the sentinel error "--label is required".
	ErrLabelRequired = errors.New("--label is required")

	// ErrListAdminsFailed is the sentinel error "failed to list admins".
	ErrListAdminsFailed = errors.New("failed to list admins")

	// ErrListBackendsFailed is the sentinel error "failed to list backends".
	ErrListBackendsFailed = errors.New("failed to list backends")

	// ErrListCertificatesFailed is the sentinel error "failed to list certificates".
	ErrListCertificatesFailed = errors.New("failed to list certificates")

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

	// ErrQueryAuditFailed is the sentinel error "failed to query audit log".
	ErrQueryAuditFailed = errors.New("failed to query audit log")

	// ErrRSAKeySizeTooLarge is the sentinel error "RSA key size must be at most 4096 bits".
	ErrRSAKeySizeTooLarge = errors.New("RSA key size must be at most 4096 bits")

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

	// ErrDeleteRecoveryKeysFailed wraps a recovery-key deletion failure.
	ErrDeleteRecoveryKeysFailed = errors.New("failed to delete recovery keys")

	// ErrGenerateRootTokenFailed wraps a root-token generation failure.
	ErrGenerateRootTokenFailed = errors.New("failed to generate root token")

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

	// ErrRotateScopeKeysFailed is the sentinel error "failed to rotate the
	// tenant's keys".
	ErrRotateScopeKeysFailed = errors.New("failed to rotate the tenant's keys")

	// ErrRotateScopeKeysPartial is returned when a scope rotation left some
	// keys unrotated; the output lists each one's reason.
	ErrRotateScopeKeysPartial = errors.New("some keys were not rotated")

	// ErrListKeyVersionsFailed is the sentinel error "failed to list key
	// versions".
	ErrListKeyVersionsFailed = errors.New("failed to list key versions")

	// ErrChangeKeyVersionFailed is the sentinel error "failed to change the
	// key version".
	ErrChangeKeyVersionFailed = errors.New("failed to change the key version")

	// ErrInvalidKeyVersion is returned for a key version argument that is
	// not a positive integer.
	ErrInvalidKeyVersion = errors.New("invalid key version: must be a positive integer")

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

// ACME admin errors (cmd/xkmsctl/acme*.go). Kept distinct from the local
// xkms admin/cert sentinels above: both domains speak of "accounts" and
// "certificates", but they name different servers over different SDKs, and
// collapsing them onto the same sentinel would make an error message from
// one read as if it came from the other.
var (
	// ErrInvalidAccountID is returned when an ACME account ID argument does
	// not parse as an unsigned integer.
	ErrInvalidAccountID = errors.New("invalid ACME account ID")

	// ErrListAccountsFailed is the sentinel error "failed to list ACME accounts".
	ErrListAccountsFailed = errors.New("failed to list ACME accounts")

	// ErrGetACMEAccountFailed is the sentinel error "failed to get ACME account".
	ErrGetACMEAccountFailed = errors.New("failed to get ACME account")

	// ErrDisableACMEAccountFailed is the sentinel error "failed to disable ACME account".
	ErrDisableACMEAccountFailed = errors.New("failed to disable ACME account")

	// ErrListACMECertificatesFailed is the sentinel error "failed to list ACME certificates".
	ErrListACMECertificatesFailed = errors.New("failed to list ACME certificates")

	// ErrGetACMECertificateFailed is the sentinel error "failed to get ACME certificate".
	ErrGetACMECertificateFailed = errors.New("failed to get ACME certificate")

	// ErrRevokeACMECertificateFailed is the sentinel error "failed to revoke ACME certificate".
	ErrRevokeACMECertificateFailed = errors.New("failed to revoke ACME certificate")

	// ErrInvalidACMESerial is returned when an ACME certificate serial
	// argument is empty.
	ErrInvalidACMESerial = errors.New("certificate serial number is required")

	// ErrACMETenantIDRequired is returned when an "acme eab" verb is
	// invoked without --tenant. EAB is tenant-scoped in go-xkms's ACME
	// admin plane, so there is no default tenant to fall back to.
	ErrACMETenantIDRequired = errors.New("--tenant is required for EAB operations")

	// ErrACMEEABKIDRequired is returned when "acme eab get/delete" is
	// invoked without a key-ID argument.
	ErrACMEEABKIDRequired = errors.New("EAB key ID is required")

	// ErrCreateACMEEABFailed is the sentinel error "failed to create EAB".
	ErrCreateACMEEABFailed = errors.New("failed to create EAB")

	// ErrGetACMEEABFailed is the sentinel error "failed to get EAB".
	ErrGetACMEEABFailed = errors.New("failed to get EAB")

	// ErrDeleteACMEEABFailed is the sentinel error "failed to delete EAB".
	ErrDeleteACMEEABFailed = errors.New("failed to delete EAB")

	// ErrListACMEEABFailed is the sentinel error "failed to list EABs".
	ErrListACMEEABFailed = errors.New("failed to list EABs")

	// ErrGetACMEStatusFailed is the sentinel error "failed to get CA status".
	ErrGetACMEStatusFailed = errors.New("failed to get CA status")

	// ErrGetACMEStatsFailed is the sentinel error "failed to get CA statistics".
	ErrGetACMEStatsFailed = errors.New("failed to get CA statistics")
)

// Sentinel errors for the password / platform / policy / pin / status
// command groups and the key attestation, ECDH derivation, by-ID wrap,
// and key-material export verbs.
var (
	// ErrReadSecretFailed is returned when a secret cannot be read from a
	// flag, stdin, or an interactive prompt.
	ErrReadSecretFailed = errors.New("failed to read secret")

	// Password store errors

	// ErrPasswordNameRequired is returned when a password entry name is missing.
	ErrPasswordNameRequired = errors.New("password name is required")

	// ErrPasswordIDRequired is returned when a password entry ID is missing.
	ErrPasswordIDRequired = errors.New("password id is required")

	// ErrPasswordSecretRequired is returned when no password value could be
	// resolved from the flag, stdin, or the interactive prompt.
	ErrPasswordSecretRequired = errors.New("password value is required")

	// ErrPasswordUpdateNoFields is returned when a password update names no
	// fields to change.
	ErrPasswordUpdateNoFields = errors.New("password update requires at least one field flag")

	// ErrAccessModeRequired is returned when the password store access mode
	// argument is missing.
	ErrAccessModeRequired = errors.New("access mode is required (pin_per_operation | session_based)")

	// ErrInvalidAccessMode is returned when the password store access mode
	// is not one of the staticpw access modes.
	ErrInvalidAccessMode = errors.New("invalid access mode (valid: pin_per_operation, session_based)")

	// ErrAddPasswordFailed is the sentinel error "failed to add password".
	ErrAddPasswordFailed = errors.New("failed to add password")

	// ErrGetPasswordFailed is the sentinel error "failed to get password".
	ErrGetPasswordFailed = errors.New("failed to get password")

	// ErrListPasswordsFailed is the sentinel error "failed to list passwords".
	ErrListPasswordsFailed = errors.New("failed to list passwords")

	// ErrUpdatePasswordFailed is the sentinel error "failed to update password".
	ErrUpdatePasswordFailed = errors.New("failed to update password")

	// ErrDeletePasswordFailed is the sentinel error "failed to delete password".
	ErrDeletePasswordFailed = errors.New("failed to delete password")

	// ErrUnlockPasswordStoreFailed is the sentinel error "failed to unlock password store".
	ErrUnlockPasswordStoreFailed = errors.New("failed to unlock password store")

	// ErrLockPasswordStoreFailed is the sentinel error "failed to lock password store".
	ErrLockPasswordStoreFailed = errors.New("failed to lock password store")

	// ErrPasswordStoreStatusFailed is the sentinel error "failed to get password store status".
	ErrPasswordStoreStatusFailed = errors.New("failed to get password store status")

	// ErrSetPasswordAccessModeFailed is the sentinel error "failed to set password store access mode".
	ErrSetPasswordAccessModeFailed = errors.New("failed to set password store access mode")

	// ErrGeneratePasswordFailed is the sentinel error "failed to generate password".
	ErrGeneratePasswordFailed = errors.New("failed to generate password")

	// Personal password vault errors

	// ErrVaultPassphraseRequired is returned when no vault passphrase could
	// be resolved from the flag, stdin, or the interactive prompt.
	ErrVaultPassphraseRequired = errors.New("vault passphrase is required")

	// ErrVaultPassphraseMismatch is returned when the interactively
	// confirmed new passphrase does not match the first entry.
	ErrVaultPassphraseMismatch = errors.New("vault passphrases do not match")

	// ErrVaultRecoveryCodeRequired is returned when no recovery code could
	// be resolved from the flag, stdin, or the interactive prompt.
	ErrVaultRecoveryCodeRequired = errors.New("vault recovery code is required")

	// ErrVaultFactorIDRequired is returned when a vault verb that acts on
	// one factor is not given --factor-id.
	ErrVaultFactorIDRequired = errors.New("vault factor id is required (--factor-id; see \"password vault status\")")

	// ErrVaultSingleStdin is returned when more than one secret flag is
	// "-": standard input can carry only one secret per invocation.
	ErrVaultSingleStdin = errors.New("only one of --recovery-code and --passphrase may read standard input (\"-\")")

	// ErrVaultStatusFailed is the sentinel error "failed to get vault status".
	ErrVaultStatusFailed = errors.New("failed to get vault status")

	// ErrVaultEnrollFailed is the sentinel error "failed to enroll vault factor".
	ErrVaultEnrollFailed = errors.New("failed to enroll vault factor")

	// ErrVaultRotateFailed is the sentinel error "failed to rotate vault factor".
	ErrVaultRotateFailed = errors.New("failed to rotate vault factor")

	// ErrVaultRemoveFactorFailed is the sentinel error "failed to remove vault factor".
	ErrVaultRemoveFactorFailed = errors.New("failed to remove vault factor")

	// ErrVaultRecoverFailed is the sentinel error "failed to recover vault".
	ErrVaultRecoverFailed = errors.New("failed to recover vault")

	// ErrVaultPasskeyWithPassphrase is returned when a vault verb is given
	// both --passkey and --passphrase: it sends exactly one factor.
	ErrVaultPasskeyWithPassphrase = errors.New("--passkey and --passphrase are mutually exclusive")

	// ErrVaultPINWithoutPasskey is returned when a security key PIN flag is
	// given without --passkey: the PIN serves only a vault passkey and never
	// unlocks the vault by itself.
	ErrVaultPINWithoutPasskey = errors.New("--" + pinFlagStdin + " and --" + pinFlagValue +
		" are the security key PIN and need --passkey")

	// ErrVaultPasskeyPINRequired is returned when no security key PIN was
	// supplied for a vault passkey, which is always PIN-verified.
	ErrVaultPasskeyPINRequired = errors.New("a vault passkey needs your security key's PIN; supply it with --" +
		pinFlagStdin + " (preferred), the " + pinEnvVar + " environment variable, or --" + pinFlagValue)

	// ErrVaultPasskeySingleStdin is returned when both the recovery code and
	// the security key PIN are asked to come from standard input.
	ErrVaultPasskeySingleStdin = errors.New("only one of --recovery-code - and --" + pinFlagStdin +
		" may read standard input; supply the PIN with " + pinEnvVar + " instead")

	// ErrVaultRotatePasskey is returned when rotate names a passkey factor.
	// A passkey's secret is bound to its credential on the security key, so
	// there is no new secret to rotate to.
	ErrVaultRotatePasskey = errors.New("a passkey cannot be rotated: enroll a new passkey " +
		"(\"password vault enroll --passkey\") and remove the old one (\"password vault remove\")")

	// Platform store errors

	// ErrPlatformSecretNameRequired is returned when a platform secret name is missing.
	ErrPlatformSecretNameRequired = errors.New("platform secret name is required")

	// ErrPlatformSecretRequired is returned when no secret bytes could be
	// resolved from --value, --file, stdin, or the interactive prompt.
	ErrPlatformSecretRequired = errors.New("platform secret value is required")

	// ErrPlatformSecretSourceConflict is returned when both --value and
	// --file are supplied for a platform secret.
	ErrPlatformSecretSourceConflict = errors.New("--value and --file are mutually exclusive")

	// ErrReadSecretFileFailed is the sentinel error "failed to read secret file".
	ErrReadSecretFileFailed = errors.New("failed to read secret file")

	// ErrWriteSecretFileFailed is the sentinel error "failed to write secret file".
	ErrWriteSecretFileFailed = errors.New("failed to write secret file")

	// ErrPutPlatformSecretFailed is the sentinel error "failed to store platform secret".
	ErrPutPlatformSecretFailed = errors.New("failed to store platform secret")

	// ErrGetPlatformSecretFailed is the sentinel error "failed to get platform secret".
	ErrGetPlatformSecretFailed = errors.New("failed to get platform secret")

	// ErrDeletePlatformSecretFailed is the sentinel error "failed to delete platform secret".
	ErrDeletePlatformSecretFailed = errors.New("failed to delete platform secret")

	// ErrListPlatformSecretsFailed is the sentinel error "failed to list platform secrets".
	ErrListPlatformSecretsFailed = errors.New("failed to list platform secrets")

	// ErrResealPlatformSecretFailed is the sentinel error "failed to reseal platform secret".
	ErrResealPlatformSecretFailed = errors.New("failed to reseal platform secret")

	// ErrPlatformStoreStatusFailed is the sentinel error "failed to get platform store status".
	ErrPlatformStoreStatusFailed = errors.New("failed to get platform store status")

	// OIDC credential errors

	// ErrOIDCCredentialCreateFailed is the sentinel error "failed to create OIDC credential".
	ErrOIDCCredentialCreateFailed = errors.New("failed to create OIDC credential")

	// ErrOIDCCredentialImportFailed is the sentinel error "failed to import OIDC credential".
	ErrOIDCCredentialImportFailed = errors.New("failed to import OIDC credential")

	// ErrOIDCCredentialListFailed is the sentinel error "failed to list OIDC credentials".
	ErrOIDCCredentialListFailed = errors.New("failed to list OIDC credentials")

	// ErrOIDCCredentialGetFailed is the sentinel error "failed to get OIDC credential".
	ErrOIDCCredentialGetFailed = errors.New("failed to get OIDC credential")

	// ErrOIDCCredentialRefreshFailed is the sentinel error "failed to refresh OIDC credential".
	ErrOIDCCredentialRefreshFailed = errors.New("failed to refresh OIDC credential")

	// ErrOIDCCredentialDeleteFailed is the sentinel error "failed to delete OIDC credential".
	ErrOIDCCredentialDeleteFailed = errors.New("failed to delete OIDC credential")

	// ErrOIDCTokenFailed is the sentinel error "failed to get an OIDC access token".
	ErrOIDCTokenFailed = errors.New("failed to get an OIDC access token")

	// ErrOIDCLoginFailed is the sentinel error "OIDC device login failed".
	ErrOIDCLoginFailed = errors.New("OIDC device login failed")

	// ErrOIDCLoginExpired is returned when a device login is not approved
	// before it expires.
	ErrOIDCLoginExpired = errors.New("OIDC device login was not approved in time")

	// ErrOIDCNoDeviceLogin is returned when the server starts no device
	// login for the credential.
	ErrOIDCNoDeviceLogin = errors.New("the server returned no device login")

	// ErrOIDCAccessTokenRequired is returned by import without
	// --access-token or --codex-auth.
	ErrOIDCAccessTokenRequired = errors.New("import needs --access-token or --codex-auth")

	// ErrOIDCImportSourceConflict is returned when --codex-auth is combined
	// with token flags.
	ErrOIDCImportSourceConflict = errors.New("--codex-auth cannot be combined with --access-token, --refresh-token or --id-token")

	// ErrOIDCCodexAuthRead is returned when the codex auth.json cannot be read.
	ErrOIDCCodexAuthRead = errors.New("failed to read codex auth.json")

	// ErrOIDCCodexAuthWrite is returned when the codex auth.json cannot be written.
	ErrOIDCCodexAuthWrite = errors.New("failed to write codex auth.json")

	// ErrOIDCInvalidExpiry is returned for an --expires-at that is not RFC 3339.
	ErrOIDCInvalidExpiry = errors.New("invalid --expires-at (want RFC 3339)")

	// TPM policy errors

	// ErrTPMPolicyDescribeFailed is the sentinel error "failed to set TPM policy description".
	ErrTPMPolicyDescribeFailed = errors.New("failed to set TPM policy description")

	// ErrInvalidTPMPolicyPCR is returned for a negative PCR index.
	ErrInvalidTPMPolicyPCR = errors.New("invalid PCR index")

	// ErrCreateTPMPolicyFailed is the sentinel error "failed to create TPM policy".
	ErrCreateTPMPolicyFailed = errors.New("failed to create TPM policy")

	// ErrListTPMPoliciesFailed is the sentinel error "failed to list TPM policies".
	ErrListTPMPoliciesFailed = errors.New("failed to list TPM policies")

	// ErrGetTPMPolicyFailed is the sentinel error "failed to get TPM policy".
	ErrGetTPMPolicyFailed = errors.New("failed to get TPM policy")

	// ErrUpdateTPMPolicyFailed is the sentinel error "failed to update TPM policy".
	ErrUpdateTPMPolicyFailed = errors.New("failed to update TPM policy")

	// ErrRevokeTPMPolicyFailed is the sentinel error "failed to revoke TPM policy".
	ErrRevokeTPMPolicyFailed = errors.New("failed to revoke TPM policy")

	// ErrVerifyTPMPolicyFailed is the sentinel error "failed to verify TPM policy".
	ErrVerifyTPMPolicyFailed = errors.New("failed to verify TPM policy")

	// ErrTPMPolicyMismatch is returned when a TPM policy's captured PCR
	// values differ from the live ones.
	ErrTPMPolicyMismatch = errors.New("TPM policy does not match the live PCR values")

	// ErrTPMPolicyNotApproved is returned when a TPM policy has no current
	// approval (it was revoked, or the counter moved past its approval).
	ErrTPMPolicyNotApproved = errors.New("TPM policy is not approved")

	// ErrDeleteTPMPolicyFailed is the sentinel error "failed to delete TPM policy".
	ErrDeleteTPMPolicyFailed = errors.New("failed to delete TPM policy")

	// ErrTPMPolicyObjectsFailed is the sentinel error "failed to list the objects of a TPM policy".
	ErrTPMPolicyObjectsFailed = errors.New("failed to list the objects of a TPM policy")

	// ErrTPMPolicyAutoUnsealFailed is the sentinel error "failed to set TPM policy auto-unseal".
	ErrTPMPolicyAutoUnsealFailed = errors.New("failed to set TPM policy auto-unseal")

	// ErrRotateTPMAuthorityFailed is the sentinel error "failed to rotate the TPM policy authority".
	ErrRotateTPMAuthorityFailed = errors.New("failed to rotate the TPM policy authority")

	// ErrTPMObjectPolicyFailed is the sentinel error "failed to get the TPM policy of an object".
	ErrTPMObjectPolicyFailed = errors.New("failed to get the TPM policy of an object")

	// ErrTenantTPMModeFailed is the sentinel error "failed to get or set a tenant's TPM mode".
	ErrTenantTPMModeFailed = errors.New("failed to get or set a tenant's TPM mode")

	// ErrTPMAreasRequired is returned when only one of --tpm-public and
	// --tpm-private is given: a TPM2 sealed object needs both.
	ErrTPMAreasRequired = errors.New("--tpm-public and --tpm-private must be given together")

	// ErrPasswordSealFailed is returned when a TPM2 sealed object's
	// --password could not be sealed into protected memory.
	ErrPasswordSealFailed = errors.New("failed to seal the sealed-object password into protected memory")

	// ErrPasswordOpenFailed is returned when a TPM2 sealed object's
	// password could not be opened from protected memory for the request.
	ErrPasswordOpenFailed = errors.New("failed to open the sealed-object password from protected memory")

	// ErrInvalidBase64TPMArea is returned when a TPM2 sealed object's area
	// is not valid base64.
	ErrInvalidBase64TPMArea = errors.New("invalid base64 TPM sealed-object area")

	// ErrTenantVTPMFailed is the sentinel error "tenant vTPM operation failed".
	ErrTenantVTPMFailed = errors.New("tenant vTPM operation failed")

	// PIN errors

	// ErrPINEmpty is returned when an interactive or piped PIN resolves to
	// an empty string.
	ErrPINEmpty = errors.New("PIN must not be empty")

	// ErrPINInputStdinEmpty indicates --pin-stdin was given but standard input
	// carried no PIN.
	//
	// Continuing with an empty PIN here would be a silent default: the
	// ceremony that follows fails inside the authenticator with a CTAP error
	// that names neither the PIN nor the flag that supplies it.
	ErrPINInputStdinEmpty = errors.New("pin: --pin-stdin was given but standard input carried no PIN")

	// ErrPINInputStdinRead indicates standard input could not be read.
	ErrPINInputStdinRead = errors.New("pin: failed to read the PIN from standard input")

	// ErrPINInputFlagsMissing indicates the command did not declare the PIN
	// input flags with addPINFlags. It is a wiring defect, not operator input,
	// and is reported rather than swallowed: a command that silently resolved
	// no PIN would look to the operator exactly like an authenticator that
	// needs none.
	ErrPINInputFlagsMissing = errors.New("pin: the command does not declare the PIN input flags")

	// ErrPINInputSealFailed indicates a resolved PIN could not be sealed into
	// protected memory.
	ErrPINInputSealFailed = errors.New("pin: failed to seal the PIN into protected memory")

	// ErrWebAuthnPINRequired indicates the authenticator refused a WebAuthn
	// ceremony because it has a PIN set and none was supplied.
	//
	// It replaces the raw CTAP2_ERR_PIN_REQUIRED, which names neither the PIN
	// nor the way to supply it: "fido2: PIN required" reads as a device fault
	// rather than as missing input. The flag names are composed from the same
	// constants addPINFlags declares, so a rename cannot leave this message
	// naming a flag that no longer exists.
	ErrWebAuthnPINRequired = errors.New("webauthn: this authenticator requires a PIN; supply it with --" +
		pinFlagStdin + " (preferred), the " + pinEnvVar + " environment variable, or --" + pinFlagValue)

	// ErrWebAuthnOriginRequired indicates a WebAuthn ceremony verb could not
	// determine the origin to bind into the ceremony: no --origin was given
	// and --server is not an http(s) URL to derive one from.
	ErrWebAuthnOriginRequired = errors.New("webauthn: the origin cannot be derived from --server; supply it with --" +
		originFlag + " (for example https://kms.example.com)")

	// ErrChangeSOPINFailed is the sentinel error "failed to change SO PIN".
	ErrChangeSOPINFailed = errors.New("failed to change SO PIN")

	// ErrChangeUserPINFailed is the sentinel error "failed to change user PIN".
	ErrChangeUserPINFailed = errors.New("failed to change user PIN")

	// ErrVerifyUserPINFailed is the sentinel error "failed to verify user PIN".
	ErrVerifyUserPINFailed = errors.New("failed to verify user PIN")

	// ErrGetLockoutStatusFailed is the sentinel error "failed to get lockout status".
	ErrGetLockoutStatusFailed = errors.New("failed to get lockout status")

	// ErrResetLockoutFailed is the sentinel error "failed to reset lockout".
	ErrResetLockoutFailed = errors.New("failed to reset lockout")

	// Server status errors

	// ErrHealthCheckFailed is the sentinel error "health check failed".
	ErrHealthCheckFailed = errors.New("health check failed")

	// Key operation errors

	// ErrAttestKeyFailed is the sentinel error "failed to attest key".
	ErrAttestKeyFailed = errors.New("failed to attest key")

	// ErrGenerateNonceFailed is the sentinel error "failed to generate nonce".
	ErrGenerateNonceFailed = errors.New("failed to generate nonce")

	// ErrWriteAttestationFileFailed is the sentinel error "failed to write attestation file".
	ErrWriteAttestationFileFailed = errors.New("failed to write attestation file")

	// ErrDeriveKeyECDHFailed is the sentinel error "failed to derive key via ECDH".
	ErrDeriveKeyECDHFailed = errors.New("failed to derive key via ECDH")

	// ErrPeerPublicKeyRequired is returned when --peer-key is missing for derive-ecdh.
	ErrPeerPublicKeyRequired = errors.New("--peer-key is required (peer public key file)")

	// ErrWriteDerivedKeyFileFailed is the sentinel error "failed to write derived key file".
	ErrWriteDerivedKeyFileFailed = errors.New("failed to write derived key file")

	// ErrWrapKeyByIDFailed is the sentinel error "failed to wrap key by ID".
	ErrWrapKeyByIDFailed = errors.New("failed to wrap key by ID")

	// ErrUnwrapKeyByIDFailed is the sentinel error "failed to unwrap key by ID".
	ErrUnwrapKeyByIDFailed = errors.New("failed to unwrap key by ID")

	// ErrWrappingKeyIDRequired is returned when --wrapping-key is missing for wrap-by-id.
	ErrWrappingKeyIDRequired = errors.New("--wrapping-key is required")

	// ErrUnwrappingKeyIDRequired is returned when --unwrapping-key is missing for unwrap-by-id.
	ErrUnwrappingKeyIDRequired = errors.New("--unwrapping-key is required")

	// ErrWrappedKeyFileRequired is returned when --wrapped-file is missing for unwrap-by-id.
	ErrWrappedKeyFileRequired = errors.New("--wrapped-file is required")

	// ErrExportKeyMaterialFailed is the sentinel error "failed to export key material".
	ErrExportKeyMaterialFailed = errors.New("failed to export key material")

	// User management errors

	// ErrUserUpdateEnableFlagRequired is returned when "user update" is
	// invoked without exactly one of --enable / --disable.
	ErrUserUpdateEnableFlagRequired = errors.New("exactly one of --enable or --disable is required")

	// ErrUserCertSourceRequired is returned when "user bind-cert" is invoked
	// without exactly one of --thumbprint / --cert-file.
	ErrUserCertSourceRequired = errors.New("exactly one of --thumbprint or --cert-file is required")

	// ErrInviteReferenceInvalid is returned when "user invite redeem" cannot
	// resolve a tenant ID and token from its argument and flags: neither an
	// "/invite/<tenant>/<token>" link nor a bare token plus --tenant-id.
	ErrInviteReferenceInvalid = errors.New("invite reference must be the printed invitation link, or a bare token with --tenant-id")

	// ErrInviteMethodInvalid is returned when "user invite redeem --method"
	// names anything other than "fido2" or "piv".
	ErrInviteMethodInvalid = errors.New("--method must be \"fido2\" or \"piv\"")

	// ErrPIVCertFileRequired is returned when "user invite redeem --method
	// piv" is invoked without --piv-cert-file.
	ErrPIVCertFileRequired = errors.New("--piv-cert-file is required with --method piv")

	// ErrGetInviteFailed is the sentinel error "failed to look up invitation".
	ErrGetInviteFailed = errors.New("failed to look up invitation")

	// ErrBeginInviteRegistrationFailed is the sentinel error "failed to begin invitation registration".
	ErrBeginInviteRegistrationFailed = errors.New("failed to begin invitation registration")

	// ErrFinishInviteRegistrationFailed is the sentinel error "failed to finish invitation registration".
	ErrFinishInviteRegistrationFailed = errors.New("failed to finish invitation registration")

	// ErrActivateInvitePIVFailed is the sentinel error "failed to activate invitation with PIV credential".
	ErrActivateInvitePIVFailed = errors.New("failed to activate invitation with PIV credential")
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

// FrostRecipientMissingError is returned when dealer keygen has no
// --recipient for a participant. Every exported package is encrypted to its
// participant's recipient key, so each one must be given.
type FrostRecipientMissingError struct {
	// ID is the participant ID with no recipient key.
	ID uint32
}

// Error returns a human-readable description.
func (e *FrostRecipientMissingError) Error() string {
	return fmt.Sprintf("dealer mode needs --recipient %d=<public-key-file>: each package is encrypted to its participant's recipient key", e.ID)
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

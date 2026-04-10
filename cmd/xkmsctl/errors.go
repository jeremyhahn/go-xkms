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

import "errors"

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

	// ErrBarrierUnsealNoInput is returned when no secret, share, or shares are provided
	// for the barrier unseal command.
	ErrBarrierUnsealNoInput = errors.New("one of --secret, --share, or --shares is required")

	// ErrBarrierRekeyParams is returned when invalid threshold or shares parameters
	// are provided for the barrier rekey command.
	ErrBarrierRekeyParams = errors.New("--threshold and --shares must be positive integers")

	// ErrBarrierRootTokenNoShares is returned when no shares are provided for
	// root token generation.
	ErrBarrierRootTokenNoShares = errors.New("--shares is required for root token generation")

	// ErrBarrierNotShamir is returned when a Shamir-specific operation is attempted
	// on a barrier that does not use the Shamir strategy.
	ErrBarrierNotShamir = errors.New("barrier is not using Shamir strategy")

	// ErrBarrierInvalidShareIndex is returned when an invalid share index is
	// provided for share deletion.
	ErrBarrierInvalidShareIndex = errors.New("share index must be a non-negative integer")

	// ErrBarrierSharesDeleteNoIndex is returned when no index is provided and
	// --all is not set for share deletion.
	ErrBarrierSharesDeleteNoIndex = errors.New("provide a share index or use --all to delete all shares")

	// ErrBarrierRecoveryParams is returned when invalid threshold or keys parameters
	// are provided for recovery key generation.
	ErrBarrierRecoveryParams = errors.New("--threshold and --keys must be positive integers")

	// ErrBarrierRecoveryNoKeys is returned when no recovery keys are provided
	// for barrier recovery.
	ErrBarrierRecoveryNoKeys = errors.New("--keys is required for barrier recovery")

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

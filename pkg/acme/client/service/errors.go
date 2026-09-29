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

// Package service provides a reusable service layer for ACME client operations.
// It wraps the low-level ACME client with higher-level workflows for account
// registration, certificate lifecycle management, device enrollment, and
// automatic renewal.
package service

import (
	"errors"
	"fmt"
)

// ErrChallengeSetupFailed indicates that setting up an ACME challenge failed.
type ErrChallengeSetupFailed struct {
	ChallengeType string
	Reason        string
}

func (e ErrChallengeSetupFailed) Error() string {
	return fmt.Sprintf("acme-client-service: challenge setup failed for %s: %s", e.ChallengeType, e.Reason)
}

// ErrUnsupportedChallengeType indicates an unsupported ACME challenge type was requested.
type ErrUnsupportedChallengeType struct {
	ChallengeType string
}

func (e ErrUnsupportedChallengeType) Error() string {
	return fmt.Sprintf("acme-client-service: unsupported challenge type: %s", e.ChallengeType)
}

// ErrChallengeCleanupFailed indicates that removing a previously provisioned
// ACME challenge record failed.
type ErrChallengeCleanupFailed struct {
	ChallengeType string
	Reason        string
}

func (e ErrChallengeCleanupFailed) Error() string {
	return fmt.Sprintf("acme-client-service: challenge cleanup failed for %s: %s", e.ChallengeType, e.Reason)
}

// ErrInvalidHTTP01Token indicates that a server-supplied HTTP-01 challenge
// token does not conform to RFC 8555 Section 8.3's base64url token format.
// It is returned before the token is joined into a filesystem path.
type ErrInvalidHTTP01Token struct {
	Token  string
	Reason string
}

func (e ErrInvalidHTTP01Token) Error() string {
	return fmt.Sprintf("acme-client-service: invalid http-01 challenge token %q: %s", e.Token, e.Reason)
}

// ErrUnsupportedDNSProvider indicates that DNS01Config.Provider named a
// provider this project does not implement. It is returned at configuration
// time so a doomed DNS-01 validation is never attempted.
type ErrUnsupportedDNSProvider struct {
	Provider string
}

func (e ErrUnsupportedDNSProvider) Error() string {
	return fmt.Sprintf("acme-client-service: unsupported dns-01 provider %q (supported: route53, cloudflare, azure, clouddns)", e.Provider)
}

// ErrInvalidDNSProviderCredential indicates that a DNS01Config.Credentials
// entry for the named provider could not be parsed into the type its
// provider Config field requires.
type ErrInvalidDNSProviderCredential struct {
	Provider string
	Key      string
	Reason   string
}

func (e ErrInvalidDNSProviderCredential) Error() string {
	return fmt.Sprintf("acme-client-service: invalid %q credential for dns-01 provider %q: %s", e.Key, e.Provider, e.Reason)
}

// ErrMissingEmail indicates that an email address is required but not provided.
type ErrMissingEmail struct{}

func (e ErrMissingEmail) Error() string {
	return "acme-client-service: email address is required for account registration"
}

// ErrMissingDomain indicates that a domain name is required but not provided.
type ErrMissingDomain struct{}

func (e ErrMissingDomain) Error() string {
	return "acme-client-service: domain name is required for certificate request"
}

// ErrMissingCertFile indicates that a certificate file path is required but not provided.
type ErrMissingCertFile struct{}

func (e ErrMissingCertFile) Error() string {
	return "acme-client-service: certificate file path is required"
}

// ErrMissingDeviceID indicates that a device ID is required but not provided.
type ErrMissingDeviceID struct{}

func (e ErrMissingDeviceID) Error() string {
	return "acme-client-service: device ID is required"
}

// ErrUnsupportedKeyType indicates an unsupported key type was specified.
type ErrUnsupportedKeyType struct {
	KeyType string
}

func (e ErrUnsupportedKeyType) Error() string {
	return fmt.Sprintf("acme-client-service: unsupported key type: %s", e.KeyType)
}

// ErrInvalidPCRIndex indicates a PCR index is out of range.
type ErrInvalidPCRIndex struct {
	Index int
}

func (e ErrInvalidPCRIndex) Error() string {
	return fmt.Sprintf("acme-client-service: PCR index out of range: %d (must be 0-23)", e.Index)
}

// ErrInvalidPCRFormat indicates a PCR index string could not be parsed.
type ErrInvalidPCRFormat struct {
	Value string
}

func (e ErrInvalidPCRFormat) Error() string {
	return fmt.Sprintf("acme-client-service: invalid PCR index format: %s", e.Value)
}

// ErrUnsupportedConfigFormat indicates the config file extension is not supported.
type ErrUnsupportedConfigFormat struct {
	Extension string
}

func (e ErrUnsupportedConfigFormat) Error() string {
	return fmt.Sprintf("acme-client-service: unsupported config file format: %s", e.Extension)
}

// ErrUnsupportedTransport indicates an unsupported SDK transport protocol was specified.
type ErrUnsupportedTransport struct {
	Transport string
}

func (e ErrUnsupportedTransport) Error() string {
	return fmt.Sprintf("acme-client-service: unsupported SDK transport: %s", e.Transport)
}

// ErrSDKClientCreation indicates a failure creating the SDK client.
type ErrSDKClientCreation struct {
	Err error
}

func (e ErrSDKClientCreation) Error() string {
	return "acme-client-service: failed to create SDK client: " + e.Err.Error()
}

func (e ErrSDKClientCreation) Unwrap() error {
	return e.Err
}

// ErrSDKOrderFailed indicates an ACME order operation failed via the SDK.
type ErrSDKOrderFailed struct {
	Operation string
	Err       error
}

func (e ErrSDKOrderFailed) Error() string {
	return fmt.Sprintf("acme-client-service: SDK order %s failed: %s", e.Operation, e.Err.Error())
}

func (e ErrSDKOrderFailed) Unwrap() error {
	return e.Err
}

// ErrSDKAuthorizationFailed indicates an ACME authorization operation failed via the SDK.
type ErrSDKAuthorizationFailed struct {
	Err error
}

func (e ErrSDKAuthorizationFailed) Error() string {
	return "acme-client-service: SDK authorization failed: " + e.Err.Error()
}

func (e ErrSDKAuthorizationFailed) Unwrap() error {
	return e.Err
}

// ErrSDKChallengeFailed indicates an ACME challenge operation failed via the SDK.
type ErrSDKChallengeFailed struct {
	Err error
}

func (e ErrSDKChallengeFailed) Error() string {
	return "acme-client-service: SDK challenge failed: " + e.Err.Error()
}

func (e ErrSDKChallengeFailed) Unwrap() error {
	return e.Err
}

// ErrSDKCertificateFailed indicates an ACME certificate operation failed via the SDK.
type ErrSDKCertificateFailed struct {
	Operation string
	Err       error
}

func (e ErrSDKCertificateFailed) Error() string {
	return fmt.Sprintf("acme-client-service: SDK certificate %s failed: %s", e.Operation, e.Err.Error())
}

func (e ErrSDKCertificateFailed) Unwrap() error {
	return e.Err
}

// ErrSDKAccountFailed indicates an ACME account operation failed via the SDK.
type ErrSDKAccountFailed struct {
	Err error
}

func (e ErrSDKAccountFailed) Error() string {
	return "acme-client-service: SDK account registration failed: " + e.Err.Error()
}

func (e ErrSDKAccountFailed) Unwrap() error {
	return e.Err
}

// ErrCertificateParseFailed indicates failure parsing a certificate from the SDK response.
type ErrCertificateParseFailed struct {
	Err error
}

func (e ErrCertificateParseFailed) Error() string {
	return "acme-client-service: failed to parse certificate from SDK response: " + e.Err.Error()
}

func (e ErrCertificateParseFailed) Unwrap() error {
	return e.Err
}

// ErrSDKOrderPollTimeout indicates the order polling timed out waiting for a valid status.
type ErrSDKOrderPollTimeout struct {
	OrderURL string
	Status   string
}

func (e ErrSDKOrderPollTimeout) Error() string {
	return fmt.Sprintf("acme-client-service: order poll timed out (url: %s, last status: %s)", e.OrderURL, e.Status)
}

// ErrSDKChallengeNotFound indicates the requested challenge type was not found in the authorization.
type ErrSDKChallengeNotFound struct {
	ChallengeType string
}

func (e ErrSDKChallengeNotFound) Error() string {
	return fmt.Sprintf("acme-client-service: challenge type %s not found in authorization", e.ChallengeType)
}

// ErrAccountNotFound indicates the account name was not found in the configuration.
type ErrAccountNotFound struct {
	Name string
}

func (e ErrAccountNotFound) Error() string {
	return fmt.Sprintf("acme-client-service: account not found: %s", e.Name)
}

// ErrAccountAlreadyExists indicates the account name already exists in the configuration.
type ErrAccountAlreadyExists struct {
	Name string
}

func (e ErrAccountAlreadyExists) Error() string {
	return fmt.Sprintf("acme-client-service: account already exists: %s", e.Name)
}

// ErrCertSpecNotFound indicates the certificate spec name was not found.
type ErrCertSpecNotFound struct {
	Name string
}

func (e ErrCertSpecNotFound) Error() string {
	return fmt.Sprintf("acme-client-service: certificate spec not found: %s", e.Name)
}

// ErrCertSpecAlreadyExists indicates the certificate spec already exists.
type ErrCertSpecAlreadyExists struct {
	Name string
}

func (e ErrCertSpecAlreadyExists) Error() string {
	return fmt.Sprintf("acme-client-service: certificate spec already exists: %s", e.Name)
}

// ErrInvalidAccountConfig indicates the account configuration validation failed.
type ErrInvalidAccountConfig struct {
	Name   string
	Reason string
}

func (e ErrInvalidAccountConfig) Error() string {
	return fmt.Sprintf("acme-client-service: invalid account config for %s: %s", e.Name, e.Reason)
}

// ErrInvalidCertSpec indicates the certificate spec validation failed.
type ErrInvalidCertSpec struct {
	Name   string
	Reason string
}

func (e ErrInvalidCertSpec) Error() string {
	return fmt.Sprintf("acme-client-service: invalid certificate spec for %s: %s", e.Name, e.Reason)
}

// ErrKeyGeneration indicates that key generation failed.
type ErrKeyGeneration struct {
	Algorithm string
	Err       error
}

func (e ErrKeyGeneration) Error() string {
	return fmt.Sprintf("acme-client-service: key generation failed for algorithm %s: %s", e.Algorithm, e.Err.Error())
}

func (e ErrKeyGeneration) Unwrap() error {
	return e.Err
}

// ErrStorageFactory indicates that storage factory creation failed.
type ErrStorageFactory struct {
	Err error
}

func (e ErrStorageFactory) Error() string {
	return "acme-client-service: storage factory creation failed: " + e.Err.Error()
}

func (e ErrStorageFactory) Unwrap() error {
	return e.Err
}

// ErrClientCreation indicates that ACME client creation failed.
type ErrClientCreation struct {
	Account string
	Err     error
}

func (e ErrClientCreation) Error() string {
	return fmt.Sprintf("acme-client-service: client creation failed for account %s: %s", e.Account, e.Err.Error())
}

func (e ErrClientCreation) Unwrap() error {
	return e.Err
}

// Sentinel causes wrapped by ErrDeployFailed when Deploy is called with an
// incomplete or invalid DeployConfig. Callers can match a specific cause
// with errors.Is, which walks ErrDeployFailed.Unwrap to reach these.
var (
	ErrDeployConfigNil     = errors.New("acme-client-service: deploy config is nil")
	ErrDeployCertPEMEmpty  = errors.New("acme-client-service: certificate PEM data is empty")
	ErrDeployCertPathEmpty = errors.New("acme-client-service: certificate path is empty")
	ErrDeployKeyPathEmpty  = errors.New("acme-client-service: key path is empty")
	ErrDeployKeyPEMEmpty   = errors.New("acme-client-service: private key PEM data is empty")
)

// ErrDeployFailed indicates that certificate deployment failed.
type ErrDeployFailed struct {
	CertName string
	Err      error
}

func (e ErrDeployFailed) Error() string {
	return fmt.Sprintf("acme-client-service: certificate deployment failed for %s: %s", e.CertName, e.Err.Error())
}

func (e ErrDeployFailed) Unwrap() error {
	return e.Err
}

// ErrPostHookFailed indicates that a post-deployment hook failed.
type ErrPostHookFailed struct {
	Hook string
	Err  error
}

func (e ErrPostHookFailed) Error() string {
	return fmt.Sprintf("acme-client-service: post-deployment hook failed for %s: %s", e.Hook, e.Err.Error())
}

func (e ErrPostHookFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidKeyConfig indicates that key configuration validation failed.
type ErrInvalidKeyConfig struct {
	Reason string
}

func (e ErrInvalidKeyConfig) Error() string {
	return fmt.Sprintf("acme-client-service: invalid key config: %s", e.Reason)
}

// ErrValidation indicates a configuration validation failure.
type ErrValidation struct {
	Field  string
	Reason string
}

func (e *ErrValidation) Error() string {
	return fmt.Sprintf("acme-client-service: validation error on %s: %s", e.Field, e.Reason)
}

// ErrCSRCreation indicates that CSR creation failed.
type ErrCSRCreation struct {
	Err error
}

func (e ErrCSRCreation) Error() string {
	return "acme-client-service: CSR creation failed: " + e.Err.Error()
}

func (e ErrCSRCreation) Unwrap() error {
	return e.Err
}

// ErrKeyEncoding indicates that private key encoding failed.
type ErrKeyEncoding struct {
	Err error
}

func (e ErrKeyEncoding) Error() string {
	return "acme-client-service: key encoding failed: " + e.Err.Error()
}

func (e ErrKeyEncoding) Unwrap() error {
	return e.Err
}

// ErrInvalidIP indicates that an IP address string could not be parsed.
type ErrInvalidIP struct {
	Value string
}

func (e ErrInvalidIP) Error() string {
	return fmt.Sprintf("acme-client-service: invalid IP address: %s", e.Value)
}

// ErrInvalidURI indicates that a URI string could not be parsed.
type ErrInvalidURI struct {
	Value string
	Err   error
}

func (e ErrInvalidURI) Error() string {
	return fmt.Sprintf("acme-client-service: invalid URI: %s: %s", e.Value, e.Err.Error())
}

func (e ErrInvalidURI) Unwrap() error {
	return e.Err
}

// ErrNothingToDeploy indicates that no deploy configuration exists for the certificate.
type ErrNothingToDeploy struct {
	Name string
}

func (e ErrNothingToDeploy) Error() string {
	return fmt.Sprintf("acme-client-service: no deploy configuration for certificate: %s", e.Name)
}

// ErrMissingKeyConfig indicates that a required key configuration is absent.
// Context identifies which configuration element is missing the key (e.g.,
// the certificate spec name).
type ErrMissingKeyConfig struct {
	Context string
}

func (e ErrMissingKeyConfig) Error() string {
	return fmt.Sprintf("acme-client-service: missing key configuration for %s", e.Context)
}

// ErrNoIssuedCertificate indicates that a certificate spec exists in the
// configuration but no certificate has been issued for it yet.
type ErrNoIssuedCertificate struct {
	Name string
}

func (e ErrNoIssuedCertificate) Error() string {
	return fmt.Sprintf("acme-client-service: no issued certificate for spec %q — call Request first", e.Name)
}

// ErrDeviceSpecNotFound indicates the device spec name was not found.
type ErrDeviceSpecNotFound struct {
	Name string
}

func (e ErrDeviceSpecNotFound) Error() string {
	return fmt.Sprintf("acme-client-service: device spec not found: %s", e.Name)
}

// ErrDeviceNotEnrolled indicates that a device spec exists in the
// configuration but has not yet been enrolled or attested.
type ErrDeviceNotEnrolled struct {
	Name string
}

func (e ErrDeviceNotEnrolled) Error() string {
	return fmt.Sprintf("acme-client-service: device %q has not been enrolled or attested — call Enroll or Attest first", e.Name)
}

// ErrDeviceTPMOpenFailed indicates that opening the TPM configured for a
// device spec failed.
type ErrDeviceTPMOpenFailed struct {
	Name string
	Err  error
}

func (e ErrDeviceTPMOpenFailed) Error() string {
	return fmt.Sprintf("acme-client-service: failed to open TPM for device %q: %s", e.Name, e.Err.Error())
}

func (e ErrDeviceTPMOpenFailed) Unwrap() error {
	return e.Err
}

// ErrDeviceTPMNotProvisioned indicates that a device's TPM has not been
// provisioned (no EK/SRK/IAK at their configured persistent handles) and,
// because it is not the in-process simulator, go-xkms will not provision it
// automatically.
type ErrDeviceTPMNotProvisioned struct {
	Name string
}

func (e ErrDeviceTPMNotProvisioned) Error() string {
	return fmt.Sprintf("acme-client-service: TPM for device %q is not provisioned; provision it through the platform's TPM provisioning path before enrolling or attesting", e.Name)
}

// ErrDeviceTPMProvisionFailed indicates that auto-provisioning the
// in-process TPM simulator for a device spec failed.
type ErrDeviceTPMProvisionFailed struct {
	Name string
	Err  error
}

func (e ErrDeviceTPMProvisionFailed) Error() string {
	return fmt.Sprintf("acme-client-service: failed to provision simulator TPM for device %q: %s", e.Name, e.Err.Error())
}

func (e ErrDeviceTPMProvisionFailed) Unwrap() error {
	return e.Err
}

// ErrDeviceTPMConfigIncomplete indicates the TPM configuration for a device
// spec is missing a section required to auto-provision the simulator.
type ErrDeviceTPMConfigIncomplete struct {
	Name   string
	Reason string
}

func (e ErrDeviceTPMConfigIncomplete) Error() string {
	return fmt.Sprintf("acme-client-service: incomplete TPM configuration for device %q: %s", e.Name, e.Reason)
}

// ErrDeviceEKCertificateRequired indicates that a real (non-simulator) TPM
// has no Endorsement Key certificate available and none was configured to
// provision, so it cannot carry one in the TCG-CSR-IDEVID.
type ErrDeviceEKCertificateRequired struct {
	Name string
	Err  error
}

func (e ErrDeviceEKCertificateRequired) Error() string {
	return fmt.Sprintf("acme-client-service: device %q has no Endorsement Key certificate and none is configured: %s", e.Name, e.Err.Error())
}

func (e ErrDeviceEKCertificateRequired) Unwrap() error {
	return e.Err
}

// ErrInvalidEKCertificatePEM indicates that DeviceTPMConfig.EKCertificatePEM
// could not be decoded as a PEM certificate block.
type ErrInvalidEKCertificatePEM struct {
	Name string
}

func (e ErrInvalidEKCertificatePEM) Error() string {
	return fmt.Sprintf("acme-client-service: EK certificate PEM for device %q is not a valid PEM-encoded certificate", e.Name)
}

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

package config

import "errors"

var (
	// ErrConfigNotFound is returned when the config file does not exist at the expected path.
	ErrConfigNotFound = errors.New("config: file not found")

	// ErrConfigInvalid is returned when the config file cannot be parsed or contains invalid values.
	ErrConfigInvalid = errors.New("config: file is invalid")

	// ErrConfigSaveFailed is returned when the config file cannot be written to disk.
	ErrConfigSaveFailed = errors.New("config: failed to save")

	// ErrConfigLoadFailed is returned when the config file cannot be read from disk.
	ErrConfigLoadFailed = errors.New("config: failed to load")

	// ErrConfigDirCreate is returned when the config directory cannot be created.
	ErrConfigDirCreate = errors.New("config: failed to create directory")

	// ErrPolicyInvalid is returned when the policy section contains invalid or inconsistent values.
	ErrPolicyInvalid = errors.New("config: policy section is invalid")

	// ErrPolicyHMACMissing is returned when the HMAC file is missing in enterprise mode.
	ErrPolicyHMACMissing = errors.New("config: policy HMAC file missing")

	// ErrPolicyHMACMismatch is returned when HMAC verification fails, indicating potential tampering.
	ErrPolicyHMACMismatch = errors.New("config: policy HMAC verification failed")

	// ErrPolicyHMACSaveFailed is returned when the HMAC file cannot be written to disk.
	ErrPolicyHMACSaveFailed = errors.New("config: failed to write policy HMAC file")

	// ErrPolicyHMACLoadFailed is returned when the HMAC file cannot be read from disk.
	ErrPolicyHMACLoadFailed = errors.New("config: failed to load policy HMAC file")

	// ErrPolicyKeyDerivationFailed is returned when HMAC key derivation from the SO PIN fails.
	ErrPolicyKeyDerivationFailed = errors.New("config: policy HMAC key derivation failed")

	// ErrPolicySOPINRequired is returned when an SO PIN is required for policy operations but not provided.
	ErrPolicySOPINRequired = errors.New("config: SO PIN required for policy operations")

	// ErrPolicyVersionMismatch is returned when the policy version does not match the HMAC version.
	ErrPolicyVersionMismatch = errors.New("config: policy version does not match HMAC version")

	// ErrPolicyUnverifiable is returned by LoadVerifiedPolicy when the config
	// directory is sealed (enterprise mode) and the policy section cannot be
	// authenticated: no SO PIN was supplied, the HMAC file cannot be read, or
	// the HMAC does not match. The cause is joined and reachable with
	// errors.Is. A consumer that receives it must not read the section.
	ErrPolicyUnverifiable = errors.New("config: sealed policy cannot be verified")

	// ErrBarrierCloudKMSConfigInvalid is returned when a cloud KMS barrier
	// strategy (aws_kms, gcp_kms, azure_kv, vault) is missing required
	// configuration or combines fields inconsistently (e.g. a partial
	// explicit-credential set). See DetailError for the specific field.
	ErrBarrierCloudKMSConfigInvalid = errors.New("config: cloud KMS barrier strategy configuration is invalid")
)

// DetailError appends detail text directly after a wrapped error while
// preserving errors.Is / errors.As matching of the wrapped error through
// Unwrap. The detail text carries its own leading separator.
type DetailError struct {
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *DetailError) Error() string {
	return e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *DetailError) Unwrap() error {
	return e.Err
}

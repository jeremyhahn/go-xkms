// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package appraisal

import (
	"errors"
	"strconv"
)

var (
	// ErrNilRequest indicates a nil request or evidence argument.
	ErrNilRequest = errors.New("attestation: nil request")

	// ErrInvalidName indicates an endorsement or reference-values name that
	// cannot be stored. See NameError.
	ErrInvalidName = errors.New("attestation: invalid name")

	// ErrEndorsementInvalid indicates an endorsement that cannot be stored.
	// See EndorsementInvalidError.
	ErrEndorsementInvalid = errors.New("attestation: invalid endorsement")

	// ErrRecordNotFound indicates a missing endorsement or reference values.
	// See RecordNotFoundError.
	ErrRecordNotFound = errors.New("attestation: record not found")

	// ErrReferenceValuesRejected indicates a signed CoRIM no stored
	// reference-signer endorsement verifies. See ReferenceValuesRejectedError.
	ErrReferenceValuesRejected = errors.New("attestation: reference values rejected")

	// ErrStoreUnavailable indicates the endorsement and reference-values store
	// failed. See StoreError.
	ErrStoreUnavailable = errors.New("attestation: store unavailable")

	// ErrInvalidConfig indicates an Appraiser or Store built from an unusable
	// configuration. See ConfigError.
	ErrInvalidConfig = errors.New("attestation: invalid configuration")

	// ErrInvalidTenant indicates a tenant that names no record scope. See
	// TenantError.
	ErrInvalidTenant = errors.New("attestation: invalid tenant")

	// ErrHostNotVerified indicates the Verifier did not verify a host's
	// evidence. See HostAppraisalError.
	ErrHostNotVerified = errors.New("attestation: host evidence not verified")

	// ErrPCRMismatch indicates a quoted PCR the reference values do not
	// admit. A HostAppraisalError with divergent PCRs reports it.
	ErrPCRMismatch = errors.New("attestation: PCR value does not match the reference values")

	// ErrReferenceBankUncovered indicates reference values that hold no PCR
	// digest in the quoted bank. See ReferenceBankUncoveredError.
	ErrReferenceBankUncovered = errors.New("attestation: reference values do not cover the quoted PCR bank")

	// ErrQuoteNotBound indicates PCR values that cannot be tied to the signed
	// quote. See QuoteBindingError.
	ErrQuoteNotBound = errors.New("attestation: PCR values are not bound to the quote")

	// ErrQuotedPCRDigestMismatch indicates PCR values that do not reproduce
	// the signed quote's pcrDigest. See QuotedPCRDigestMismatchError.
	ErrQuotedPCRDigestMismatch = errors.New("attestation: PCR values do not reproduce the quoted digest")

	// ErrPCRBankUnavailable indicates a PCR bank the TPM did not report. See
	// PCRBankUnavailableError.
	ErrPCRBankUnavailable = errors.New("attestation: PCR bank unavailable")
)

// NameError reports an invalid endorsement or reference-values name.
type NameError struct {
	Name string
}

// Error returns a human-readable description.
func (e *NameError) Error() string {
	return "attestation: name " + strconv.Quote(e.Name) + " must be 1-" +
		strconv.Itoa(maxNameLen) + " bytes without '/'"
}

// Unwrap returns ErrInvalidName.
func (e *NameError) Unwrap() error { return ErrInvalidName }

// EndorsementInvalidError reports an endorsement that cannot be stored.
type EndorsementInvalidError struct {
	Reason string
}

// Error returns a human-readable description.
func (e *EndorsementInvalidError) Error() string {
	return "attestation: invalid endorsement: " + e.Reason
}

// Unwrap returns ErrEndorsementInvalid.
func (e *EndorsementInvalidError) Unwrap() error { return ErrEndorsementInvalid }

// RecordNotFoundError reports a missing endorsement or reference values.
type RecordNotFoundError struct {
	Kind string
	Name string
}

// Error returns a human-readable description.
func (e *RecordNotFoundError) Error() string {
	return "attestation: " + e.Kind + " " + strconv.Quote(e.Name) + " not found"
}

// Unwrap returns ErrRecordNotFound.
func (e *RecordNotFoundError) Unwrap() error { return ErrRecordNotFound }

// ReferenceValuesRejectedError reports a signed CoRIM that no stored
// reference-signer endorsement verifies, or that carries no usable PCR
// reference values.
type ReferenceValuesRejectedError struct {
	Reason string
	Cause  error
}

// Error returns a human-readable description.
func (e *ReferenceValuesRejectedError) Error() string {
	return "attestation: reference values rejected: " + e.Reason
}

// Unwrap returns ErrReferenceValuesRejected and the verification failure.
func (e *ReferenceValuesRejectedError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrReferenceValuesRejected}
	}
	return []error{ErrReferenceValuesRejected, e.Cause}
}

// StoreError reports a failed store operation on one record key.
type StoreError struct {
	Op  string
	Key string
	Err error
}

// Error returns a human-readable description.
func (e *StoreError) Error() string {
	return "attestation: store " + e.Op + " " + strconv.Quote(e.Key) + ": " + e.Err.Error()
}

// Unwrap returns ErrStoreUnavailable and the store failure.
func (e *StoreError) Unwrap() []error { return []error{ErrStoreUnavailable, e.Err} }

// ConfigError reports an unusable Appraiser or Store configuration.
type ConfigError struct {
	Field  string
	Reason string
	Cause  error
}

// Error returns a human-readable description.
func (e *ConfigError) Error() string {
	msg := "attestation: invalid configuration: " + e.Field + " " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns ErrInvalidConfig and the cause.
func (e *ConfigError) Unwrap() []error {
	if e.Cause == nil {
		return []error{ErrInvalidConfig}
	}
	return []error{ErrInvalidConfig, e.Cause}
}

// TenantError reports a tenant that names no record scope.
type TenantError struct {
	Tenant string
	Cause  error
}

// Error returns a human-readable description.
func (e *TenantError) Error() string {
	return "attestation: invalid tenant " + strconv.Quote(e.Tenant) + ": " + e.Cause.Error()
}

// Unwrap returns ErrInvalidTenant and the scope failure.
func (e *TenantError) Unwrap() []error { return []error{ErrInvalidTenant, e.Cause} }

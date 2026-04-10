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

package store

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// ErrSignerStoreNotInitialized is returned when the signer store DAO
// was not properly initialized (e.g., nil backend or codec failure).
var ErrSignerStoreNotInitialized = errors.New("signer store: not initialized")

// ErrSignerNotFound is returned when a signer is not found in storage.
type ErrSignerNotFound struct {
	CN string
}

func (e *ErrSignerNotFound) Error() string {
	return fmt.Sprintf("signer not found for %s: %s", e.CN, "storage: not found")
}

// ErrSignerGet is returned when a storage get operation fails for a signer.
type ErrSignerGet struct {
	CN    string
	Cause error
}

func (e *ErrSignerGet) Error() string {
	return fmt.Sprintf("failed to get signer %s: %v", e.CN, e.Cause)
}

func (e *ErrSignerGet) Unwrap() error { return e.Cause }

// ErrSignerPEMDecode is returned when PEM decoding fails for a signer.
type ErrSignerPEMDecode struct {
	CN    string
	Cause error
}

func (e *ErrSignerPEMDecode) Error() string {
	return fmt.Sprintf("failed to decode PEM for %s: %v", e.CN, e.Cause)
}

func (e *ErrSignerPEMDecode) Unwrap() error { return e.Cause }

// ErrSignerKeyParse is returned when private key parsing fails.
type ErrSignerKeyParse struct {
	CN            string
	Algorithm     string
	Cause         error
	FallbackCause error
}

func (e *ErrSignerKeyParse) Error() string {
	if e.FallbackCause != nil {
		return fmt.Sprintf("failed to parse %s private key for %s: %v (pkcs8: %v)", e.Algorithm, e.CN, e.Cause, e.FallbackCause)
	}
	return fmt.Sprintf("failed to parse %s private key for %s: %v", e.Algorithm, e.CN, e.Cause)
}

func (e *ErrSignerKeyParse) Unwrap() error { return e.Cause }

// ErrSignerKeyTypeMismatch is returned when a parsed key doesn't match the expected type.
type ErrSignerKeyTypeMismatch struct {
	CN       string
	Expected string
	Actual   string
}

func (e *ErrSignerKeyTypeMismatch) Error() string {
	return fmt.Sprintf("key is not an %s private key for %s", e.Expected, e.CN)
}

// ErrSignerNil is returned when a nil signer is provided to Save.
type ErrSignerNil struct {
	CN string
}

func (e *ErrSignerNil) Error() string {
	return fmt.Sprintf("signer is nil for %s", e.CN)
}

// ErrSignerMarshal is returned when private key marshaling fails.
type ErrSignerMarshal struct {
	CN    string
	Cause error
}

func (e *ErrSignerMarshal) Error() string {
	return fmt.Sprintf("failed to marshal private key for %s: %v", e.CN, e.Cause)
}

func (e *ErrSignerMarshal) Unwrap() error { return e.Cause }

// ErrSignerSave is returned when the storage put operation fails for a signer.
type ErrSignerSave struct {
	CN    string
	Cause error
}

func (e *ErrSignerSave) Error() string {
	return fmt.Sprintf("failed to save signer %s.signer: %v", e.CN, e.Cause)
}

func (e *ErrSignerSave) Unwrap() error { return e.Cause }

// ErrSignerDelete is returned when the storage delete operation fails for a signer.
type ErrSignerDelete struct {
	CN    string
	Cause error
}

func (e *ErrSignerDelete) Error() string {
	return fmt.Sprintf("failed to delete signer %s.signer: %v", e.CN, e.Cause)
}

func (e *ErrSignerDelete) Unwrap() error { return e.Cause }

// ErrSignatureSave is returned when saving a signature fails.
type ErrSignatureSave struct {
	Key   string
	Cause error
}

func (e *ErrSignatureSave) Error() string {
	return fmt.Sprintf("failed to save signature %s: %v", e.Key, e.Cause)
}

func (e *ErrSignatureSave) Unwrap() error { return e.Cause }

// ErrUnsupportedAlgorithm is returned when an unsupported key algorithm is specified.
type ErrUnsupportedAlgorithm struct {
	CN        string
	Algorithm x509.PublicKeyAlgorithm
}

func (e *ErrUnsupportedAlgorithm) Error() string {
	return fmt.Sprintf("unsupported key algorithm for %s: %v", e.CN, e.Algorithm)
}

// ErrUnsupportedSignerType is returned when an unsupported signer type is provided to Save.
type ErrUnsupportedSignerType struct {
	CN   string
	Type string
}

func (e *ErrUnsupportedSignerType) Error() string {
	return fmt.Sprintf("unsupported signer type for %s: %s", e.CN, e.Type)
}

// ErrSignerExtract is returned when the private key cannot be extracted from a crypto.Signer.
type ErrSignerExtract struct {
	CN        string
	Algorithm string
}

func (e *ErrSignerExtract) Error() string {
	return fmt.Sprintf("unable to extract %s private key from signer for %s", e.Algorithm, e.CN)
}

// ErrUnsupportedPublicKeyType is returned when a crypto.Signer has an unsupported public key type.
type ErrUnsupportedPublicKeyType struct {
	CN   string
	Type string
}

func (e *ErrUnsupportedPublicKeyType) Error() string {
	return fmt.Sprintf("unsupported public key type for %s: %s", e.CN, e.Type)
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build frost

package frost

import (
	"errors"
	"fmt"
)

// Sentinel errors for the FROST backend.
// These errors can be checked with errors.Is().
var (
	// ErrBackendClosed indicates the backend has been closed.
	ErrBackendClosed = errors.New("frost: backend closed")

	// ErrKeyNotFound indicates the requested key does not exist.
	ErrKeyNotFound = errors.New("frost: key not found")

	// ErrKeyAlreadyExists indicates the key already exists.
	ErrKeyAlreadyExists = errors.New("frost: key already exists")

	// ErrInsufficientShares indicates not enough shares for threshold.
	ErrInsufficientShares = errors.New("frost: insufficient signature shares")

	// ErrNonceAlreadyUsed indicates a nonce reuse attempt.
	// Nonce reuse in FROST is catastrophic - it allows full key recovery.
	ErrNonceAlreadyUsed = errors.New("frost: nonce already used")

	// ErrNonceNotFound indicates the nonce package was not found.
	ErrNonceNotFound = errors.New("frost: nonce not found")

	// ErrInvalidSignature indicates signature verification failed.
	ErrInvalidSignature = errors.New("frost: invalid signature")

	// ErrInvalidCommitment indicates malformed commitment data.
	ErrInvalidCommitment = errors.New("frost: invalid commitment")

	// ErrInvalidShare indicates malformed signature share.
	ErrInvalidShare = errors.New("frost: invalid signature share")

	// ErrSessionNotFound indicates the signing session doesn't exist.
	ErrSessionNotFound = errors.New("frost: session not found")

	// ErrSessionExpired indicates the signing session has expired.
	ErrSessionExpired = errors.New("frost: session expired")

	// ErrNotImplemented indicates a feature is not supported.
	ErrNotImplemented = errors.New("frost: not implemented")

	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("frost: invalid configuration")

	// ErrInvalidAttributes indicates the key attributes are invalid.
	ErrInvalidAttributes = errors.New("frost: invalid key attributes")

	// ErrUnsupportedAlgorithm indicates the algorithm is not supported.
	ErrUnsupportedAlgorithm = errors.New("frost: unsupported algorithm")

	// ErrInvalidParticipant indicates an invalid participant identifier.
	ErrInvalidParticipant = errors.New("frost: invalid participant")

	// ErrDKGFailed indicates distributed key generation failed.
	ErrDKGFailed = errors.New("frost: key generation failed")

	// ErrAggregationFailed indicates signature aggregation failed.
	ErrAggregationFailed = errors.New("frost: signature aggregation failed")

	// ErrDecryptionNotSupported indicates FROST is signing-only per RFC 9591.
	ErrDecryptionNotSupported = errors.New("frost: decryption not supported (FROST is signing-only)")
)

// KeyNotFoundError provides detailed information about a missing key.
type KeyNotFoundError struct {
	KeyID string
}

// Error implements the error interface.
func (e *KeyNotFoundError) Error() string {
	return fmt.Sprintf("frost: key not found: %s", e.KeyID)
}

// Unwrap returns the underlying error for errors.Is() support.
func (e *KeyNotFoundError) Unwrap() error {
	return ErrKeyNotFound
}

// ShareNotFoundError provides detailed information about a missing share.
type ShareNotFoundError struct {
	KeyID         string
	ParticipantID uint32
}

// Error implements the error interface.
func (e *ShareNotFoundError) Error() string {
	return fmt.Sprintf("frost: share not found for key %s, participant %d", e.KeyID, e.ParticipantID)
}

// Unwrap returns the underlying error for errors.Is() support.
func (e *ShareNotFoundError) Unwrap() error {
	return ErrKeyNotFound
}

// NonceReuseError provides detailed information about a nonce reuse attempt.
type NonceReuseError struct {
	KeyID         string
	ParticipantID uint32
	SessionID     string
}

// Error implements the error interface.
func (e *NonceReuseError) Error() string {
	return fmt.Sprintf("frost: CRITICAL nonce reuse detected for key %s, participant %d, session %s",
		e.KeyID, e.ParticipantID, e.SessionID)
}

// Unwrap returns the underlying error for errors.Is() support.
func (e *NonceReuseError) Unwrap() error {
	return ErrNonceAlreadyUsed
}

// CulpritError identifies malicious or faulty participants during signing.
type CulpritError struct {
	KeyID    string
	Culprits []uint32
	Reason   string
}

// Error implements the error interface.
func (e *CulpritError) Error() string {
	return fmt.Sprintf("frost: signing failed for key %s, culprits: %v, reason: %s",
		e.KeyID, e.Culprits, e.Reason)
}

// Unwrap returns the underlying error for errors.Is() support.
func (e *CulpritError) Unwrap() error {
	return ErrInvalidShare
}

// ConfigError provides detailed information about a configuration error.
type ConfigError struct {
	Field   string
	Message string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return fmt.Sprintf("frost: invalid config %s: %s", e.Field, e.Message)
}

// Unwrap returns the underlying error for errors.Is() support.
func (e *ConfigError) Unwrap() error {
	return ErrInvalidConfig
}

// AlgorithmError provides detailed information about an unsupported algorithm.
type AlgorithmError struct {
	Algorithm string
}

// Error implements the error interface.
func (e *AlgorithmError) Error() string {
	return fmt.Sprintf("frost: unsupported algorithm: %s", e.Algorithm)
}

// Unwrap returns the underlying error for errors.Is() support.
func (e *AlgorithmError) Unwrap() error {
	return ErrUnsupportedAlgorithm
}

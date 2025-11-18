// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"errors"
	"fmt"
)

var (
	// ErrInsufficientShares indicates not enough shares were provided for reconstruction
	ErrInsufficientShares = errors.New("insufficient shares for threshold reconstruction")

	// ErrInvalidShare indicates a share failed validation
	ErrInvalidShare = errors.New("invalid share")

	// ErrShareNotFound indicates a requested share does not exist
	ErrShareNotFound = errors.New("share not found")

	// ErrKeyNotFound indicates a requested key does not exist
	ErrKeyNotFound = errors.New("key not found")

	// ErrInvalidThreshold indicates invalid threshold parameters
	ErrInvalidThreshold = errors.New("invalid threshold parameters")

	// ErrNotImplemented indicates a feature is not yet implemented
	ErrNotImplemented = errors.New("not implemented")

	// ErrUnsupportedAlgorithm indicates an unsupported threshold algorithm
	ErrUnsupportedAlgorithm = errors.New("unsupported threshold algorithm")

	// ErrBackendClosed indicates the backend has been closed
	ErrBackendClosed = errors.New("threshold backend is closed")

	// ErrInvalidKeyType indicates an unsupported key type for threshold operations
	ErrInvalidKeyType = errors.New("invalid key type for threshold operations")
)

// ShareNotFoundError wraps ErrShareNotFound with context about which share was not found.
type ShareNotFoundError struct {
	KeyID   string
	ShareID int
}

func (e *ShareNotFoundError) Error() string {
	return fmt.Sprintf("share %d not found for key %s", e.ShareID, e.KeyID)
}

func (e *ShareNotFoundError) Unwrap() error {
	return ErrShareNotFound
}

// InsufficientSharesError wraps ErrInsufficientShares with details.
type InsufficientSharesError struct {
	Have      int
	Threshold int
}

func (e *InsufficientSharesError) Error() string {
	return fmt.Sprintf("insufficient shares: have %d, need %d", e.Have, e.Threshold)
}

func (e *InsufficientSharesError) Unwrap() error {
	return ErrInsufficientShares
}

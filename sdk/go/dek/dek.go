// Copyright (c) 2026 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Package dek re-exports go-qrdb's DEK management types through go-xkms so
// consumers of the go-xkms SDK never need to import go-qrdb/sdk/go/dek
// directly. This is the "go-xkms inherits from go-qrdb via SDK layers"
// indirection described in the architecture docs.
//
// All public symbols are aliases of the go-qrdb SDK's dek package.
// There is no logic in this file.
//
// See github.com/jeremyhahn/go-qrdb/sdk/go/dek for the canonical documentation.
package dek

import (
	"context"
	"log/slog"
	"time"

	qrdbdek "github.com/jeremyhahn/go-qrdb/sdk/go/dek"
)

// TenantDEKManager is the re-export of qrdbdek.TenantDEKManager.
type TenantDEKManager = qrdbdek.TenantDEKManager

// ClusterDEKManager is the re-export of qrdbdek.ClusterDEKManager.
type ClusterDEKManager = qrdbdek.ClusterDEKManager

// TenantDEKStatus is the re-export of qrdbdek.TenantDEKStatus.
type TenantDEKStatus = qrdbdek.TenantDEKStatus

// TenantDEKManagerConfig is the re-export of qrdbdek.TenantDEKManagerConfig.
type TenantDEKManagerConfig = qrdbdek.TenantDEKManagerConfig

// StorageBackend is the re-export of qrdbdek.StorageBackend.
type StorageBackend = qrdbdek.StorageBackend

// EncryptionBarrier is the re-export of qrdbdek.EncryptionBarrier.
type EncryptionBarrier = qrdbdek.EncryptionBarrier

// TenantServicer is the re-export of qrdbdek.TenantServicer.
type TenantServicer = qrdbdek.TenantServicer

// BootstrapState is the re-export of qrdbdek.BootstrapState.
type BootstrapState = qrdbdek.BootstrapState

// BootstrapResult is the re-export of qrdbdek.BootstrapResult.
type BootstrapResult = qrdbdek.BootstrapResult

// BootstrapOption is the re-export of qrdbdek.BootstrapOption.
type BootstrapOption = qrdbdek.BootstrapOption

// Bootstrap state constants.
const (
	BootstrapCreated       = qrdbdek.BootstrapCreated
	BootstrapAlreadyExists = qrdbdek.BootstrapAlreadyExists
	BootstrapDeferred      = qrdbdek.BootstrapDeferred
	BootstrapNonFatal      = qrdbdek.BootstrapNonFatal
)

// Algorithm and key-size constants.
const (
	AlgorithmAES256GCM = qrdbdek.AlgorithmAES256GCM
	AESKeySize         = qrdbdek.AESKeySize
)

// Error type re-exports.
type (
	NilInputError             = qrdbdek.NilInputError
	UnsupportedAlgorithmError = qrdbdek.UnsupportedAlgorithmError
	SealedError               = qrdbdek.SealedError
	CryptoError               = qrdbdek.CryptoError
	NotInitializedError       = qrdbdek.NotInitializedError
	AlreadyInProgressError    = qrdbdek.AlreadyInProgressError
	NoActiveOperationError    = qrdbdek.NoActiveOperationError
	NotImplementedError       = qrdbdek.NotImplementedError
	ManagerClosedError        = qrdbdek.ManagerClosedError
	NotFoundError             = qrdbdek.NotFoundError
	DecodeError               = qrdbdek.DecodeError
	EncodeError               = qrdbdek.EncodeError
	StorageOperationError     = qrdbdek.StorageOperationError
	CiphertextTooShortError   = qrdbdek.CiphertextTooShortError
	DataTruncatedError        = qrdbdek.DataTruncatedError
	RequiredFieldError        = qrdbdek.RequiredFieldError
	InvalidInputError         = qrdbdek.InvalidInputError
)

// IsNotFound is the re-export of qrdbdek.IsNotFound.
func IsNotFound(err error) bool { return qrdbdek.IsNotFound(err) }

// IsValidAlgorithm is the re-export of qrdbdek.IsValidAlgorithm.
func IsValidAlgorithm(algorithm string) bool { return qrdbdek.IsValidAlgorithm(algorithm) }

// NewClusterDEKManager is the re-export of qrdbdek.NewClusterDEKManager.
func NewClusterDEKManager(
	barrier EncryptionBarrier,
	logger *slog.Logger,
) (*ClusterDEKManager, error) {
	return qrdbdek.NewClusterDEKManager(barrier, logger)
}

// NewTenantDEKManager is the re-export of qrdbdek.NewTenantDEKManager.
func NewTenantDEKManager(
	clusterDEK *ClusterDEKManager,
	storage StorageBackend,
	logger *slog.Logger,
	config *TenantDEKManagerConfig,
) (TenantDEKManager, error) {
	return qrdbdek.NewTenantDEKManager(clusterDEK, storage, logger, config)
}

// BootstrapSystemTenant is the re-export of qrdbdek.BootstrapSystemTenant.
// This is the SINGLE canonical system-tenant bootstrap function. Do not
// reimplement it; call this instead.
func BootstrapSystemTenant(ctx context.Context, svc TenantServicer, opts ...BootstrapOption) *BootstrapResult {
	return qrdbdek.BootstrapSystemTenant(ctx, svc, opts...)
}

// WithBootstrapTimeout is the re-export of qrdbdek.WithBootstrapTimeout.
func WithBootstrapTimeout(d time.Duration) BootstrapOption {
	return qrdbdek.WithBootstrapTimeout(d)
}

// WithBootstrapLogger is the re-export of qrdbdek.WithBootstrapLogger.
func WithBootstrapLogger(l *slog.Logger) BootstrapOption {
	return qrdbdek.WithBootstrapLogger(l)
}

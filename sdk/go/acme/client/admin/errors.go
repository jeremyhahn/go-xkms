// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package admin

import "github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"

// TenantNotFoundError indicates a tenant was not found.
type TenantNotFoundError struct {
	errors.CAError
}

// TenantAlreadyExistsError indicates a tenant already exists.
type TenantAlreadyExistsError struct {
	errors.CAError
}

// EABNotFoundError indicates an EAB was not found.
type EABNotFoundError struct {
	errors.CAError
}

// RoleNotFoundError indicates a role was not found.
type RoleNotFoundError struct {
	errors.CAError
}

// UserNotFoundError indicates a user was not found.
type UserNotFoundError struct {
	errors.CAError
}

// CertificateNotFoundError indicates a certificate was not found.
type CertificateNotFoundError struct {
	errors.CAError
}

// AccountNotFoundError indicates an account was not found.
type AccountNotFoundError struct {
	errors.CAError
}

// OrderNotFoundError indicates an order was not found.
type OrderNotFoundError struct {
	errors.CAError
}

// TenantRootCAExistsError indicates a tenant root CA already exists.
type TenantRootCAExistsError struct {
	errors.CAError
}

// TenantRootCANotFoundError indicates a tenant root CA was not found.
type TenantRootCANotFoundError struct {
	errors.CAError
}

// IntermediateCANotFoundError indicates an intermediate CA was not found.
type IntermediateCANotFoundError struct {
	errors.CAError
}

// IntermediateCAExistsError indicates an intermediate CA already exists.
type IntermediateCAExistsError struct {
	errors.CAError
}

// RevocationFailedError indicates a certificate revocation failed.
type RevocationFailedError struct {
	errors.CAError
}

// NewTenantNotFound creates a TenantNotFoundError.
func NewTenantNotFound(op, message string) *TenantNotFoundError {
	return &TenantNotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewTenantAlreadyExists creates a TenantAlreadyExistsError.
func NewTenantAlreadyExists(op, message string) *TenantAlreadyExistsError {
	return &TenantAlreadyExistsError{
		CAError: *errors.NewAlreadyExists(op, message),
	}
}

// NewEABNotFound creates an EABNotFoundError.
func NewEABNotFound(op, message string) *EABNotFoundError {
	return &EABNotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewRoleNotFound creates a RoleNotFoundError.
func NewRoleNotFound(op, message string) *RoleNotFoundError {
	return &RoleNotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewUserNotFound creates a UserNotFoundError.
func NewUserNotFound(op, message string) *UserNotFoundError {
	return &UserNotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewCertificateNotFound creates a CertificateNotFoundError.
func NewCertificateNotFound(op, message string) *CertificateNotFoundError {
	return &CertificateNotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewAccountNotFound creates an AccountNotFoundError.
func NewAccountNotFound(op, message string) *AccountNotFoundError {
	return &AccountNotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewOrderNotFound creates an OrderNotFoundError.
func NewOrderNotFound(op, message string) *OrderNotFoundError {
	return &OrderNotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewTenantRootCAExists creates a TenantRootCAExistsError.
func NewTenantRootCAExists(op, message string) *TenantRootCAExistsError {
	return &TenantRootCAExistsError{
		CAError: *errors.NewAlreadyExists(op, message),
	}
}

// NewTenantRootCANotFound creates a TenantRootCANotFoundError.
func NewTenantRootCANotFound(op, message string) *TenantRootCANotFoundError {
	return &TenantRootCANotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewIntermediateCANotFound creates an IntermediateCANotFoundError.
func NewIntermediateCANotFound(op, message string) *IntermediateCANotFoundError {
	return &IntermediateCANotFoundError{
		CAError: *errors.NewNotFound(op, message),
	}
}

// NewIntermediateCAExists creates an IntermediateCAExistsError.
func NewIntermediateCAExists(op, message string) *IntermediateCAExistsError {
	return &IntermediateCAExistsError{
		CAError: *errors.NewAlreadyExists(op, message),
	}
}

// NewRevocationFailed creates a RevocationFailedError.
func NewRevocationFailed(op, message string) *RevocationFailedError {
	return &RevocationFailedError{
		CAError: *errors.NewInternal(op, message),
	}
}

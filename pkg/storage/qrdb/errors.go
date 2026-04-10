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

// Package qrdb provides a storage.Backend implementation backed by a
// QRDB KVClient, enabling go-xkms to use embedded or distributed QRDB
// engines for key-value persistence.
package qrdb

// BackendError wraps a transport-level error with the storage operation
// and key that triggered it.
type BackendError struct {
	Op  string
	Key string
	Err error
}

// Error returns a human-readable description of the backend error.
func (e *BackendError) Error() string {
	msg := "qrdb: " + e.Op
	if e.Key != "" {
		msg += " key=" + e.Key
	}
	msg += ": " + e.Err.Error()
	return msg
}

// Unwrap returns the underlying transport error.
func (e *BackendError) Unwrap() error {
	return e.Err
}

// FactoryError is returned when an embedded engine factory fails to
// initialize the QRDB stack (storage, state machine, services, or client).
type FactoryError struct {
	Engine string
	Err    error
}

// Error returns a human-readable description of the factory error.
func (e *FactoryError) Error() string {
	return "qrdb factory: engine=" + e.Engine + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *FactoryError) Unwrap() error {
	return e.Err
}

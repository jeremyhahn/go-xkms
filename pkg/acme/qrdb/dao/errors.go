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

// Package dao provides QRDB-backed DAO adapters that implement the go-xkms
// storage interfaces. These adapters wrap QRDB's GenericDAO for uint64-keyed entities
// and use kvstore.KVStore directly for string-keyed entities (Tenant, ExternalAccountBinding).
package dao

// NilEntityError is returned when a nil entity is passed to a DAO operation.
type NilEntityError struct {
	EntityType string
}

// Error returns a human-readable description of the nil entity error.
func (e NilEntityError) Error() string {
	return "qrdb dao: " + e.EntityType + " entity cannot be nil"
}

// NilKVStoreError is returned when a nil KVStore is provided during initialization.
type NilKVStoreError struct{}

// Error returns a human-readable description of the nil KVStore error.
func (e NilKVStoreError) Error() string {
	return "qrdb dao: kvstore cannot be nil"
}

// InvalidIDError is returned when an invalid identifier is provided.
type InvalidIDError struct {
	EntityType string
	Reason     string
}

// Error returns a human-readable description of the invalid ID error.
func (e InvalidIDError) Error() string {
	return "qrdb dao: invalid " + e.EntityType + " ID: " + e.Reason
}

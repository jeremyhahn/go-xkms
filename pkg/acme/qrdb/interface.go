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

package qrdb

import (
	"context"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// Service defines the interface for QRDB integration within go-trusted-ca.
// It provides typed accessors for all QRDB subsystems including key-value
// storage, cluster administration, watches, leases, batch operations,
// transactions, and secondary indexes.
type Service interface {
	// KV returns a KVClient for data-plane key-value operations.
	KV() db.KVClient

	// Admin returns an AdminClient for control-plane cluster operations.
	Admin() db.AdminClient

	// Watch returns a WatchClient for event streaming on key changes.
	Watch() db.WatchClient

	// Lease returns a LeaseClient for distributed lease management.
	Lease() db.LeaseClient

	// Batch returns a BatchClient for atomic batch operations.
	Batch() db.BatchClient

	// Transaction returns a TransactionClient for atomic compare-and-swap
	// transaction execution.
	Transaction() db.TransactionClient

	// Index returns an IndexClient for secondary index management.
	Index() db.IndexClient

	// Users returns a UserClient for user management operations
	// including creation, listing, enable/disable.
	Users() db.UserClient

	// Roles returns a RoleClient for role-based access control
	// including role CRUD, permission management, and role assignment.
	Roles() db.RoleClient

	// Certs returns a CertClient for certificate management operations
	// including generation, export, revocation, and listing.
	Certs() db.CertClient

	// Barrier returns a BarrierClient for cryptographic barrier operations
	// including seal/unseal, Shamir secret sharing, and recovery keys.
	Barrier() db.BarrierClient

	// Ceremony returns a CeremonyClient for M-of-N initialization
	// ceremony operations including officer enrollment and share distribution.
	Ceremony() db.CeremonyClient

	// Credentials returns a CredentialClient for named credential
	// management using the configured sealing strategy.
	Credentials() db.CredentialClient

	// Config returns the service configuration.
	Config() *Config

	// Healthy reports whether the QRDB connection is healthy.
	Healthy(ctx context.Context) bool

	// Close shuts down the QRDB client and releases all resources.
	Close() error
}

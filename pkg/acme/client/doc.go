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

// Package trustedca provides a library entry point for the go-xkms ACME Certificate Authority.
//
// It is an ACME RFC-8555 compliant Certificate Authority with support
// for Trusted Computing specifications and multi-tenancy via QRDB.
//
// # Quick Start
//
// Basic usage with all components:
//
//	import (
//	    "github.com/jeremyhahn/go-xkms/pkg/acme/client"
//	    "github.com/jeremyhahn/go-xkms/pkg/ca"
//	    "github.com/jeremyhahn/go-xkms/pkg/acme/storage"
//	)
//
//	// Create CA and storage
//	myCA, _ := ca.New(caConfig)
//	storageFactory, _ := storage.NewFactory(storageConfig)
//
//	// Create TrustedCA instance
//	tca, err := trustedca.New(
//	    trustedca.WithCA(myCA),
//	    trustedca.WithStorageFactory(storageFactory),
//	    trustedca.WithConfig(config),
//	)
//
//	// Start serving
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	tca.Serve(ctx)
//
// # Multi-Tenant Mode with QRDB
//
// For multi-tenant deployments with authentication:
//
//	import (
//	    "github.com/jeremyhahn/go-xkms/pkg/acme/client"
//	)
//
//	// Parent application creates QRDB service
//	db, _ := qrdb.New(qrdbConfig)
//
//	// Pass to TrustedCA
//	tca, err := trustedca.New(
//	    trustedca.WithQRDB(db),
//	    trustedca.WithCA(myCA),
//	    trustedca.WithStorageFactory(storageFactory),
//	    trustedca.WithMultiTenant(),
//	)
//
// # Supported Challenge Types
//
// TrustedCA supports the following ACME challenge types:
//   - http-01: HTTP challenge (RFC 8555)
//   - dns-01: DNS challenge (RFC 8555)
//   - device-attest-01: TPM device attestation
//   - endorse-01: EK certificate issuance for TPMs without manufacturer certificates
//
// # Architecture
//
// TrustedCA integrates:
//   - ACME server for certificate issuance
//   - Admin API for management operations
//   - QRDB for authentication and storage
//   - Multi-tenant support with per-tenant CAs and policies
package client

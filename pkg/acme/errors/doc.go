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

// Package errors provides a typed error system for go-trusted-ca that:
//
//  1. Survives gRPC boundaries by implementing the GRPCStatus interface
//     and serializing type metadata in gRPC response metadata.
//
//  2. Maps directly to RFC 8555 ACME Problem Documents for automatic
//     conversion in the frontend API layer.
//
// This enables deeply-nested services to return specific error types
// that propagate all the way to ACME clients as proper problem documents.
//
// Error types are defined as an iota enum and can be wrapped with context
// while preserving the original type information across service boundaries.
//
// Example usage:
//
//	// Create a typed error
//	err := errors.NotFoundError("account %s not found", accountID)
//
//	// Check error type
//	if errors.Is(err, errors.NotFound) {
//	    // Handle not found case
//	}
//
//	// Convert to ACME Problem Document
//	problem := errors.ToProblemDocument(err)
package errors

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

// Package grpc provides gRPC protocol adapter for go-xkms services.
//
// To use the gRPC adapter:
//  1. Run 'make proto' to generate protobuf code
//  2. Build with -tags=grpc
//
// Example:
//
//	go build -tags=grpc ./...
package grpc

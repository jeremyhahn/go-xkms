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

// Package interceptors provides gRPC server interceptors for deadline management,
// logging, metrics, and other cross-cutting concerns.
//
// The deadline interceptor properly manages client deadlines by subtracting
// network return overhead to ensure handlers complete within the deadline,
// accounting for the time needed to send the response back to the client.
//
// Example usage:
//
//	server := grpc.NewServer(
//	    grpc.UnaryInterceptor(interceptors.DeadlineInterceptor(20*time.Millisecond)),
//	    grpc.StreamInterceptor(interceptors.StreamDeadlineInterceptor(20*time.Millisecond)),
//	)
package interceptors

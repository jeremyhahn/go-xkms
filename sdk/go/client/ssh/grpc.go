// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package ssh

// GRPCOptions is the configuration stub for the future gRPC transport.
// The Client it would construct is reserved by this placeholder — the
// REST transport (Phase 1c) is the primary remote surface, and gRPC
// will land alongside or after.
type GRPCOptions struct {
	// Endpoint is the dial target (host:port). Required when
	// implemented.
	Endpoint string
}

// NewGRPC returns NotImplementedError. The symbol exists so callers can
// detect the stub at compile time without guessing at a future name.
func NewGRPC(_ GRPCOptions) (Client, error) {
	return nil, &NotImplementedError{Transport: "grpc", Op: "NewGRPC"}
}

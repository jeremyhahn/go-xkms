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

//go:build integration && !grpc

package multiprotocol

import (
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
)

// createGRPCAdapter returns a stub adapter when the grpc build tag is not present.
// To use the real gRPC adapter, build with: go test -tags=integration,grpc
func createGRPCAdapter(config *ServerConfig, logger *slog.Logger) api.AdminAdapter {
	logger.Warn("gRPC adapter not available - build with -tags=grpc to enable")
	return newStubAdapter(api.ProtocolGRPC, "gRPC requires proto generation - build with -tags=grpc")
}

// createGRPCUnixAdapter returns a stub adapter when the grpc build tag is not present.
// To use the real gRPC Unix adapter, build with: go test -tags=integration,grpc
func createGRPCUnixAdapter(config *ServerConfig, logger *slog.Logger) api.AdminAdapter {
	logger.Warn("gRPC Unix adapter not available - build with -tags=grpc to enable")
	return newStubAdapter(api.ProtocolUnix, "gRPC Unix requires proto generation - build with -tags=grpc")
}

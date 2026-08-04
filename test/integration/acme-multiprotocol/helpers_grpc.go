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

//go:build integration && grpc

package multiprotocol

import (
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api/grpc"
)

// createGRPCAdapter creates a gRPC adapter using the real implementation.
// This file is only built when the grpc build tag is present.
func createGRPCAdapter(config *ServerConfig, logger *slog.Logger) api.AdminAdapter {
	if config.GRPCAddr == "" {
		logger.Warn("gRPC address not configured, using stub adapter")
		return newStubAdapter(api.ProtocolGRPC, "gRPC address not configured")
	}

	adapter, err := grpc.NewAdapter(&api.AdapterConfig{
		GRPCAddr:  config.GRPCAddr,
		TLSConfig: config.TLSConfig,
	})
	if err != nil {
		logger.Warn("failed to create gRPC adapter", "error", err)
		return newStubAdapter(api.ProtocolGRPC, err.Error())
	}

	logger.Info("gRPC adapter created successfully", "address", config.GRPCAddr)
	return adapter
}

// createGRPCUnixAdapter creates a gRPC adapter that connects via Unix domain socket.
// This uses the same gRPC client but connects to a Unix socket instead of TCP.
func createGRPCUnixAdapter(config *ServerConfig, logger *slog.Logger) api.AdminAdapter {
	if config.GRPCUnixPath == "" {
		logger.Warn("gRPC Unix socket path not configured, using stub adapter")
		return newStubAdapter(api.ProtocolUnix, "gRPC Unix socket path not configured")
	}

	adapter, err := grpc.NewAdapter(&api.AdapterConfig{
		GRPCUnixPath: config.GRPCUnixPath,
	})
	if err != nil {
		logger.Warn("failed to create gRPC Unix adapter", "error", err)
		return newStubAdapter(api.ProtocolUnix, err.Error())
	}

	logger.Info("gRPC Unix adapter created successfully", "path", config.GRPCUnixPath)
	return adapter
}

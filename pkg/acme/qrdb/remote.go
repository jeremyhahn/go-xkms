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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/grpc"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/mcp"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/quic"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/rest"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/unix"
)

// transportConstructor is a factory function that creates a Transport
// from the given options. Each remote protocol registers a constructor
// in the transportFactory map.
type transportConstructor func(opts ...transport.Option) (transport.Transport, error)

// transportFactory provides O(1) protocol-to-constructor dispatch for
// remote QRDB transports.
var transportFactory = map[Protocol]transportConstructor{
	ProtocolREST: func(opts ...transport.Option) (transport.Transport, error) { return rest.New(opts...) },
	ProtocolGRPC: func(opts ...transport.Option) (transport.Transport, error) { return grpc.New(opts...) },
	ProtocolQUIC: func(opts ...transport.Option) (transport.Transport, error) { return quic.New(opts...) },
	ProtocolUnix: func(opts ...transport.Option) (transport.Transport, error) { return unix.New(opts...) },
	ProtocolMCP:  func(opts ...transport.Option) (transport.Transport, error) { return mcp.New(opts...) },
}

// createClient builds an SDK client from the service configuration by
// looking up the appropriate transport constructor, building transport
// options from the config, and connecting the client.
func createClient(sc *serviceConfig) (*qrdbsdk.Client, error) {
	constructor, ok := transportFactory[sc.config.Protocol]
	if !ok {
		return nil, NewError(ErrorCodeInvalidConfig, "unsupported remote protocol").
			WithContext("protocol", string(sc.config.Protocol))
	}

	opts := buildTransportOptions(sc.config)

	rt, err := constructor(opts...)
	if err != nil {
		return nil, NewError(ErrorCodeConnection, "failed to create transport").
			WithCause(err).
			WithContext("protocol", string(sc.config.Protocol))
	}

	client, err := qrdbsdk.NewClient(rt)
	if err != nil {
		return nil, NewError(ErrorCodeConnection, "failed to create sdk client").
			WithCause(err).
			WithContext("protocol", string(sc.config.Protocol))
	}

	if err := client.Connect(context.Background()); err != nil {
		return nil, NewError(ErrorCodeConnection, "failed to connect to qrdb server").
			WithCause(err).
			WithContext("protocol", string(sc.config.Protocol)).
			WithContext("address", resolveAddress(sc.config))
	}

	return client, nil
}

// buildTransportOptions constructs transport.Option values from the
// service Config. For unix protocol, the socket path is used as the
// address. TLS and timeout options are added when configured.
func buildTransportOptions(cfg *Config) []transport.Option {
	opts := make([]transport.Option, 0, 4)

	addr := resolveAddress(cfg)
	if addr != "" {
		opts = append(opts, transport.WithAddress(addr))
	}

	if cfg.ClientTLS != nil && cfg.ClientTLS.CAFile != "" {
		opts = append(opts, transport.WithTLS(
			cfg.ClientTLS.CertFile,
			cfg.ClientTLS.KeyFile,
			cfg.ClientTLS.CAFile,
		))
	}

	if cfg.Timeout > 0 {
		opts = append(opts, transport.WithTimeout(cfg.Timeout))
	}

	return opts
}

// resolveAddress returns the appropriate address for the configured
// protocol. Unix protocol uses UnixSocketPath; all others use Address.
func resolveAddress(cfg *Config) string {
	if cfg.Protocol == ProtocolUnix {
		return cfg.UnixSocketPath
	}
	return cfg.Address
}

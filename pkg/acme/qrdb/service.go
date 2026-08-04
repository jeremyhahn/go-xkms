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

package qrdb

import (
	"context"
	"sync/atomic"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/embedded"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// service is the production implementation of the Service interface.
type service struct {
	client         *qrdbsdk.Client
	cfg            *Config
	embeddedServer *embedded.Server
	healthy        atomic.Bool
	closed         atomic.Bool
}

// New creates a new QRDB Service from the provided options.
//
// When WithQRDBClient is provided, the service uses the supplied client
// directly. Otherwise, a client is constructed from the configuration.
// For embedded protocol, an in-process QRDB server is created via the
// embedded.NewServer factory. For remote protocols, a transport-based
// client is constructed from the configuration.
func New(opts ...ServiceOption) (Service, error) {
	sc := &serviceConfig{}
	for _, opt := range opts {
		opt(sc)
	}

	// Use provided client directly.
	if sc.client != nil {
		cfg := sc.config
		if cfg == nil {
			cfg = DefaultConfig()
		}
		svc := &service{
			client: sc.client,
			cfg:    cfg,
		}
		svc.healthy.Store(true)
		return svc, nil
	}

	// Validate configuration when constructing a new client.
	if sc.config == nil {
		return nil, NewError(ErrorCodeInvalidConfig, "config is required when no client is provided")
	}
	if err := sc.config.Validate(); err != nil {
		return nil, err
	}

	// Embedded mode: create an in-process QRDB server via the real
	// embedded.NewServer factory from go-qrdb.
	if sc.config.Protocol == ProtocolEmbedded {
		serverCfg := &embedded.ServerConfig{
			DataDir: sc.config.DataDir,
			Backend: xkmssdk.QRDBBackendPebble,
		}

		// Pass barrier config if enabled.
		if sc.config.Barrier != nil && sc.config.Barrier.Enabled {
			serverCfg.Barrier = &embedded.BarrierConfig{
				Strategy: sc.config.Barrier.Strategy,
			}
			if sc.config.Barrier.Shamir != nil {
				serverCfg.Barrier.Shamir = &embedded.ShamirConfig{
					Threshold: sc.config.Barrier.Shamir.Threshold,
					Total:     sc.config.Barrier.Shamir.Total,
				}
			}
		}

		server, err := embedded.NewServer(context.Background(), serverCfg)
		if err != nil {
			return nil, NewError(ErrorCodeServiceInit, "failed to create embedded QRDB server").
				WithCause(err)
		}

		svc := &service{
			client:         server.Client(),
			cfg:            sc.config,
			embeddedServer: server,
		}
		svc.healthy.Store(true)
		return svc, nil
	}

	// Construct transport-based client from configuration.
	client, err := createClient(sc)
	if err != nil {
		return nil, err
	}

	svc := &service{
		client: client,
		cfg:    sc.config,
	}
	svc.healthy.Store(true)
	return svc, nil
}

// KV returns a KVClient for data-plane key-value operations.
func (s *service) KV() db.KVClient {
	return s.client.KV()
}

// Admin returns an AdminClient for control-plane cluster operations.
func (s *service) Admin() db.AdminClient {
	return s.client.Admin()
}

// Watch returns a WatchClient for event streaming on key changes.
func (s *service) Watch() db.WatchClient {
	return s.client.Watch()
}

// Lease returns a LeaseClient for distributed lease management.
func (s *service) Lease() db.LeaseClient {
	return s.client.Lease()
}

// Batch returns a BatchClient for atomic batch operations.
func (s *service) Batch() db.BatchClient {
	return s.client.Batch()
}

// Transaction returns a TransactionClient for atomic compare-and-swap
// transaction execution.
func (s *service) Transaction() db.TransactionClient {
	return s.client.Transaction()
}

// Index returns an IndexClient for secondary index management.
func (s *service) Index() db.IndexClient {
	return s.client.Index()
}

// Users returns a UserClient for user management operations.
func (s *service) Users() db.UserClient {
	return s.client.Users()
}

// Roles returns a RoleClient for role-based access control operations.
func (s *service) Roles() db.RoleClient {
	return s.client.Roles()
}

// Certs returns a CertClient for certificate management operations.
func (s *service) Certs() db.CertClient {
	return s.client.Certs()
}

// Barrier returns a BarrierClient for cryptographic barrier operations.
func (s *service) Barrier() db.BarrierClient {
	return s.client.Barrier()
}

// Ceremony returns a CeremonyClient for M-of-N initialization ceremony operations.
func (s *service) Ceremony() db.CeremonyClient {
	return s.client.Ceremony()
}

// Credentials returns a CredentialClient for named credential management.
func (s *service) Credentials() db.CredentialClient {
	return s.client.Credentials()
}

// Config returns the service configuration.
func (s *service) Config() *Config {
	return s.cfg
}

// Healthy reports whether the QRDB connection is healthy.
func (s *service) Healthy(ctx context.Context) bool {
	if s.closed.Load() {
		return false
	}
	return s.client.Healthy(ctx)
}

// Close shuts down the QRDB client and releases all resources.
// When running in embedded mode, the embedded server is also shut down.
func (s *service) Close() error {
	if s.closed.Swap(true) {
		return nil // already closed
	}
	s.healthy.Store(false)
	if s.embeddedServer != nil {
		return s.embeddedServer.Shutdown(context.Background())
	}
	return s.client.Close()
}

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

package server

import (
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// CA returns the TrustedCA instance used by the server, or nil when the CA
// subsystem has not been configured. The returned instance is used by the
// ACME integration to bootstrap an ACME-compatible certificate authority
// against shared keystore state.
func (s *Server) CA() ca.TrustedCA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ca
}

// QRDBClient returns the embedded qrdb node's SDK client, or nil before the
// node has been constructed. It is the same client type (*qrdbsdk.Client)
// that already structurally satisfies pkg/acme/qrdb.Service (KV, Admin,
// Watch, Lease, Batch, Transaction, Index, Users, Roles, Certs all match by
// method signature), so a composing binary can pass it directly wherever
// that interface is required — e.g. the ACME admin surface's tenant role and
// user delegation to qrdb RBAC — without a bespoke adapter.
func (s *Server) QRDBClient() *qrdbsdk.Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.qrdbClient
}

// TenantService returns go-qrdb's canonical TenantServicer composed on the
// embedded node, or nil when the node barrier flip is not engaged
// (nodeSealEnabled false) or the node has not finished constructing yet. It
// mirrors CA() and Backend(name): a thin accessor for state pkg/server
// already owns, used by composing binaries (e.g. cmd/xkmsd's admin surface)
// that delegate tenant CRUD to qrdb instead of keeping a parallel model.
func (s *Server) TenantService() qrdbsdk.ServiceTenantServicer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tenantService
}

// Backend returns the keystore-backed xkms.Backend registered under the given
// name, or nil when no backend with that name has been initialized. The name
// matches the backend identifier used in configuration (e.g. "software",
// "pkcs8", "tpm2", ...).
func (s *Server) Backend(name string) xkms.Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backends[name]
}

// Logger returns the server's structured logger. External subsystems (such
// as the ACME integration bootstrapped from cmd/xkmsd) can use this to emit
// log messages that inherit the server's configured handler and level.
func (s *Server) Logger() *slog.Logger {
	return s.logger
}

// CreateStorage creates a new storage.Backend that uses the server's
// configured storage engine, rooted at the given subdirectory beneath the
// server's data directory (for persistent engines). This is the public
// entry-point used by optional subsystems (e.g. the ACME server) that need
// to persist their own state alongside the server's metadata.
//
// The caller is responsible for closing the returned Backend when it is no
// longer needed.
func (s *Server) CreateStorage(subdir string) (storage.Backend, error) {
	return s.createStorage(subdir)
}

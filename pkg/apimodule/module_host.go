// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package apimodule

import (
	"context"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// HostStoragePrefix is the qrdb key namespace a self-built module persists
// its stores under in the host's KV, one sub-namespace per feature
// (xkms/passwords/, xkms/ssh/, xkms/ca/, ...), so they never collide with
// the host's own keys. It is part of the persisted layout.
const HostStoragePrefix = "xkms/"

// HostBuildError reports that the module's self-built REST surface
// (rest.NewHostServer) failed to construct from the host's inputs — e.g.
// the resolved XKMSService has no crypto backend, or neither a signing
// backend nor a qrdb client is available to authenticate callers with.
// Module routes answer 503 with this error's message and AuthenticateHTTP
// fails closed on it: a host that gave the module nothing to build a REST
// surface from must find out loudly, not by every route silently 404ing or
// 401ing as if the surface had never been registered.
type HostBuildError struct {
	Err error
}

// Error implements the error interface.
func (e *HostBuildError) Error() string {
	return "xkms module: host provided no usable REST inputs: " + e.Err.Error()
}

// Unwrap exposes the underlying construction error for errors.As/errors.Is.
func (e *HostBuildError) Unwrap() error { return e.Err }

// restServer resolves the REST surface backing the module's HTTP routes and
// its AuthenticateHTTP fallback.
//
// A host-supplied resolver (WithRESTServer) always wins: it shares whatever
// REST wiring the host itself runs (xkmsd's own case — pkg/server
// ModuleRESTServer). Absent one, the module lazily self-builds a
// non-listening *rest.Server around the resolved XKMSService
// (rest.NewHostServer) using whatever host inputs were configured
// (WithQRDBClient, WithWebAuthnConfig,
// WithWebAuthnCredentialStoreDecorator, WithSessionOptions, WithPIVLogin)
// and the store-backed features hostStores composed from the host's
// dependencies,
// so a host that merely composes the module via NewServiceModule still gets
// a working REST surface instead of the module's HTTP surface silently not
// existing.
//
// Returns (nil, nil) while composition is still in progress (the resolved
// XKMSService is not yet available) — callers retry on the next request, as
// before. Returns a non-nil error only for a genuine, sticky-until-retried
// construction failure; callers surface it as a loud 503 rather than the
// generic "still composing" message.
func (m *Module) restServer() (*rest.Server, error) {
	if m.resolveREST != nil {
		return m.resolveREST(), nil
	}
	if srv := m.selfREST.Load(); srv != nil {
		return srv, nil
	}

	x := m.resolve()
	if x == nil {
		return nil, nil
	}

	stores := m.hostStores(x)
	hc := &rest.HostConfig{
		XKMSService:   x,
		Session:       m.sessionOptions,
		PIVLogin:      m.pivLogin,
		PasswordStore: stores.PasswordStore,
		SSHClient:     stores.SSH,
	}
	if m.resolveQRDBClient != nil {
		hc.QRDBClient = m.resolveQRDBClient()
	}
	if hc.QRDBClient != nil {
		// WebAuthn credentials persist through the host datastore's DAO
		// factory; without one the WebAuthn routes stay unmounted.
		ds, err := datastore.New(hc.QRDBClient, config.DatastoreConfig{})
		if err != nil {
			return nil, &HostBuildError{Err: err}
		}
		hc.DAOFactory = ds.DAOFactory()
	}
	if m.webauthnConfig != nil {
		hc.WebAuthn = rest.WebAuthnConfigFromXKMS(m.webauthnConfig)
		hc.WebAuthnCredentialStoreDecorator = m.webauthnCredentialStoreDecorator
	}

	srv, err := rest.NewHostServer(context.Background(), hc)
	if err != nil {
		return nil, &HostBuildError{Err: err}
	}
	if !m.selfREST.CompareAndSwap(nil, srv) {
		srv = m.selfREST.Load()
	}
	return srv, nil
}

// selfBuilds reports whether the module composes its own surfaces from host
// inputs (no WithRESTServer). A module bound to a host-supplied REST server
// (xkmsd) serves what that host composed and never composes stores itself.
func (m *Module) selfBuilds() bool { return m.resolveREST == nil }

// hostStores composes the module's store-backed features from the host's
// inputs through pkg/compose -- the construction path xkmsd uses -- and
// wires them into x, exactly once. Every transport's first use (REST
// self-build, the gRPC keystore) goes through it, so all transports observe
// one set of stores.
//
// A dependency the host did not supply leaves its feature off; compose
// logs each one with a typed reason and records it in Stores.Disabled.
func (m *Module) hostStores(x *xkms.XKMSService) *compose.Stores {
	if st := m.stores.Load(); st != nil {
		return st
	}
	m.composeMu.Lock()
	defer m.composeMu.Unlock()
	if st := m.stores.Load(); st != nil {
		return st
	}

	deps := compose.Deps{
		Service:             x,
		PIN:                 m.pinBackend,
		PlatformSealer:      m.platformSealer,
		CredentialStrategy:  m.credentialStrategy,
		CA:                  m.caConfig,
		TPMBackend:          compose.TPM2Backend(x),
		VTPM:                m.vtpm,
		PasskeyRelyingParty: m.passwordVaultRelyingParty(),
		Logger:              slog.Default().With("module", ModuleName),
	}
	if m.resolveQRDBClient != nil {
		if client := m.resolveQRDBClient(); client != nil {
			// Without storage compose leaves every store-backed feature
			// off and records why.
			open, daos, err := hostStorage(client, compose.Databases(deps))
			if err != nil {
				deps.Logger.Warn("module host storage unavailable", "error", err)
			}
			deps.Storage = open
			deps.DAOs = daos
			// The host node's lease primitive serializes OIDC credential
			// refreshes and elects their scheduler across the host's
			// cluster. A client whose transport carries no coordination
			// leaves the feature off, with its reason recorded.
			if coord, err := client.Coordination(); err == nil {
				deps.Leases = coord
			}
		}
	}
	if m.resolveBarrierRegistry != nil {
		deps.BarrierRegistry = m.resolveBarrierRegistry()
	}
	if m.resolveTenantStores != nil {
		deps.TenantStores = m.resolveTenantStores()
	}

	// Build fails only for a nil Service, which the callers have already
	// excluded; every feature failure is recorded in Stores.Disabled.
	st, err := compose.Build(context.Background(), deps)
	if err != nil {
		st = &compose.Stores{Disabled: []error{err}}
	}
	st.Wire(x)
	m.stores.Store(st)
	return st
}

// HostStores returns the store-backed features the module composed from
// its host's inputs, and the typed reason each missing one is off, or nil
// before the module's first use or when it serves a host-supplied REST
// server (WithRESTServer).
func (m *Module) HostStores() *compose.Stores { return m.stores.Load() }

// hostStorage opens each feature's store as a prefixed view under
// HostStoragePrefix over the DAO factory of a datastore on the host's
// client, and returns that factory serving each of databases. The views
// share one backend and their Close does not close the host's client. A
// database the host's client cannot open leaves the views and returns no
// factory, so only the features persisting DAO entities go off.
func hostStorage(client *qrdbsdk.Client, databases []string) (compose.StorageFactory, *qrdbsdk.DAOFactory, error) {
	ds, err := datastore.New(client, config.DatastoreConfig{})
	if err != nil {
		return nil, nil, err
	}
	open, err := compose.FactoryStorage(ds.DAOFactory(), HostStoragePrefix)
	if err != nil {
		return nil, nil, err
	}
	for _, name := range databases {
		if _, err := ds.DatabaseKVStore(context.Background(), name); err != nil {
			return open, nil, err
		}
	}
	return open, ds.DAOFactory(), nil
}

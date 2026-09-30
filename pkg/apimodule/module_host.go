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
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
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
		ServeBarrier:  m.barrierRoutes,
	}
	if m.resolveQRDBClient != nil {
		hc.QRDBClient = m.resolveQRDBClient()
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

// servesBarrierRoutes reports whether RegisterHTTP mounts the barrier route
// families (rest.IsBarrierRoute).
func (m *Module) servesBarrierRoutes() bool { return !m.selfBuilds() || m.barrierRoutes }

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
		Service:            x,
		PIN:                m.pinBackend,
		PlatformSealer:     m.platformSealer,
		CredentialStrategy: m.credentialStrategy,
		CA:                 m.caConfig,
		TPMBackend:         compose.TPM2Backend(x),
		VTPM:               m.vtpm,
		ServeBarrier:       m.barrierRoutes,
		Logger:             slog.Default().With("module", ModuleName),
	}
	if m.resolveQRDBClient != nil {
		if client := m.resolveQRDBClient(); client != nil {
			deps.Storage = hostStorage(client)
			if m.barrierRoutes {
				deps.Custodians = client.CustodianGroups()
				deps.Shares = client.Shares()
			}
		}
	}
	if m.resolveBarrierRegistry != nil {
		if inner := m.resolveBarrierRegistry(); inner != nil {
			deps.BarrierRegistry = seal.WrapBarrierRegistry(inner, inner.SystemBarrier())
		}
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

// hostStorage opens each feature's store as a prefixed view of the host's
// qrdb KV under HostStoragePrefix. The views share one backend and their
// Close does not close the host's client.
func hostStorage(client *qrdbsdk.Client) compose.StorageFactory {
	shared := qrdbstorage.NewBackend(client.KV())
	return func(name string) (storage.Backend, error) {
		return storage.NewPrefixBackend(shared, HostStoragePrefix+name+"/")
	}
}

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

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
)

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
// (WithQRDBClient, WithWebAuthnConfig, WithSessionOptions, WithPIVLogin),
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

	hc := &rest.HostConfig{
		XKMSService: x,
		Session:     m.sessionOptions,
		PIVLogin:    m.pivLogin,
	}
	if m.resolveQRDBClient != nil {
		hc.QRDBClient = m.resolveQRDBClient()
	}
	if m.webauthnConfig != nil {
		hc.WebAuthn = rest.WebAuthnConfigFromXKMS(m.webauthnConfig)
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

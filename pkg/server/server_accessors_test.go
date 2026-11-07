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

package server

import (
	"context"
	"net"
	"net/http"
	"testing"
	"testing/fstest"

	"google.golang.org/grpc/metadata"

	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// namedAuthenticator is a minimal auth.Authenticator whose Name() reports a
// fixed marker, so a test can prove a decorator's return value became the
// server's live authenticator instead of being silently ignored.
type namedAuthenticator struct{ name string }

func (n *namedAuthenticator) AuthenticateHTTP(*http.Request) (*auth.Identity, error) {
	return nil, auth.ErrUnauthenticated
}

func (n *namedAuthenticator) AuthenticateGRPC(context.Context, metadata.MD) (*auth.Identity, error) {
	return nil, auth.ErrUnauthenticated
}

func (n *namedAuthenticator) Name() string { return n.name }

// TestSetUIAssets proves SetUIAssets installs the given filesystem for the
// REST transport to serve.
func TestSetUIAssets(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	s := newServerForTest(t, cfg)

	require.Nil(t, s.uiAssets)
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}}
	s.SetUIAssets(assets)
	require.Equal(t, assets, s.uiAssets)
}

// TestSetRESTListener proves SetRESTListener stores the pre-bound listener
// for the REST transport to serve instead of binding the configured port.
func TestSetRESTListener(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	s := newServerForTest(t, cfg)
	require.Nil(t, s.restListener)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	s.SetRESTListener(ln)
	require.Same(t, ln, s.restListener)
}

// TestSetMetricsListener proves SetMetricsListener stores the pre-bound
// listener for the metrics server to serve instead of binding the
// configured port (go-xkms#1142). The behavioral proof -- that startMetrics
// actually serves on it and MetricsAddr reports it -- lives in
// metrics_listener_test.go; this is the field-assignment counterpart to
// TestSetRESTListener above.
func TestSetMetricsListener(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	s := newServerForTest(t, cfg)
	require.Nil(t, s.metricsListener)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	s.SetMetricsListener(ln)
	require.Same(t, ln, s.metricsListener)
}

// TestWithAuthenticatorDecorator proves the decorator option's return value
// replaces the server's built authenticator, not merely gets invoked and
// discarded.
func TestWithAuthenticatorDecorator(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	marker := &namedAuthenticator{name: "decorator-marker"}
	decorator := func(auth.Authenticator) auth.Authenticator { return marker }

	s := newServerForTest(t, cfg, WithAuthenticatorDecorator(decorator))
	require.Equal(t, "decorator-marker", s.authenticator.Name())
}

// TestWithExtraModules proves the option appends every supplied module to
// the server's extra-module list, preserving order, rather than replacing or
// dropping any of them.
func TestWithExtraModules(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	mod1 := &fakeServiceModule{name: "mod1"}
	mod2 := &fakeServiceModule{name: "mod2"}

	s := newServerForTest(t, cfg, WithExtraModules(mod1, mod2))
	require.Len(t, s.extraModules, 2)
	require.Equal(t, "mod1", s.extraModules[0].Name())
	require.Equal(t, "mod2", s.extraModules[1].Name())
}

// fakeServiceModule is a minimal qrdbserver.ServiceModule for exercising
// WithExtraModules without depending on any real module implementation.
type fakeServiceModule struct {
	qrdbserver.BaseModule
	name string
}

func (m *fakeServiceModule) Name() string { return m.name }

// TestEscrowRegistry_NilByDefault proves EscrowRegistry reports nil when
// escrow is not configured, matching initializeEscrow's documented no-op.
func TestEscrowRegistry_NilByDefault(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	s := newServerForTest(t, cfg)
	require.Nil(t, s.EscrowRegistry())
}

// TestQRDBClient_NilBeforeNodeConstruction proves QRDBClient reports nil
// before the embedded qrdb node has been constructed, matching CA()/
// Backend()'s "nil until wired" contract. Every datastore.mode "standalone"
// deployment (the default) now always constructs the embedded node by the
// time New() returns (go-xkms#1345) -- there is no longer a storage engine
// choice that skips it -- so this is checked directly against a
// newMinimalServer bypass (New() never called) rather than a full New(cfg),
// which the old backend-choice fixture used to leave the node unconstructed.
func TestQRDBClient_NilBeforeNodeConstruction(t *testing.T) {
	s := newMinimalServer(t, createMinimalConfig(t))
	require.Nil(t, s.QRDBClient())
}

func TestDatastore_NilBeforeInitialization(t *testing.T) {
	s := newMinimalServer(t, createMinimalConfig(t))
	require.Nil(t, s.Datastore())
}

func TestDatastore_ReturnsTheSharedDatastore(t *testing.T) {
	s := newMinimalServer(t, createMinimalConfig(t))
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	}
	ds, err := datastore.Open(context.Background(), cfg, s.logger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ds.Close()) })

	s.datastore.Store(ds)
	require.Same(t, ds, s.Datastore())
}

// TestTenantService_NilWithoutNodeFlip proves TenantService reports nil when
// the node barrier flip is not engaged.
func TestTenantService_NilWithoutNodeFlip(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t)
	s := newServerForTest(t, cfg)
	require.Nil(t, s.TenantService())
}

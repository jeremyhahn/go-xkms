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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/apimodule"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	sshrecords "github.com/jeremyhahn/go-xkms/pkg/ssh/records"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestShutdown_DrainsInFlightRequestBeforeClosingStorage shuts the server down
// while a request is in flight on the embedded node and has that request
// reach the shared datastore once shutdown has begun -- as the module REST
// binding does when the first request builds it (ModuleRESTServer ->
// ensureSSHClient -> daoFactory). Shutdown must drain the request before it
// closes the storage and the datastore the handler reads: the handler sees a
// live datastore, never a nil one, and the read never races the close.
func TestShutdown_DrainsInFlightRequestBeforeClosingStorage(t *testing.T) {
	tempDir := t.TempDir()
	ports := reserveLoopbackPorts(t, 2)
	restPort := ports.port(0)
	certFile, keyFile, caFile := createTestTLSFiles(t)

	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "127.0.0.1",
			RESTPort: restPort,
			QUICPort: ports.port(1),
		},
		Protocols: config.ProtocolsConfig{REST: true},
		Logging:   config.LoggingConfig{Level: "error", Format: "json"},
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		},
		Auth:      testJWTAuthConfig(t),
		Datastore: config.DatastoreConfig{Path: tempDir},
		Default:   config.DefaultConfig("software"),
		Backends: config.BackendsConfig{
			Software: &config.SoftwareConfig{
				Enabled: true,
				Path:    filepath.Join(tempDir, "software"),
			},
		},
		// First boot binds the administrator's certificate from this CA;
		// without one the node serves only the ceremony endpoints.
		CA: &ca.MultiIdentityCAConfig{
			DefaultValidityDays: 365,
			Identity: []ca.Identity{{
				IsRoot:  true,
				Valid:   1,
				Subject: ca.Subject{CommonName: "Shutdown In-Flight Root CA", Organization: "Test Org", Country: "US"},
				Keys: []*types.KeyConfig{
					{KeyAlgorithm: types.AlgorithmECDSA, ECCConfig: &types.ECCConfig{Curve: types.CurveP256}},
				},
			}},
		},
	}

	// The probe handler parks until shutdown has begun, then does what the
	// lazily built module REST binding does: it opens a feature database
	// through the shared datastore.
	var server *Server
	entered := make(chan struct{})
	type probeResult struct {
		err      error
		panicked any
	}
	result := make(chan probeResult, 1)
	probe, err := apimodule.NewAdminModule(func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			var res probeResult
			defer func() {
				res.panicked = recover()
				result <- res
			}()
			close(entered)
			<-server.ctx.Done()
			_, res.err = server.daoFactory(sshrecords.DatabaseName)
			w.WriteHeader(http.StatusOK)
		})
	}, []apimodule.AdminRoute{
		{Method: http.MethodGet, Path: "/admin/inflight", Permission: "acme_accounts:list"},
	})
	require.NoError(t, err)

	ports.Release(t)
	server, err = New(cfg, WithExtraModules(probe))
	require.NoError(t, err)

	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	t.Cleanup(client.CloseIdleConnections)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://localhost:%d/admin/inflight", restPort), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+mintTestSessionJWT(t))

	requestDone := make(chan error, 1)
	go func() {
		resp, doErr := client.Do(req)
		if doErr == nil {
			doErr = resp.Body.Close()
		}
		requestDone <- doErr
	}()

	select {
	case <-entered:
	case doErr := <-requestDone:
		t.Fatalf("the request ended before reaching the probe handler: %v", doErr)
	}

	require.NoError(t, server.Shutdown())

	// Shutdown drained the handler before it returned: its result is there.
	select {
	case res := <-result:
		assert.Nil(t, res.panicked, "the in-flight handler must not panic during shutdown")
		if res.err != nil {
			assert.NotErrorIs(t, res.err, ErrNoDatastore,
				"the in-flight handler must see the datastore it started with")
		}
	default:
		t.Fatal("Shutdown returned while the request was still in flight")
	}
	<-requestDone

	// After shutdown the datastore is gone, and a late caller is told so.
	_, err = server.daoFactory(sshrecords.DatabaseName)
	assert.ErrorIs(t, err, ErrNoDatastore)
}

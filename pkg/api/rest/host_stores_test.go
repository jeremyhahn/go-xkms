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

package rest

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/tenancy"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// routeSpec returns the table entry for method+pattern.
func routeSpec(t *testing.T, method, pattern string) RouteSpec {
	t.Helper()
	for _, spec := range Routes() {
		if spec.Method == method && spec.Pattern == pattern {
			return spec
		}
	}
	t.Fatalf("no route %s %s", method, pattern)
	return RouteSpec{}
}

func newHostTestService(t *testing.T) *xkms.XKMSService {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	return svc
}

// TestNewHostServer_StoreSurfacesFollowHostConfig proves the Password
// Manager and SSH surfaces mount exactly when the host hands in their
// stores, and the custodian/share surfaces only with ServeBarrier and the
// host's qrdb client.
func TestNewHostServer_StoreSurfacesFollowHostConfig(t *testing.T) {
	svc := newHostTestService(t)
	passwords := routeSpec(t, "GET", "/api/v1/passwords/")
	ssh := routeSpec(t, "GET", "/xkms/v1/ssh/keys")
	custodian := routeSpec(t, "GET", "/api/v1/custodian/groups/")
	shares := routeSpec(t, "GET", "/api/v1/shares/")
	ca := routeSpec(t, "GET", "/api/v1/ca/certificate")

	t.Run("nothing supplied", func(t *testing.T) {
		srv, err := NewHostServer(context.Background(), &HostConfig{XKMSService: svc, ServeBarrier: true})
		require.NoError(t, err)
		for _, spec := range []RouteSpec{passwords, ssh, custodian, shares, ca} {
			assert.False(t, srv.RouteEnabled(spec), "%s must stay off", spec.Pattern)
		}
	})

	t.Run("stores and barrier supplied", func(t *testing.T) {
		sshStorage, err := storage.NewMemoryBackend()
		require.NoError(t, err)
		sshClient, err := tenancy.New(tenancy.Options{Storage: sshStorage})
		require.NoError(t, err)
		client, _ := newFakeQRDBClient(t)

		srv, err := NewHostServer(context.Background(), &HostConfig{
			XKMSService:   svc,
			QRDBClient:    client,
			PasswordStore: staticpw.NewStore(storage.New()),
			SSHClient:     sshClient,
			ServeBarrier:  true,
		})
		require.NoError(t, err)
		for _, spec := range []RouteSpec{passwords, ssh, custodian, shares} {
			assert.True(t, srv.RouteEnabled(spec), "%s must mount", spec.Pattern)
		}
		assert.False(t, srv.RouteEnabled(ca), "no CA is wired into the service")
	})

	t.Run("barrier not served", func(t *testing.T) {
		client, _ := newFakeQRDBClient(t)
		srv, err := NewHostServer(context.Background(), &HostConfig{XKMSService: svc, QRDBClient: client})
		require.NoError(t, err)
		assert.False(t, srv.RouteEnabled(custodian))
		assert.False(t, srv.RouteEnabled(shares))
	})
}

func TestIsBarrierRoute(t *testing.T) {
	for _, pattern := range []string{
		"/api/v1/barrier/status",
		"/api/v1/custodian/groups/",
		"/api/v1/shares/submit",
		"/api/v1/init/status",
	} {
		assert.True(t, IsBarrierRoute(RouteSpec{Pattern: pattern}), pattern)
	}
	for _, pattern := range []string{
		"/api/v1/passwords/",
		"/api/v1/tenants/{tenantID}/barrier/status",
		"/api/v1/platform/status",
		"/xkms/v1/ssh/keys",
	} {
		assert.False(t, IsBarrierRoute(RouteSpec{Pattern: pattern}), pattern)
	}

	// Every family actually exists in the table, so the prefixes cannot
	// silently drift away from the routes they name.
	counts := map[string]int{}
	for _, spec := range Routes() {
		for _, prefix := range barrierRoutePrefixes {
			if strings.HasPrefix(spec.Pattern, prefix) {
				counts[prefix]++
			}
		}
	}
	for _, prefix := range barrierRoutePrefixes {
		assert.Positive(t, counts[prefix], "no route under %s", prefix)
	}
}

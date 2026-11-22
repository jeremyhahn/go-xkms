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
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
)

// Concurrent first requests on a self-building module build exactly one
// REST host: every caller gets the same *rest.Server, and the build's
// writes to the shared XKMSService (token issuer, WebAuthn, invite user
// client) never run twice at once, so the test is clean under -race.
func TestModuleHost_RestServer_ConcurrentFirstCallsBuildOnce(t *testing.T) {
	m, _, _ := nodeHostedModule(t)

	var builds atomic.Int32
	orig := newHostServer
	newHostServer = func(ctx context.Context, hc *rest.HostConfig) (*rest.Server, error) {
		builds.Add(1)
		return orig(ctx, hc)
	}
	t.Cleanup(func() { newHostServer = orig })

	const callers = 8
	var (
		start   sync.WaitGroup
		done    sync.WaitGroup
		servers [callers]*rest.Server
		errs    [callers]error
	)
	start.Add(1)
	for i := 0; i < callers; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			servers[i], errs[i] = m.restServer()
		}(i)
	}
	start.Done()
	done.Wait()

	for i := 0; i < callers; i++ {
		require.NoError(t, errs[i])
		require.NotNil(t, servers[i])
		assert.Same(t, servers[0], servers[i], "every caller must get the one published server")
	}
	assert.Equal(t, int32(1), builds.Load(), "exactly one REST host must be built")
}

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
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// backendMetricsFakeBackend is a minimal xkms.Backend stub for
// updateBackendMetrics: it implements only ListKeys, ListCerts, and Close --
// the three methods updateBackendMetrics actually calls. Every other method
// panics via the embedded nil xkms.Backend if a test reaches it
// unexpectedly. listKeysCalls/listCertsCalls count invocations (atomic:
// probeBackendMetrics runs its backends' probes on the test goroutine today,
// but the counters must stay race-detector-clean even if that changes) so a
// test can assert updateBackendMetrics makes at most one listing call per
// backend per sweep instead of double-listing (go-xkms#720 follow-up).
type backendMetricsFakeBackend struct {
	xkms.Backend
	keys    []*types.KeyAttributes
	certs   []string
	listErr error

	listKeysCalls  atomic.Int32
	listCertsCalls atomic.Int32
}

func (b *backendMetricsFakeBackend) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	b.listKeysCalls.Add(1)
	if b.listErr != nil {
		return nil, b.listErr
	}
	return b.keys, nil
}

func (b *backendMetricsFakeBackend) ListCerts(_ context.Context) ([]string, error) {
	b.listCertsCalls.Add(1)
	return b.certs, nil
}

func (b *backendMetricsFakeBackend) Close() error { return nil }

func backendHealthy(t *testing.T, name string) float64 {
	t.Helper()
	g, err := metrics.BackendHealthy.GetMetricWithLabelValues(name)
	require.NoError(t, err)
	return testutil.ToFloat64(g)
}

func keysTotal(t *testing.T, name string) float64 {
	t.Helper()
	g, err := metrics.KeysTotal.GetMetricWithLabelValues(name)
	require.NoError(t, err)
	return testutil.ToFloat64(g)
}

func certsTotal(t *testing.T, name string) float64 {
	t.Helper()
	g, err := metrics.CertsTotal.GetMetricWithLabelValues(name)
	require.NoError(t, err)
	return testutil.ToFloat64(g)
}

func operationsTotal(t *testing.T, operation, backend, status string) float64 {
	t.Helper()
	c, err := metrics.OperationsTotal.GetMetricWithLabelValues(operation, backend, status)
	require.NoError(t, err)
	return testutil.ToFloat64(c)
}

// TestUpdateBackendMetrics_HealthyBackend verifies that a responsive backend
// is published as healthy and its keys/certs gauges reflect ListKeys/ListCerts.
func TestUpdateBackendMetrics_HealthyBackend(t *testing.T) {
	metrics.Enable()

	s := newMinimalServer(t, &config.Config{})
	s.backends = map[string]xkms.Backend{
		"healthy-backend": &backendMetricsFakeBackend{
			keys:  []*types.KeyAttributes{{CN: "k1"}, {CN: "k2"}},
			certs: []string{"c1"},
		},
	}

	s.updateBackendMetrics()

	assert.Equal(t, float64(1), backendHealthy(t, "healthy-backend"))
	assert.Equal(t, float64(2), keysTotal(t, "healthy-backend"))
	assert.Equal(t, float64(1), certsTotal(t, "healthy-backend"))
}

// TestUpdateBackendMetrics_FailingBackend verifies that a backend whose
// ListKeys probe fails is published as unhealthy (go-xkms#720: this
// replaces the hard-coded metrics.SetBackendHealth(name, true) that ran
// regardless of whether the backend actually answered), and that the
// failure is also recorded as an OpHealthCheck error.
func TestUpdateBackendMetrics_FailingBackend(t *testing.T) {
	metrics.Enable()

	listErr := errors.New("backend not responding")
	s := newMinimalServer(t, &config.Config{})
	s.backends = map[string]xkms.Backend{
		"failing-backend": &backendMetricsFakeBackend{listErr: listErr},
	}

	beforeErrors := operationsTotal(t, metrics.OpHealthCheck, "failing-backend", metrics.StatusError)

	s.updateBackendMetrics()

	assert.Equal(t, float64(0), backendHealthy(t, "failing-backend"))
	assert.Equal(t, beforeErrors+1, operationsTotal(t, metrics.OpHealthCheck, "failing-backend", metrics.StatusError))

	// A failed ListKeys probe must not publish a keys-total gauge value: it
	// has no count to report, and publishing 0 would read as "empty backend"
	// rather than "backend did not answer".
	_, err := metrics.KeysTotal.GetMetricWithLabelValues("failing-backend")
	require.NoError(t, err)
	assert.Equal(t, float64(0), keysTotal(t, "failing-backend"))
}

// TestUpdateBackendMetrics_MixedBackends verifies one failing backend does
// not prevent a healthy sibling from being probed and published.
func TestUpdateBackendMetrics_MixedBackends(t *testing.T) {
	metrics.Enable()

	s := newMinimalServer(t, &config.Config{})
	s.backends = map[string]xkms.Backend{
		"ok":      &backendMetricsFakeBackend{keys: []*types.KeyAttributes{{CN: "k1"}}},
		"failing": &backendMetricsFakeBackend{listErr: errors.New("timeout")},
	}

	s.updateBackendMetrics()

	assert.Equal(t, float64(1), backendHealthy(t, "ok"))
	assert.Equal(t, float64(1), keysTotal(t, "ok"))
	assert.Equal(t, float64(0), backendHealthy(t, "failing"))
}

// TestUpdateBackendMetrics_SingleListCallPerBackend asserts the fix for the
// coordinator's performance review: one sweep calls ListKeys exactly once
// and ListCerts exactly once per backend -- the same ListKeys result backs
// both the health gauge and the keys-total reconciliation, rather than
// probing health through one call and recounting keys through a second one.
func TestUpdateBackendMetrics_SingleListCallPerBackend(t *testing.T) {
	metrics.Enable()

	backend := &backendMetricsFakeBackend{
		keys:  []*types.KeyAttributes{{CN: "k1"}, {CN: "k2"}, {CN: "k3"}},
		certs: []string{"c1"},
	}
	s := newMinimalServer(t, &config.Config{})
	s.backends = map[string]xkms.Backend{"counted": backend}

	s.updateBackendMetrics()

	assert.Equal(t, int32(1), backend.listKeysCalls.Load(), "ListKeys calls in one sweep")
	assert.Equal(t, int32(1), backend.listCertsCalls.Load(), "ListCerts calls in one sweep")
	assert.Equal(t, float64(3), keysTotal(t, "counted"))
	assert.Equal(t, float64(1), certsTotal(t, "counted"))
}

// TestUpdateBackendMetrics_ReconcilesRequestPathDrift asserts the periodic
// sweep is the reconciliation point for the request-path increment/decrement
// counters (pkg/xkms's incrementKeysTotal/decrementKeysTotal): an
// out-of-band drift -- a key created outside this process, or simply the
// gauge never having been set -- self-corrects to the real count on the
// next sweep rather than persisting.
func TestUpdateBackendMetrics_ReconcilesRequestPathDrift(t *testing.T) {
	metrics.Enable()

	backend := &backendMetricsFakeBackend{
		keys: []*types.KeyAttributes{{CN: "k1"}, {CN: "k2"}},
	}
	s := newMinimalServer(t, &config.Config{})
	s.backends = map[string]xkms.Backend{"drifted": backend}

	// Simulate drift: the gauge claims a count that does not match the
	// backend's real contents (e.g. a request-path Inc/Dec that never ran
	// in this process, or a key added by another tool entirely).
	metrics.SetKeysTotal("drifted", 99)
	require.Equal(t, float64(99), keysTotal(t, "drifted"))

	s.updateBackendMetrics()

	assert.Equal(t, float64(2), keysTotal(t, "drifted"), "sweep must overwrite drifted value with the real count")
}

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

package xkms

import (
	"context"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/metrics"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// counterValue reads a CounterVec series, returning 0 for a series that has
// not been observed yet (testutil.ToFloat64 panics on that case, which every
// "before" read in these tests would otherwise hit).
func counterValue(t *testing.T, vec *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	c, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	return testutil.ToFloat64(c)
}

// histogramSampleCount reads a HistogramVec series' observation count,
// returning 0 for a series that has not been observed yet.
func histogramSampleCount(t *testing.T, vec *prometheus.HistogramVec, labels ...string) uint64 {
	t.Helper()
	obs, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	hist, ok := obs.(prometheus.Histogram)
	require.True(t, ok)
	var m dto.Metric
	require.NoError(t, hist.Write(&m))
	return m.GetHistogram().GetSampleCount()
}

// gaugeValue reads a GaugeVec series, returning 0 for a series that has not
// been observed yet.
func gaugeValue(t *testing.T, vec *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	g, err := vec.GetMetricWithLabelValues(labels...)
	require.NoError(t, err)
	return testutil.ToFloat64(g)
}

// TestServiceBoundary_GenerateKey_RecordsOperation drives GenerateKey through
// the XKMSService boundary and asserts the real Prometheus counters and
// histogram it must update: this is the "instrument once at the service
// boundary" contract go-xkms#720 requires -- every transport reaches this
// same method, so counting here counts every transport exactly once.
func TestServiceBoundary_GenerateKey_RecordsOperation(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpGenerate, "software", metrics.StatusSuccess)
	beforeSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpGenerate, "software")
	beforeKeys := gaugeValue(t, metrics.KeysTotal, "software")

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "metrics-generate-key",
		Algorithm: "ecdsa",
		Backend:   "software",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpGenerate, "software", metrics.StatusSuccess)
	afterSamples := histogramSampleCount(t, metrics.OperationDuration, metrics.OpGenerate, "software")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=generate,backend=software,status=success}")
	assert.Equal(t, beforeSamples+1, afterSamples, "xkms_operation_duration_seconds sample count")

	// GenerateKey increments the keys-total gauge for the backend it wrote
	// to (go-xkms#720 follow-up: this is a direct Inc(), not a recount by
	// listing, so it costs no backend call on the request path -- see
	// pkg/xkms/metrics_instrumentation.go).
	assert.Equal(t, beforeKeys+1, gaugeValue(t, metrics.KeysTotal, "software"))
}

// TestServiceBoundary_GenerateKey_RecordsError asserts the error path: a
// failed operation increments ErrorsTotal with a bounded-cardinality
// error_type label (the Go type name) instead of the sentinel-free "error"
// string the old code would have produced, and still records the failed
// attempt's duration.
func TestServiceBoundary_GenerateKey_RecordsError(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	wantErrType := errorTypeLabel(ErrMissingAlgorithm)

	beforeErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpGenerate, "software", wantErrType)
	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpGenerate, "software", metrics.StatusError)

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:   "metrics-generate-key-missing-algo",
		Backend: "software",
	})
	require.ErrorIs(t, err, ErrMissingAlgorithm)

	afterErrors := counterValue(t, metrics.ErrorsTotal, metrics.OpGenerate, "software", wantErrType)
	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpGenerate, "software", metrics.StatusError)

	assert.Equal(t, beforeErrors+1, afterErrors, "xkms_errors_total")
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{status=error}")
}

// TestServiceBoundary_Sign_RecordsOperation covers the crypto surface: Sign,
// Verify, Encrypt, and Decrypt all share the exact same recordServiceOp
// wiring, so Sign stands in for that pattern here rather than repeating it
// four times.
func TestServiceBoundary_Sign_RecordsOperation(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	genResp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "metrics-sign-key",
		Algorithm: "ecdsa",
		Backend:   "software",
	})
	require.NoError(t, err)
	require.NotNil(t, genResp)
	_ = software

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpSign, "software", metrics.StatusSuccess)

	signResp, err := svc.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "metrics-sign-key",
		Data:    []byte("hello go-xkms#720"),
		Hash:    "SHA-256",
	})
	require.NoError(t, err)
	require.NotEmpty(t, signResp.Signature)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpSign, "software", metrics.StatusSuccess)
	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=sign,backend=software,status=success}")
}

// TestServiceBoundary_DeleteKey_DecrementsKeysTotal asserts the keys-total
// gauge tracks a delete, not only a create, through a plain Dec() -- not a
// recount by listing (go-xkms#720 follow-up).
func TestServiceBoundary_DeleteKey_DecrementsKeysTotal(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "metrics-delete-key",
		Algorithm: "ecdsa",
		Backend:   "software",
	})
	require.NoError(t, err)

	afterCreate := gaugeValue(t, metrics.KeysTotal, "software")
	require.GreaterOrEqual(t, afterCreate, float64(1))

	err = svc.DeleteKey(context.Background(), "software", "metrics-delete-key")
	require.NoError(t, err)

	afterDelete := gaugeValue(t, metrics.KeysTotal, "software")
	assert.Equal(t, afterCreate-1, afterDelete)
}

// TestServiceBoundary_SaveCertificate_IncrementsCertsTotal asserts the
// certs-total gauge tracks a certificate store (OpStore) and a delete,
// through plain Inc()/Dec() calls rather than a recount by listing
// (go-xkms#720 follow-up).
func TestServiceBoundary_SaveCertificate_IncrementsCertsTotal(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	certPEM, _ := testCertPEM(t)

	beforeTotal := counterValue(t, metrics.OperationsTotal, metrics.OpStore, "software", metrics.StatusSuccess)
	beforeCerts := gaugeValue(t, metrics.CertsTotal, "software")

	err = svc.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "metrics-cert",
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	afterTotal := counterValue(t, metrics.OperationsTotal, metrics.OpStore, "software", metrics.StatusSuccess)
	afterCerts := gaugeValue(t, metrics.CertsTotal, "software")

	assert.Equal(t, beforeTotal+1, afterTotal, "xkms_operations_total{operation=store,backend=software,status=success}")
	assert.Equal(t, beforeCerts+1, afterCerts, "xkms_certs_total{backend=software}")

	err = svc.DeleteCertificate(context.Background(), "software", "metrics-cert")
	require.NoError(t, err)

	afterDeleteCerts := gaugeValue(t, metrics.CertsTotal, "software")
	assert.Equal(t, beforeCerts, afterDeleteCerts)
}

// TestServiceBoundary_SaveCertificateChain_DoesNotChangeCertsTotal is a
// regression guard: a chain is stored under a distinct key
// (storage.CertChainPath) that storage.ListCerts excludes from the count
// CertsTotal tracks, so saving one must never increment the gauge the way
// SaveCertificate does.
func TestServiceBoundary_SaveCertificateChain_DoesNotChangeCertsTotal(t *testing.T) {
	// mockKeyStore.SaveCertChain (setupService's backend) always returns
	// "not implemented"; mockExtendedKeyStore is the test double that
	// actually stores a chain.
	setupExtendedService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	certPEM, _ := testCertPEM(t)
	beforeCerts := gaugeValue(t, metrics.CertsTotal, "software")

	err = svc.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend:  "software",
		KeyID:    "metrics-chain-cert",
		ChainPEM: []string{certPEM},
	})
	require.NoError(t, err)

	assert.Equal(t, beforeCerts, gaugeValue(t, metrics.CertsTotal, "software"))
}

// countingBackend wraps a Backend and counts ListKeys/ListCerts calls, so a
// test can assert the request path adds no listing call beyond whatever the
// operation's own logic already needs (go-xkms#720 follow-up: keys/certs
// totals must be incremented/decremented directly, never recounted by
// listing, on the request path -- recounting turns an O(1) key operation
// into O(n), and for a remote backend adds a network round trip per
// request).
type countingBackend struct {
	Backend
	listKeysCalls  int
	listCertsCalls int
}

func (c *countingBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	c.listKeysCalls++
	return c.Backend.ListKeys(ctx)
}

func (c *countingBackend) ListCerts(ctx context.Context) ([]string, error) {
	c.listCertsCalls++
	return c.Backend.ListCerts(ctx)
}

// TestServiceBoundary_GenerateKey_NoListKeysCall asserts GenerateKey's
// keys-total update costs zero ListKeys calls: nothing about generating a
// new key requires listing the backend's existing keys.
func TestServiceBoundary_GenerateKey_NoListKeysCall(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	counting := &countingBackend{Backend: software}
	require.NoError(t, RegisterServiceBackend("software", counting))

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "metrics-no-list-key",
		Algorithm: "ecdsa",
		Backend:   "software",
	})
	require.NoError(t, err)

	assert.Equal(t, 0, counting.listKeysCalls)
}

// TestServiceBoundary_DeleteKey_OnlyExistingListKeysCall asserts DeleteKey's
// keys-total update adds no ListKeys call beyond the one findKeyAttrs
// already makes to resolve the key's full attributes from its ID -- i.e.
// the metrics change did not reintroduce a second, metrics-only recount.
func TestServiceBoundary_DeleteKey_OnlyExistingListKeysCall(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	_, err = svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "metrics-delete-list-count",
		Algorithm: "ecdsa",
		Backend:   "software",
	})
	require.NoError(t, err)

	counting := &countingBackend{Backend: software}
	require.NoError(t, RegisterServiceBackend("software", counting))

	err = svc.DeleteKey(context.Background(), "software", "metrics-delete-list-count")
	require.NoError(t, err)

	assert.Equal(t, 1, counting.listKeysCalls, "exactly findKeyAttrs's own lookup, no metrics-only recount")
}

// TestServiceBoundary_SaveCertificate_NoListCertsCall asserts
// SaveCertificate's certs-total update costs zero ListCerts calls.
func TestServiceBoundary_SaveCertificate_NoListCertsCall(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	counting := &countingBackend{Backend: software}
	require.NoError(t, RegisterServiceBackend("software", counting))

	certPEM, _ := testCertPEM(t)
	err = svc.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "metrics-no-list-cert",
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	assert.Equal(t, 0, counting.listCertsCalls)
}

// TestServiceBoundary_DeleteCertificate_NoListCertsCall asserts
// DeleteCertificate's certs-total update costs zero ListCerts calls.
func TestServiceBoundary_DeleteCertificate_NoListCertsCall(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)
	metrics.Enable()

	certPEM, _ := testCertPEM(t)
	err = svc.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "metrics-delete-cert-no-list",
		CertificatePEM: certPEM,
	})
	require.NoError(t, err)

	counting := &countingBackend{Backend: software}
	require.NoError(t, RegisterServiceBackend("software", counting))

	err = svc.DeleteCertificate(context.Background(), "software", "metrics-delete-cert-no-list")
	require.NoError(t, err)

	assert.Equal(t, 0, counting.listCertsCalls)
}

// TestIncrementDecrementKeysAndCertsTotal is the success test for the small
// pkg/xkms wrappers around metrics.Increment/DecrementKeysTotal and
// Increment/DecrementCertsTotal (they have no error path to also test: they
// forward unconditionally to functions that cannot fail).
func TestIncrementDecrementKeysAndCertsTotal(t *testing.T) {
	metrics.Enable()

	beforeKeys := gaugeValue(t, metrics.KeysTotal, "increment-test-backend")
	incrementKeysTotal("increment-test-backend")
	incrementKeysTotal("increment-test-backend")
	assert.Equal(t, beforeKeys+2, gaugeValue(t, metrics.KeysTotal, "increment-test-backend"))
	decrementKeysTotal("increment-test-backend")
	assert.Equal(t, beforeKeys+1, gaugeValue(t, metrics.KeysTotal, "increment-test-backend"))

	beforeCerts := gaugeValue(t, metrics.CertsTotal, "increment-test-backend")
	incrementCertsTotal("increment-test-backend")
	assert.Equal(t, beforeCerts+1, gaugeValue(t, metrics.CertsTotal, "increment-test-backend"))
	decrementCertsTotal("increment-test-backend")
	assert.Equal(t, beforeCerts, gaugeValue(t, metrics.CertsTotal, "increment-test-backend"))
}

// TestErrorTypeLabel_BoundedCardinality asserts errorTypeLabel never returns
// the dynamic, caller-influenced error message -- only the fixed Go type
// name -- so the error_type label stays bounded regardless of what a wrapped
// backend error happens to say.
func TestErrorTypeLabel_BoundedCardinality(t *testing.T) {
	err := &ErrKeyIDParse{Err: ErrInvalidKeyID}
	label := errorTypeLabel(err)

	assert.Equal(t, "*xkms.ErrKeyIDParse", label)
	assert.NotContains(t, label, ErrInvalidKeyID.Error())
}

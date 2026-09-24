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
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/metrics"
)

// caMetricsBackend is the LabelBackend value recorded for Certificate
// Authority operations, which are not addressed by backend name the way key
// and crypto operations are (a deployment has at most one CA provider). It
// keeps the CA subsystem visible on the same operations/duration/errors
// series as every other servicer operation without inventing a per-request
// value that would not exist.
const caMetricsBackend = "ca"

// metricsAllBackends is the LabelBackend value recorded for a list operation
// that spans every registered backend (an empty backend name given to
// ListKeys/ListCertificates), so the series stays distinguishable from a
// listing scoped to one named backend without minting one series per
// backend combination.
const metricsAllBackends = "all"

// recordServiceOp reports a service-boundary operation's outcome through the
// Prometheus API in pkg/metrics: OperationsTotal and OperationDuration
// always, plus ErrorsTotal when err is non-nil.
//
// Callers capture start with time.Now() at entry and invoke this once via a
// deferred closure that reads the function's named error return after the
// body has run, e.g.:
//
//	func (s *XKMSService) Sign(ctx context.Context, req *transport.SignRequest) (resp *transport.SignResponse, err error) {
//		start := time.Now()
//		backendName := s.metricsBackendName(signRequestBackend(req))
//		defer func() { recordServiceOp(metrics.OpSign, backendName, start, err) }()
//		...
//	}
//
// This is the ONE instrumentation point for the XKMSService boundary: every
// transport (REST, gRPC, MCP, QUIC, embedded) drives the same servicer
// methods, so counting here counts each request exactly once regardless of
// which transport carried it.
//
// Labels are operation, backend, and result only -- see errorTypeLabel for
// why the error label is also bounded. Never a key ID, common name, or
// tenant ID: those are unbounded-cardinality values a Prometheus label must
// never carry.
func recordServiceOp(operation, backendName string, start time.Time, err error) {
	duration := time.Since(start).Seconds()
	if err != nil {
		metrics.RecordOperation(operation, backendName, metrics.StatusError, duration)
		metrics.RecordError(operation, backendName, errorTypeLabel(err))
		return
	}
	metrics.RecordOperation(operation, backendName, metrics.StatusSuccess, duration)
}

// errorTypeLabel derives a bounded-cardinality error_type label from err's Go
// type, e.g. "*xkms.ErrBackendLookup". The concrete type set is fixed by this
// package's typed errors (go-xkms never returns an inline fmt.Errorf/errors.New
// from a function body), so the label space is small and never carries a
// caller-supplied value the way err.Error() would (a wrapped backend error
// can quote a key ID or path).
func errorTypeLabel(err error) string {
	return fmt.Sprintf("%T", err)
}

// metricsBackendName resolves the backend label for a service-boundary
// operation: the explicit name when the caller supplied one, otherwise the
// configured default backend -- the same resolution GenerateKey,
// resolveBackend, and resolveBackendWithName apply to the operation itself,
// so the metric is labeled with the backend that actually served the
// request.
func (s *XKMSService) metricsBackendName(explicit string) string {
	if explicit != "" {
		return explicit
	}
	return s.defaultBackendName()
}

// Keys/certs totals: incremented/decremented on the request path
// (below), reconciled to an absolute count on a periodic sweep
// (pkg/server's updateBackendMetrics), never recounted by listing here.
//
// An earlier version of this instrumentation recounted (ListKeys/ListCerts)
// on every create/delete. That turns every key operation into O(n) work in
// the number of keys/certs the backend holds, and for a remote backend
// (awskms, gcpkms, azurekv, vault) adds a remote list call to every request
// -- latency and API-throttling risk neither belongs on the request path.
// Incrementing/decrementing the gauge directly is O(1) and makes no backend
// call; the periodic sweep is the single place that pays for an accurate
// recount, on its own bounded schedule rather than the caller's.

// incrementKeysTotal increments backendName's keys-total gauge. Called after
// a key create/import servicer operation succeeds.
func incrementKeysTotal(backendName string) {
	metrics.IncrementKeysTotal(backendName)
}

// decrementKeysTotal decrements backendName's keys-total gauge. Called after
// a key delete servicer operation succeeds.
func decrementKeysTotal(backendName string) {
	metrics.DecrementKeysTotal(backendName)
}

// incrementCertsTotal increments backendName's certs-total gauge. Called
// after a certificate save servicer operation succeeds. Deliberately NOT
// called from SaveCertificateChain: a chain is stored under a distinct key
// (CertChainPath) that storage.ListCerts explicitly excludes from the count
// this gauge tracks (see storage/namespace.go's ListCerts), so saving a
// chain does not change it.
func incrementCertsTotal(backendName string) {
	metrics.IncrementCertsTotal(backendName)
}

// decrementCertsTotal decrements backendName's certs-total gauge. Called
// after a certificate delete servicer operation succeeds.
func decrementCertsTotal(backendName string) {
	metrics.DecrementCertsTotal(backendName)
}

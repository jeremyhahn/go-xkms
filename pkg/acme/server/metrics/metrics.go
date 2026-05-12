// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

var (
	// Registry is the Prometheus registry for all ACME metrics
	Registry = prometheus.NewRegistry()

	// Counter metrics
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Name:      "requests_total",
			Help:      "Total number of ACME requests by endpoint and status",
		},
		[]string{"endpoint", "status"},
	)

	certificatesIssuedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "acme",
			Name:      "certificates_issued_total",
			Help:      "Total number of certificates issued",
		},
	)

	certificatesRevokedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "acme",
			Name:      "certificates_revoked_total",
			Help:      "Total number of certificates revoked",
		},
	)

	challengesCompletedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Name:      "challenges_completed_total",
			Help:      "Total number of challenges completed by type and status",
		},
		[]string{"type", "status"},
	)

	errorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Name:      "errors_total",
			Help:      "Total number of errors by type",
		},
		[]string{"type"},
	)

	// Gauge metrics
	activeOrders = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Name:      "active_orders",
			Help:      "Number of currently active orders",
		},
	)

	pendingChallenges = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Name:      "pending_challenges",
			Help:      "Number of pending challenges",
		},
	)

	certificatesExpiringSoon = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Name:      "certificates_expiring_soon",
			Help:      "Number of certificates expiring in the next 30 days",
		},
	)

	// Histogram metrics
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "acme",
			Name:      "request_duration_seconds",
			Help:      "ACME request latency in seconds by endpoint",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)

	certificateIssuanceDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "acme",
			Name:      "certificate_issuance_duration_seconds",
			Help:      "Time to issue certificates in seconds",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120},
		},
	)

	once sync.Once
)

// Init initializes the metrics registry and registers all ACME metrics.
// This function is safe to call multiple times - it will only execute once.
func Init() {
	once.Do(func() {
		// Register counter metrics
		Registry.MustRegister(requestsTotal)
		Registry.MustRegister(certificatesIssuedTotal)
		Registry.MustRegister(certificatesRevokedTotal)
		Registry.MustRegister(challengesCompletedTotal)
		Registry.MustRegister(errorsTotal)

		// Register gauge metrics
		Registry.MustRegister(activeOrders)
		Registry.MustRegister(pendingChallenges)
		Registry.MustRegister(certificatesExpiringSoon)

		// Register histogram metrics
		Registry.MustRegister(requestDuration)
		Registry.MustRegister(certificateIssuanceDuration)

		// Register Go runtime metrics
		Registry.MustRegister(collectors.NewGoCollector())
		Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	})
}

// RecordRequest increments the request counter for a given endpoint and status.
func RecordRequest(endpoint, status string) {
	requestsTotal.WithLabelValues(endpoint, status).Inc()
}

// RecordCertificateIssued increments the certificate issuance counter.
func RecordCertificateIssued() {
	certificatesIssuedTotal.Inc()
}

// RecordCertificateRevoked increments the certificate revocation counter.
func RecordCertificateRevoked() {
	certificatesRevokedTotal.Inc()
}

// RecordChallengeCompleted increments the challenge completion counter.
func RecordChallengeCompleted(challengeType, status string) {
	challengesCompletedTotal.WithLabelValues(challengeType, status).Inc()
}

// RecordError increments the error counter for a given error type.
func RecordError(errorType string) {
	errorsTotal.WithLabelValues(errorType).Inc()
}

// SetActiveOrders sets the current number of active orders.
func SetActiveOrders(count float64) {
	activeOrders.Set(count)
}

// IncActiveOrders increments the active orders counter.
func IncActiveOrders() {
	activeOrders.Inc()
}

// DecActiveOrders decrements the active orders counter.
func DecActiveOrders() {
	activeOrders.Dec()
}

// SetPendingChallenges sets the current number of pending challenges.
func SetPendingChallenges(count float64) {
	pendingChallenges.Set(count)
}

// IncPendingChallenges increments the pending challenges counter.
func IncPendingChallenges() {
	pendingChallenges.Inc()
}

// DecPendingChallenges decrements the pending challenges counter.
func DecPendingChallenges() {
	pendingChallenges.Dec()
}

// SetCertificatesExpiringSoon sets the number of certificates expiring soon.
func SetCertificatesExpiringSoon(count float64) {
	certificatesExpiringSoon.Set(count)
}

// ObserveRequestDuration records the duration of a request in seconds.
func ObserveRequestDuration(endpoint string, duration float64) {
	requestDuration.WithLabelValues(endpoint).Observe(duration)
}

// ObserveCertificateIssuanceDuration records the time to issue a certificate.
func ObserveCertificateIssuanceDuration(duration float64) {
	certificateIssuanceDuration.Observe(duration)
}

// GetRequestsTotal returns the requests counter for testing.
func GetRequestsTotal() *prometheus.CounterVec {
	return requestsTotal
}

// GetCertificatesIssuedTotal returns the certificates issued counter for testing.
func GetCertificatesIssuedTotal() prometheus.Counter {
	return certificatesIssuedTotal
}

// GetCertificatesRevokedTotal returns the certificates revoked counter for testing.
func GetCertificatesRevokedTotal() prometheus.Counter {
	return certificatesRevokedTotal
}

// GetChallengesCompletedTotal returns the challenges completed counter for testing.
func GetChallengesCompletedTotal() *prometheus.CounterVec {
	return challengesCompletedTotal
}

// GetErrorsTotal returns the errors counter for testing.
func GetErrorsTotal() *prometheus.CounterVec {
	return errorsTotal
}

// GetActiveOrders returns the active orders gauge for testing.
func GetActiveOrders() prometheus.Gauge {
	return activeOrders
}

// GetPendingChallenges returns the pending challenges gauge for testing.
func GetPendingChallenges() prometheus.Gauge {
	return pendingChallenges
}

// GetCertificatesExpiringSoon returns the certificates expiring soon gauge for testing.
func GetCertificatesExpiringSoon() prometheus.Gauge {
	return certificatesExpiringSoon
}

// GetRequestDuration returns the request duration histogram for testing.
func GetRequestDuration() *prometheus.HistogramVec {
	return requestDuration
}

// GetCertificateIssuanceDuration returns the certificate issuance duration histogram for testing.
func GetCertificateIssuanceDuration() prometheus.Histogram {
	return certificateIssuanceDuration
}

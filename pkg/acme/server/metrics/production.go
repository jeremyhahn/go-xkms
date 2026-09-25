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

// Package metrics provides production-grade Prometheus metrics for the ACME
// server. This file contains tenant-aware metrics plus the circuit breaker,
// cache and graceful-degradation instrumentation used by
// pkg/acme/server/circuitbreaker and pkg/acme/server/degradation.
package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	productionOnce sync.Once

	// Tenant-aware certificate metrics
	certificatesIssuedByTenant = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "tenant",
			Name:      "certificates_issued_total",
			Help:      "Total number of certificates issued per tenant",
		},
		[]string{"tenant_id"},
	)

	certificatesRevokedByTenant = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "tenant",
			Name:      "certificates_revoked_total",
			Help:      "Total number of certificates revoked per tenant",
		},
		[]string{"tenant_id"},
	)

	// Tenant-aware challenge metrics
	challengesByTenant = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "tenant",
			Name:      "challenges_total",
			Help:      "Total number of challenges per tenant by type and status",
		},
		[]string{"tenant_id", "type", "status"},
	)

	// Tenant-aware account metrics
	activeAccountsByTenant = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Subsystem: "tenant",
			Name:      "active_accounts",
			Help:      "Number of active accounts per tenant",
		},
		[]string{"tenant_id"},
	)

	activeOrdersByTenant = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Subsystem: "tenant",
			Name:      "active_orders",
			Help:      "Number of active orders per tenant",
		},
		[]string{"tenant_id"},
	)

	// Circuit breaker metrics
	circuitBreakerState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Subsystem: "circuit_breaker",
			Name:      "state",
			Help:      "Circuit breaker state (0=closed, 1=half-open, 2=open)",
		},
		[]string{"name"},
	)

	circuitBreakerFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "circuit_breaker",
			Name:      "failures_total",
			Help:      "Total number of failures tracked by circuit breaker",
		},
		[]string{"name"},
	)

	circuitBreakerSuccesses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "circuit_breaker",
			Name:      "successes_total",
			Help:      "Total number of successes tracked by circuit breaker",
		},
		[]string{"name"},
	)

	circuitBreakerTrips = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "circuit_breaker",
			Name:      "trips_total",
			Help:      "Total number of times circuit breaker has tripped open",
		},
		[]string{"name"},
	)

	// Cache metrics for graceful degradation
	cacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "cache",
			Name:      "hits_total",
			Help:      "Total number of cache hits",
		},
		[]string{"cache_name"},
	)

	cacheMisses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "cache",
			Name:      "misses_total",
			Help:      "Total number of cache misses",
		},
		[]string{"cache_name"},
	)

	cacheSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Subsystem: "cache",
			Name:      "size",
			Help:      "Current cache size in entries",
		},
		[]string{"cache_name"},
	)

	degradationActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Name:      "degradation_active",
			Help:      "Whether graceful degradation is active (1=degraded, 0=normal)",
		},
	)
)

// InitProduction initializes production metrics and registers them with the registry.
// This function is safe to call multiple times - it will only execute once.
func InitProduction() {
	productionOnce.Do(func() {
		// Tenant-aware metrics
		Registry.MustRegister(certificatesIssuedByTenant)
		Registry.MustRegister(certificatesRevokedByTenant)
		Registry.MustRegister(challengesByTenant)
		Registry.MustRegister(activeAccountsByTenant)
		Registry.MustRegister(activeOrdersByTenant)

		// Circuit breaker metrics
		Registry.MustRegister(circuitBreakerState)
		Registry.MustRegister(circuitBreakerFailures)
		Registry.MustRegister(circuitBreakerSuccesses)
		Registry.MustRegister(circuitBreakerTrips)

		// Cache metrics
		Registry.MustRegister(cacheHits)
		Registry.MustRegister(cacheMisses)
		Registry.MustRegister(cacheSize)

		// Health indicators
		Registry.MustRegister(degradationActive)
	})
}

// Tenant-aware metric recording functions

// RecordTenantCertificateIssued records a certificate issuance for a specific tenant.
func RecordTenantCertificateIssued(tenantID string) {
	certificatesIssuedByTenant.WithLabelValues(tenantID).Inc()
}

// RecordTenantCertificateRevoked records a certificate revocation for a specific tenant.
func RecordTenantCertificateRevoked(tenantID string) {
	certificatesRevokedByTenant.WithLabelValues(tenantID).Inc()
}

// RecordTenantChallenge records a challenge event for a specific tenant.
func RecordTenantChallenge(tenantID, challengeType, status string) {
	challengesByTenant.WithLabelValues(tenantID, challengeType, status).Inc()
}

// IncTenantActiveAccounts increments the active account count for a tenant.
func IncTenantActiveAccounts(tenantID string) {
	activeAccountsByTenant.WithLabelValues(tenantID).Inc()
}

// DecTenantActiveAccounts decrements the active account count for a tenant.
func DecTenantActiveAccounts(tenantID string) {
	activeAccountsByTenant.WithLabelValues(tenantID).Dec()
}

// IncTenantActiveOrders increments the active order count for a tenant.
func IncTenantActiveOrders(tenantID string) {
	activeOrdersByTenant.WithLabelValues(tenantID).Inc()
}

// DecTenantActiveOrders decrements the active order count for a tenant.
func DecTenantActiveOrders(tenantID string) {
	activeOrdersByTenant.WithLabelValues(tenantID).Dec()
}

// Circuit breaker metric recording functions

// CircuitBreakerState represents the state of a circuit breaker.
type CircuitBreakerState int

const (
	// CircuitBreakerClosed indicates the circuit is closed (normal operation).
	CircuitBreakerClosed CircuitBreakerState = iota
	// CircuitBreakerHalfOpen indicates the circuit is testing if the service recovered.
	CircuitBreakerHalfOpen
	// CircuitBreakerOpen indicates the circuit is open (failing fast).
	CircuitBreakerOpen
)

// SetCircuitBreakerState sets the circuit breaker state for a named breaker.
func SetCircuitBreakerState(name string, state CircuitBreakerState) {
	circuitBreakerState.WithLabelValues(name).Set(float64(state))
}

// RecordCircuitBreakerFailure records a failure for a circuit breaker.
func RecordCircuitBreakerFailure(name string) {
	circuitBreakerFailures.WithLabelValues(name).Inc()
}

// RecordCircuitBreakerSuccess records a success for a circuit breaker.
func RecordCircuitBreakerSuccess(name string) {
	circuitBreakerSuccesses.WithLabelValues(name).Inc()
}

// RecordCircuitBreakerTrip records a circuit breaker trip event.
func RecordCircuitBreakerTrip(name string) {
	circuitBreakerTrips.WithLabelValues(name).Inc()
}

// Cache metric recording functions

// RecordCacheHit records a cache hit.
func RecordCacheHit(cacheName string) {
	cacheHits.WithLabelValues(cacheName).Inc()
}

// RecordCacheMiss records a cache miss.
func RecordCacheMiss(cacheName string) {
	cacheMisses.WithLabelValues(cacheName).Inc()
}

// SetCacheSize sets the current cache size.
func SetCacheSize(cacheName string, size float64) {
	cacheSize.WithLabelValues(cacheName).Set(size)
}

// Health indicator functions

// SetDegradationActive sets whether graceful degradation is active.
func SetDegradationActive(active bool) {
	if active {
		degradationActive.Set(1)
	} else {
		degradationActive.Set(0)
	}
}

// Getter functions for testing

// GetCertificatesIssuedByTenant returns the tenant certificates issued counter.
func GetCertificatesIssuedByTenant() *prometheus.CounterVec {
	return certificatesIssuedByTenant
}

// GetCertificatesRevokedByTenant returns the tenant certificates revoked counter.
func GetCertificatesRevokedByTenant() *prometheus.CounterVec {
	return certificatesRevokedByTenant
}

// GetChallengesByTenant returns the tenant challenges counter.
func GetChallengesByTenant() *prometheus.CounterVec {
	return challengesByTenant
}

// GetActiveAccountsByTenant returns the tenant active accounts gauge.
func GetActiveAccountsByTenant() *prometheus.GaugeVec {
	return activeAccountsByTenant
}

// GetActiveOrdersByTenant returns the tenant active orders gauge.
func GetActiveOrdersByTenant() *prometheus.GaugeVec {
	return activeOrdersByTenant
}

// GetCircuitBreakerState returns the circuit breaker state gauge.
func GetCircuitBreakerState() *prometheus.GaugeVec {
	return circuitBreakerState
}

// GetCircuitBreakerFailures returns the circuit breaker failures counter.
func GetCircuitBreakerFailures() *prometheus.CounterVec {
	return circuitBreakerFailures
}

// GetCircuitBreakerSuccesses returns the circuit breaker successes counter.
func GetCircuitBreakerSuccesses() *prometheus.CounterVec {
	return circuitBreakerSuccesses
}

// GetCircuitBreakerTrips returns the circuit breaker trips counter.
func GetCircuitBreakerTrips() *prometheus.CounterVec {
	return circuitBreakerTrips
}

// GetCacheHits returns the cache hits counter.
func GetCacheHits() *prometheus.CounterVec {
	return cacheHits
}

// GetCacheMisses returns the cache misses counter.
func GetCacheMisses() *prometheus.CounterVec {
	return cacheMisses
}

// GetCacheSize returns the cache size gauge.
func GetCacheSize() *prometheus.GaugeVec {
	return cacheSize
}

// GetDegradationActive returns the degradation active gauge.
func GetDegradationActive() prometheus.Gauge {
	return degradationActive
}

// MetricsCollector records both the global ACME metric and its per-tenant
// counterpart for a single account's certificate, revocation and challenge
// events, so a handler acting on a tenant-bound account does not need to
// duplicate the "record global, then record tenant if bound" branch at every
// call site. tenantID is the empty string for a non-tenant-bound account, in
// which case only the global metric is recorded.
type MetricsCollector struct {
	tenantID string
}

// NewMetricsCollector creates a metrics collector scoped to tenantID (the
// empty string for a non-tenant-bound account).
func NewMetricsCollector(tenantID string) *MetricsCollector {
	return &MetricsCollector{tenantID: tenantID}
}

// RecordCertificateIssued records a certificate issuance.
func (mc *MetricsCollector) RecordCertificateIssued() {
	RecordCertificateIssued()
	if mc.tenantID != "" {
		RecordTenantCertificateIssued(mc.tenantID)
	}
}

// RecordCertificateRevoked records a certificate revocation.
func (mc *MetricsCollector) RecordCertificateRevoked() {
	RecordCertificateRevoked()
	if mc.tenantID != "" {
		RecordTenantCertificateRevoked(mc.tenantID)
	}
}

// RecordChallenge records a challenge event.
func (mc *MetricsCollector) RecordChallenge(challengeType, status string) {
	RecordChallengeCompleted(challengeType, status)
	if mc.tenantID != "" {
		RecordTenantChallenge(mc.tenantID, challengeType, status)
	}
}

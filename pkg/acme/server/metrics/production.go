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

// Package metrics provides production-grade Prometheus metrics for the ACME server.
// This file contains tenant-aware metrics, cluster metrics, and SLI/SLO
// focused observability instrumentation.
package metrics

import (
	"sync"
	"sync/atomic"

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

	// Tenant-aware request metrics
	requestsByTenant = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "tenant",
			Name:      "requests_total",
			Help:      "Total number of ACME requests per tenant by endpoint and status",
		},
		[]string{"tenant_id", "endpoint", "status"},
	)

	requestDurationByTenant = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "acme",
			Subsystem: "tenant",
			Name:      "request_duration_seconds",
			Help:      "ACME request latency per tenant in seconds by endpoint",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"tenant_id", "endpoint"},
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

	// Cluster metrics
	clusterHealthy = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "trustedca",
			Name:      "healthy",
			Help:      "Cluster health status (1=healthy, 0=unhealthy)",
		},
	)

	clusterLeader = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "trustedca",
			Subsystem: "raft",
			Name:      "is_leader",
			Help:      "Whether this node is the Raft leader (1=leader, 0=follower)",
		},
	)

	clusterFollowers = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "trustedca",
			Subsystem: "raft",
			Name:      "followers",
			Help:      "Number of Raft followers in the cluster",
		},
	)

	clusterElectionCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: "trustedca",
			Subsystem: "raft",
			Name:      "elections_total",
			Help:      "Total number of Raft leader elections",
		},
	)

	clusterKVOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "trustedca",
			Subsystem: "kv",
			Name:      "operations_total",
			Help:      "Total number of KV operations by type and status",
		},
		[]string{"operation", "status"},
	)

	clusterKVLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "trustedca",
			Subsystem: "kv",
			Name:      "operation_duration_seconds",
			Help:      "Cluster KV operation latency in seconds",
			Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
		},
		[]string{"operation"},
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

	// Rate limiting metrics
	rateLimitHitsByTenant = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "rate_limit",
			Name:      "hits_total",
			Help:      "Total number of rate limit hits per tenant",
		},
		[]string{"tenant_id", "endpoint"},
	)

	rateLimitTokensByTenant = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Subsystem: "rate_limit",
			Name:      "tokens_remaining",
			Help:      "Remaining rate limit tokens per tenant",
		},
		[]string{"tenant_id"},
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

	// SLI/SLO metrics
	sloLatencyBudget = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "acme",
			Subsystem: "slo",
			Name:      "request_latency_seconds",
			Help:      "Request latency for SLO tracking with p50, p95, p99 buckets",
			Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"endpoint", "tenant_id"},
	)

	sloAvailability = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "acme",
			Subsystem: "slo",
			Name:      "requests_total",
			Help:      "Total requests for SLO availability tracking",
		},
		[]string{"result"}, // "success" or "error"
	)

	// Health indicators
	serviceHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "acme",
			Name:      "service_health",
			Help:      "Service component health status (1=healthy, 0=unhealthy)",
		},
		[]string{"component"},
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
		Registry.MustRegister(requestsByTenant)
		Registry.MustRegister(requestDurationByTenant)
		Registry.MustRegister(challengesByTenant)
		Registry.MustRegister(activeAccountsByTenant)
		Registry.MustRegister(activeOrdersByTenant)

		// Cluster metrics
		Registry.MustRegister(clusterHealthy)
		Registry.MustRegister(clusterLeader)
		Registry.MustRegister(clusterFollowers)
		Registry.MustRegister(clusterElectionCount)
		Registry.MustRegister(clusterKVOperations)
		Registry.MustRegister(clusterKVLatency)

		// Circuit breaker metrics
		Registry.MustRegister(circuitBreakerState)
		Registry.MustRegister(circuitBreakerFailures)
		Registry.MustRegister(circuitBreakerSuccesses)
		Registry.MustRegister(circuitBreakerTrips)

		// Rate limiting metrics
		Registry.MustRegister(rateLimitHitsByTenant)
		Registry.MustRegister(rateLimitTokensByTenant)

		// Cache metrics
		Registry.MustRegister(cacheHits)
		Registry.MustRegister(cacheMisses)
		Registry.MustRegister(cacheSize)

		// SLO metrics
		Registry.MustRegister(sloLatencyBudget)
		Registry.MustRegister(sloAvailability)

		// Health indicators
		Registry.MustRegister(serviceHealth)
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

// RecordTenantRequest records a request for a specific tenant.
func RecordTenantRequest(tenantID, endpoint, status string) {
	requestsByTenant.WithLabelValues(tenantID, endpoint, status).Inc()
}

// RecordTenantRequestDuration records request duration for a specific tenant.
func RecordTenantRequestDuration(tenantID, endpoint string, duration float64) {
	requestDurationByTenant.WithLabelValues(tenantID, endpoint).Observe(duration)
}

// RecordTenantChallenge records a challenge event for a specific tenant.
func RecordTenantChallenge(tenantID, challengeType, status string) {
	challengesByTenant.WithLabelValues(tenantID, challengeType, status).Inc()
}

// SetTenantActiveAccounts sets the active account count for a tenant.
func SetTenantActiveAccounts(tenantID string, count float64) {
	activeAccountsByTenant.WithLabelValues(tenantID).Set(count)
}

// SetTenantActiveOrders sets the active order count for a tenant.
func SetTenantActiveOrders(tenantID string, count float64) {
	activeOrdersByTenant.WithLabelValues(tenantID).Set(count)
}

// Cluster metric recording functions

// SetClusterHealthy sets the cluster health status.
func SetClusterHealthy(healthy bool) {
	if healthy {
		clusterHealthy.Set(1)
	} else {
		clusterHealthy.Set(0)
	}
}

// SetClusterLeader sets whether this node is the Raft leader.
func SetClusterLeader(isLeader bool) {
	if isLeader {
		clusterLeader.Set(1)
	} else {
		clusterLeader.Set(0)
	}
}

// SetClusterFollowers sets the number of Raft followers.
func SetClusterFollowers(count int) {
	clusterFollowers.Set(float64(count))
}

// RecordClusterElection records a Raft leader election event.
func RecordClusterElection() {
	clusterElectionCount.Inc()
}

// RecordClusterKVOperation records a KV operation.
func RecordClusterKVOperation(operation, status string) {
	clusterKVOperations.WithLabelValues(operation, status).Inc()
}

// RecordClusterKVLatency records KV operation latency.
func RecordClusterKVLatency(operation string, duration float64) {
	clusterKVLatency.WithLabelValues(operation).Observe(duration)
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

// Rate limiting metric recording functions

// RecordTenantRateLimitHit records a rate limit hit for a tenant.
func RecordTenantRateLimitHit(tenantID, endpoint string) {
	rateLimitHitsByTenant.WithLabelValues(tenantID, endpoint).Inc()
}

// SetTenantRateLimitTokens sets the remaining rate limit tokens for a tenant.
func SetTenantRateLimitTokens(tenantID string, tokens float64) {
	rateLimitTokensByTenant.WithLabelValues(tenantID).Set(tokens)
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

// SLO metric recording functions

// RecordSLOLatency records request latency for SLO tracking.
func RecordSLOLatency(endpoint, tenantID string, duration float64) {
	sloLatencyBudget.WithLabelValues(endpoint, tenantID).Observe(duration)
}

// RecordSLOSuccess records a successful request for availability SLO.
func RecordSLOSuccess() {
	sloAvailability.WithLabelValues("success").Inc()
}

// RecordSLOError records a failed request for availability SLO.
func RecordSLOError() {
	sloAvailability.WithLabelValues("error").Inc()
}

// Health indicator functions

// SetServiceHealth sets the health status of a service component.
func SetServiceHealth(component string, healthy bool) {
	if healthy {
		serviceHealth.WithLabelValues(component).Set(1)
	} else {
		serviceHealth.WithLabelValues(component).Set(0)
	}
}

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

// GetRequestsByTenant returns the tenant requests counter.
func GetRequestsByTenant() *prometheus.CounterVec {
	return requestsByTenant
}

// GetRequestDurationByTenant returns the tenant request duration histogram.
func GetRequestDurationByTenant() *prometheus.HistogramVec {
	return requestDurationByTenant
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

// GetClusterHealthy returns the cluster healthy gauge.
func GetClusterHealthy() prometheus.Gauge {
	return clusterHealthy
}

// GetClusterLeader returns the cluster leader gauge.
func GetClusterLeader() prometheus.Gauge {
	return clusterLeader
}

// GetClusterFollowers returns the cluster followers gauge.
func GetClusterFollowers() prometheus.Gauge {
	return clusterFollowers
}

// GetClusterElectionCount returns the cluster election counter.
func GetClusterElectionCount() prometheus.Counter {
	return clusterElectionCount
}

// GetClusterKVOperations returns the cluster KV operations counter.
func GetClusterKVOperations() *prometheus.CounterVec {
	return clusterKVOperations
}

// GetClusterKVLatency returns the cluster KV latency histogram.
func GetClusterKVLatency() *prometheus.HistogramVec {
	return clusterKVLatency
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

// GetRateLimitHitsByTenant returns the tenant rate limit hits counter.
func GetRateLimitHitsByTenant() *prometheus.CounterVec {
	return rateLimitHitsByTenant
}

// GetRateLimitTokensByTenant returns the tenant rate limit tokens gauge.
func GetRateLimitTokensByTenant() *prometheus.GaugeVec {
	return rateLimitTokensByTenant
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

// GetSLOLatencyBudget returns the SLO latency histogram.
func GetSLOLatencyBudget() *prometheus.HistogramVec {
	return sloLatencyBudget
}

// GetSLOAvailability returns the SLO availability counter.
func GetSLOAvailability() *prometheus.CounterVec {
	return sloAvailability
}

// GetServiceHealth returns the service health gauge.
func GetServiceHealth() *prometheus.GaugeVec {
	return serviceHealth
}

// GetDegradationActive returns the degradation active gauge.
func GetDegradationActive() prometheus.Gauge {
	return degradationActive
}

// MetricsCollector provides a centralized way to update metrics during request handling.
// It is designed to be embedded in request context for easy access.
type MetricsCollector struct {
	tenantID string
	endpoint string
}

// NewMetricsCollector creates a new metrics collector for a request.
func NewMetricsCollector(tenantID, endpoint string) *MetricsCollector {
	return &MetricsCollector{
		tenantID: tenantID,
		endpoint: endpoint,
	}
}

// RecordRequest records a request with the configured tenant and endpoint.
func (mc *MetricsCollector) RecordRequest(status string, duration float64) {
	// Global metrics
	RecordRequest(mc.endpoint, status)
	ObserveRequestDuration(mc.endpoint, duration)

	// Tenant-aware metrics
	if mc.tenantID != "" {
		RecordTenantRequest(mc.tenantID, mc.endpoint, status)
		RecordTenantRequestDuration(mc.tenantID, mc.endpoint, duration)
	}

	// SLO metrics
	RecordSLOLatency(mc.endpoint, mc.tenantID, duration)
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

// ClusterMetricsCollector collects and exports cluster metrics.
type ClusterMetricsCollector struct {
	electionCount atomic.Uint64
}

// NewClusterMetricsCollector creates a new cluster metrics collector.
func NewClusterMetricsCollector() *ClusterMetricsCollector {
	return &ClusterMetricsCollector{}
}

// UpdateClusterStatus updates the cluster metrics.
func (dmc *ClusterMetricsCollector) UpdateClusterStatus(healthy, isLeader bool, followerCount int) {
	SetClusterHealthy(healthy)
	SetClusterLeader(isLeader)
	SetClusterFollowers(followerCount)
}

// RecordElection records a leader election event.
func (dmc *ClusterMetricsCollector) RecordElection() {
	dmc.electionCount.Add(1)
	RecordClusterElection()
}

// RecordKVOperation records a KV operation with timing.
func (dmc *ClusterMetricsCollector) RecordKVOperation(operation, status string, duration float64) {
	RecordClusterKVOperation(operation, status)
	RecordClusterKVLatency(operation, duration)
}

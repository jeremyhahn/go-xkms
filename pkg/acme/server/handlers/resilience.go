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

package handlers

import (
	"net/http"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/degradation"
)

// serveOrDegrade runs compute through cb -- so a live failure both surfaces
// to the caller and counts toward cb's own failure threshold -- and falls
// back to cache's last known-good entry for key when cb rejects the call (it
// is open, or too many requests are already in flight while half-open) or
// compute itself fails. This is what lets CABundleHandler keep answering
// RFC 8555 clients that poll it constantly even while CA-bundle storage
// access is unavailable.
//
// degraded is true only when the response served came from cache instead of
// a fresh compute; a fresh compute or a still-fresh cache hit reported by a
// failed compute are not degraded.
func (s *RestService) serveOrDegrade(
	cb *circuitbreaker.CircuitBreaker,
	cache *degradation.Cache,
	key string,
	compute func() ([]byte, error),
) (value []byte, degraded bool, err error) {
	if cb == nil {
		value, err = compute()
		return value, false, err
	}

	var out []byte
	execErr := cb.Execute(func() error {
		v, computeErr := compute()
		if computeErr != nil {
			return computeErr
		}
		out = v
		return nil
	})
	if execErr == nil {
		cache.Set(key, out, s.degradationCacheTTL)
		return out, false, nil
	}

	entry, cacheErr := cache.Get(key)
	if cacheErr != nil {
		return nil, false, execErr
	}
	if !entry.IsExpired() {
		return entry.Value, false, nil
	}
	if entry.IsStale(s.degradationStaleTTL) {
		return entry.Value, true, nil
	}
	return nil, false, execErr
}

// serveCachedWhenOpen returns cache's last entry for key, marked degraded,
// when cb is open and a usable entry exists; otherwise it runs compute,
// caches the result, and returns it fresh. Unlike serveOrDegrade it never
// calls cb.Execute: it exists for an endpoint with no fallible call of its
// own (DirectoryHandler builds its response entirely from server
// configuration), so it only peeks at cb's state and never contends with a
// real dependency's admission control or half-open probe budget.
func (s *RestService) serveCachedWhenOpen(
	cb *circuitbreaker.CircuitBreaker,
	cache *degradation.Cache,
	key string,
	compute func() []byte,
) (value []byte, degraded bool) {
	if cb != nil && cb.State() == circuitbreaker.StateOpen {
		if entry, err := cache.Get(key); err == nil {
			return entry.Value, true
		}
	}

	value = compute()
	if cache != nil {
		cache.Set(key, value, s.degradationCacheTTL)
	}
	return value, false
}

// HealthStatus reports the ACME server's resilience posture: every named
// circuit breaker registered on the shared Manager (Params.Breakers), which
// includes breakers this RestService created for its own storage access as
// well as any a caller registered for the CT submitter or KMS signer; a
// bounded summary of the per-target breaker groups (http-01/dns-01
// validation targets, see TargetGroups); and whether the directory and
// CA-bundle endpoints are currently degraded.
type HealthStatus struct {
	// Healthy is false when any named breaker (Breakers) is open. A
	// per-target breaker group's Open count does NOT affect Healthy: one
	// account's failing validation target is expected, isolated behavior
	// (that isolation is the point of TargetGroups -- see
	// circuitbreaker.WrapChallengeVerifierPerTarget), not evidence that the
	// server itself is unhealthy the way an open "storage" or "kms" breaker
	// is.
	Healthy bool `json:"healthy"`

	// Breakers reports every named breaker on the shared Manager (a small,
	// fixed set of operator-configured dependencies: "storage", "kms",
	// "ct_submitter" when wired), keyed by name. Empty when Params.Breakers
	// was nil. This does NOT include per-target breakers -- see TargetGroups.
	Breakers map[string]CircuitBreakerStatus `json:"breakers,omitempty"`

	// TargetGroups reports a bounded summary of every per-target breaker
	// group on the shared Manager, keyed by group name ("http01", "dns01").
	// Unlike Breakers this never grows with the number of distinct
	// validation targets seen: see circuitbreaker.TargetGroupStatus. Empty
	// when Params.Breakers was nil.
	TargetGroups map[string]circuitbreaker.TargetGroupStatus `json:"target_groups,omitempty"`

	// Degradation reports whether the directory and CA-bundle endpoints are
	// currently serving cached content because CA-bundle storage access
	// (the "storage" breaker) is open.
	Degradation DegradationStatus `json:"degradation"`
}

// CircuitBreakerStatus reports one breaker's state and counters.
type CircuitBreakerStatus struct {
	State        string `json:"state"`
	FailureCount uint32 `json:"failure_count"`
	SuccessCount uint32 `json:"success_count"`
}

// DegradationStatus reports whether the storage breaker is open, and
// therefore whether the directory and CA-bundle endpoints are currently
// eligible to serve cached content instead of computing fresh.
type DegradationStatus struct {
	// Active is true when the storage breaker is open.
	Active bool `json:"active"`
}

// HealthHandler implements RestServicer. It reports circuit breaker state
// for every breaker on Params.Breakers and whether the directory/CA-bundle
// endpoints are currently degraded. Non-RFC 8555; no authentication, no
// dependency calls -- this reads breaker state only.
//
// GET /acme/health
func (s *RestService) HealthHandler(w http.ResponseWriter, r *http.Request) {
	status := HealthStatus{Healthy: true}

	if s.breakers != nil {
		status.Breakers = make(map[string]CircuitBreakerStatus)
		for _, cb := range s.breakers.List() {
			failures, successes := cb.Counts()
			status.Breakers[cb.Name()] = CircuitBreakerStatus{
				State:        cb.State().String(),
				FailureCount: failures,
				SuccessCount: successes,
			}
			if cb.State() != circuitbreaker.StateClosed {
				status.Healthy = false
			}
		}
		status.TargetGroups = s.breakers.TargetGroupStatuses()
	}

	status.Degradation = DegradationStatus{
		Active: s.storageBreaker != nil && s.storageBreaker.State() == circuitbreaker.StateOpen,
	}

	w.Header().Set("Content-Type", "application/json")
	if status.Healthy {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	s.encodeJSON(w, status)
}

// degradationHeader marks a response as served from the degradation cache.
// Modeled on RFC 7234 Section 5.5's Warning header (110 = "Response is
// Stale"); it is informational only and not consulted by any client this
// server issues to.
const degradationHeader = "Warning"

// degradationHeaderValue is the value degradationHeader carries on a
// degraded response.
const degradationHeaderValue = `110 - "Response is stale"`

// setDegradedHeader marks w's response as degraded when degraded is true.
// Must be called before WriteHeader.
func setDegradedHeader(w http.ResponseWriter, degraded bool) {
	if degraded {
		w.Header().Set(degradationHeader, degradationHeaderValue)
	}
}
